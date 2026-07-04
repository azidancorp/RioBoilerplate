"""Tests for sudo mode (step-up re-auth) gating of sensitive admin actions.

Covers the persistence-layer elevation primitives, the ``perform_step_up`` /
``require_elevated_session`` helpers, the admin role-change gate + dialog flow,
the schema migration that adds ``elevated_until`` to upgraded databases, and the
joined-SELECT integrity that keeps the user object parsing correctly after the
new session column was inserted ahead of the user columns.
"""

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

from app.config import config
from app.pages.app_page.admin import AdminPage
from app.persistence import Persistence
from app.session_validation import (
    perform_step_up,
    require_elevated_session,
    verify_step_up_credentials,
)

# Reuse the fake-session / mounting helpers (kept in sync with AdminPage state).
from tests.test_admin_user_lifecycle import (
    PASSWORD,
    _FakeSession,
    _create_root_session,
    _create_user,
    _mount_admin,
)


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "sudo-mode.db")
    try:
        yield persistence
    finally:
        persistence.close()


def _totp_now(secret: str) -> str:
    return pyotp.TOTP(secret).now()


# ---------------------------------------------------------------------------
# Persistence primitives
# ---------------------------------------------------------------------------


def test_elevate_and_clear_session_elevation(temp_db: Persistence):
    async def scenario():
        _, root_session = await _create_root_session(temp_db)

        # Freshly created sessions start un-elevated.
        reloaded, _ = temp_db.get_valid_session_by_auth_token(root_session.id)
        assert reloaded.elevated_until is None
        assert temp_db.session_is_elevated(reloaded) is False

        deadline = await temp_db.elevate_session(
            root_session.id, config.SUDO_MODE_TTL_SECONDS
        )
        expected = datetime.now(tz=timezone.utc) + timedelta(
            seconds=config.SUDO_MODE_TTL_SECONDS
        )
        assert abs((deadline - expected).total_seconds()) < 5

        reloaded, _ = temp_db.get_valid_session_by_auth_token(root_session.id)
        assert reloaded.elevated_until is not None
        assert temp_db.session_is_elevated(reloaded) is True

        await temp_db.clear_session_elevation(root_session.id)
        reloaded, _ = temp_db.get_valid_session_by_auth_token(root_session.id)
        assert reloaded.elevated_until is None
        assert temp_db.session_is_elevated(reloaded) is False

    asyncio.run(scenario())


def test_session_is_elevated_expires(temp_db: Persistence):
    async def scenario():
        _, root_session = await _create_root_session(temp_db)
        # Negative TTL stamps an already-expired elevation.
        await temp_db.elevate_session(root_session.id, -10)
        reloaded, _ = temp_db.get_valid_session_by_auth_token(root_session.id)
        assert reloaded.elevated_until is not None
        assert temp_db.session_is_elevated(reloaded) is False

    asyncio.run(scenario())


def test_session_slide_does_not_extend_elevation(temp_db: Persistence):
    async def scenario():
        _, root_session = await _create_root_session(temp_db)
        deadline = await temp_db.elevate_session(
            root_session.id, config.SUDO_MODE_TTL_SECONDS
        )

        sess, _ = temp_db.get_valid_session_by_auth_token(root_session.id)
        await temp_db.update_session_duration(
            sess, datetime.now(tz=timezone.utc) + timedelta(days=7)
        )

        reloaded, _ = temp_db.get_valid_session_by_auth_token(root_session.id)
        # Sliding valid_until must leave the (shorter, independent) elevation clock alone.
        assert abs((reloaded.elevated_until - deadline).total_seconds()) < 1
        assert reloaded.valid_until > datetime.now(tz=timezone.utc) + timedelta(days=6)

    asyncio.run(scenario())


def test_password_change_clears_elevation(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        await temp_db.elevate_session(root_session.id, config.SUDO_MODE_TTL_SECONDS)

        await temp_db.update_password(root.id, "BrandNewStrong!9")

        # The session is soft-invalidated (valid_until = now), so the valid-session
        # read rejects it outright...
        with pytest.raises(KeyError):
            temp_db.get_valid_session_by_auth_token(root_session.id)
        # ...and the persistence layer also NULLed elevated_until on the row.
        sess = await temp_db.get_session_by_auth_token(root_session.id)
        assert sess.elevated_until is None

    asyncio.run(scenario())


def test_joined_select_parses_user_after_column_add(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)

        sess, user = temp_db.get_valid_session_by_auth_token(root_session.id)
        assert user.id == root.id
        assert user.email == root.email
        assert user.role == root.role
        assert sess.elevated_until is None

        await temp_db.elevate_session(root_session.id, config.SUDO_MODE_TTL_SECONDS)

        sess2, user2 = temp_db.get_valid_session_by_auth_token(root_session.id)
        # The user must still parse correctly after the elevated_until column was
        # inserted ahead of the user columns (slice bump row[5:] -> row[6:]).
        assert user2.id == root.id
        assert user2.email == root.email
        assert user2.role == root.role
        assert sess2.elevated_until is not None

    asyncio.run(scenario())


def test_migration_adds_elevated_until_column(tmp_path: Path):
    """Upgraded DBs (user_sessions created without elevated_until) gain the column."""
    db_path = tmp_path / "legacy.db"

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE user_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            valid_until REAL NOT NULL,
            role TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.commit()
    conn.close()

    persistence = Persistence(db_path=db_path)
    try:
        cursor = persistence._get_cursor()
        cursor.execute("PRAGMA table_info(user_sessions)")
        cols = {row[1] for row in cursor.fetchall()}
        assert "elevated_until" in cols

        async def scenario():
            user = await _create_user(persistence, "legacy@example.com")
            # INSERT must succeed against the migrated table.
            session = await persistence.create_session(user.id)
            reloaded, _ = persistence.get_valid_session_by_auth_token(session.id)
            assert reloaded.elevated_until is None

        asyncio.run(scenario())
    finally:
        persistence.close()


# ---------------------------------------------------------------------------
# Step-up verification helper
# ---------------------------------------------------------------------------


def test_perform_step_up_password_only(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)

        result = await perform_step_up(session, password=PASSWORD, two_factor_code=None)
        assert result.ok is True
        assert result.used_recovery_code is False
        expected = datetime.now(tz=timezone.utc) + timedelta(
            seconds=config.SUDO_MODE_TTL_SECONDS
        )
        assert abs((result.elevated_until - expected).total_seconds()) < 5

        # The gate now passes for this session.
        assert require_elevated_session(session) is not None

    asyncio.run(scenario())


def test_verify_step_up_credentials_does_not_elevate_session(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            root,
            password=PASSWORD,
            two_factor_code=None,
        )

        assert result.ok is True
        assert result.elevated_until is None
        assert require_elevated_session(session) is None
        reloaded, _ = temp_db.get_valid_session_by_auth_token(root_session.id)
        assert reloaded.elevated_until is None

    asyncio.run(scenario())


def test_verify_step_up_credentials_rejects_session_user_mismatch(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        other = await _create_user(temp_db, "other-stepup@example.com")

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            other,
            password=PASSWORD,
            two_factor_code=None,
        )

        assert result.ok is False
        assert result.error_message == "Your session has expired. Please log in again."

    asyncio.run(scenario())


def test_perform_step_up_wrong_password(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)

        result = await perform_step_up(
            session, password="not-the-password", two_factor_code=None
        )
        assert result.ok is False
        assert result.error_message == "Current password is incorrect"
        assert require_elevated_session(session) is None

    asyncio.run(scenario())


def test_perform_step_up_with_2fa(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(root.id, secret)
        session = _FakeSession(temp_db, root_session, root)

        # Missing code.
        missing = await perform_step_up(
            session, password=PASSWORD, two_factor_code=None
        )
        assert missing.ok is False
        assert missing.error_message == "2FA code is required"

        # Wrong code.
        wrong = await perform_step_up(
            session, password=PASSWORD, two_factor_code="000000"
        )
        assert wrong.ok is False
        assert wrong.error_message == "Invalid 2FA or recovery code."

        # Correct code (retry briefly to avoid the 30s TOTP boundary flake).
        ok_result = None
        for _ in range(3):
            ok_result = await perform_step_up(
                session, password=PASSWORD, two_factor_code=_totp_now(secret)
            )
            if ok_result.ok:
                break
        assert ok_result is not None and ok_result.ok is True

    asyncio.run(scenario())


def test_perform_step_up_consumes_recovery_code(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(root.id, secret)
        codes = temp_db.generate_recovery_codes(root.id)
        session = _FakeSession(temp_db, root_session, root)

        result = await perform_step_up(
            session, password=PASSWORD, two_factor_code=codes[0]
        )
        assert result.ok is True
        assert result.used_recovery_code is True

        # The recovery code is single-use, mirroring the settings password-change flow.
        reuse = await perform_step_up(
            session, password=PASSWORD, two_factor_code=codes[0]
        )
        assert reuse.ok is False

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Admin handler gate + dialog flow
# ---------------------------------------------------------------------------


def test_role_change_blocked_without_elevation(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "target@example.com")
        original_role = target.role

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )

        await AdminPage._on_change_role_pressed(page)

        # The step-up dialog is shown and the pending action is stashed...
        assert page.step_up_visible is True
        assert page.step_up_pending_identifier == target.email
        assert page.step_up_pending_new_role == "admin"
        # ...and crucially, no mutation happened.
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == original_role

    asyncio.run(scenario())


def test_expired_elevation_reprompts_via_handler(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "expired@example.com")
        await temp_db.elevate_session(root_session.id, -10)  # already expired

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )

        await AdminPage._on_change_role_pressed(page)

        assert page.step_up_visible is True
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == target.role

    asyncio.run(scenario())


def test_elevated_role_change_succeeds(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "elevated@example.com")
        await temp_db.elevate_session(root_session.id, config.SUDO_MODE_TTL_SECONDS)

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )

        await AdminPage._on_change_role_pressed(page)

        assert page.step_up_visible is False
        assert page.change_role_error == ""
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == "admin"

    asyncio.run(scenario())


def test_full_step_up_dialog_flow_completes_role_change(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "flow@example.com")

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )

        # First attempt is gated and reveals the dialog.
        await AdminPage._on_change_role_pressed(page)
        assert page.step_up_visible is True

        # Supply credentials and submit the dialog.
        page.step_up_password = PASSWORD
        await AdminPage._on_step_up_submit(page)

        assert page.step_up_visible is False
        assert page.change_role_identifier == ""
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == "admin"

    asyncio.run(scenario())


def test_step_up_attempts_are_rate_limited(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS", 2)

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "ratelimit@example.com")

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            step_up_visible=True,
            step_up_pending_identifier=target.email,
            step_up_pending_new_role="admin",
            step_up_password="wrong-password",
        )

        await AdminPage._on_step_up_submit(page)
        assert page.step_up_error == "Current password is incorrect"
        await AdminPage._on_step_up_submit(page)
        assert page.step_up_error == "Current password is incorrect"

        # The third attempt is throttled by the actor-keyed admin_step_up scope.
        await AdminPage._on_step_up_submit(page)
        assert "Too many verification attempts" in page.step_up_error
        # The target was never mutated.
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == target.role

    asyncio.run(scenario())
