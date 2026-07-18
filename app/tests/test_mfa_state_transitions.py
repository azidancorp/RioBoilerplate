import asyncio
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
import time

import pyotp
import pytest

from app import persistence_auth
from app.data_models import AppUser, UserSettings, UserSession
from app.pages.app_page import enable_mfa as enable_mfa_page
from app.pages.app_page.disable_mfa import DisableMFA
from app.pages.app_page.enable_mfa import EnableMFA
from app.pages.app_page.recovery_codes import ManageRecoveryCodes
from app.persistence import Persistence, TwoFactorStateConflict


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "mfa-state-transitions.db")
    try:
        yield persistence
    finally:
        persistence.close()


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(
        self,
        persistence: Persistence,
        user_session: UserSession,
        user: AppUser,
    ) -> None:
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=user_session.id),
            UserSession: user_session,
            AppUser: user,
        }
        self.client_ip = "198.51.100.87"
        self.user_agent = "pytest"
        self.http_headers: dict[str, str] = {}
        self.running_as_website = True
        self.navigation_target: str | None = None
        self.navigation_replace = False
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()

    def __getitem__(self, key):
        try:
            return self._attachments[key]
        except KeyError as exc:
            raise KeyError(key) from exc

    def attach(self, value) -> None:
        self._attachments[type(value)] = value

    def detach(self, key) -> None:
        del self._attachments[key]

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url
        self.navigation_replace = replace

    def _register_dirty_component(self, component) -> None:
        pass


async def _create_user(
    persistence: Persistence,
    email: str,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password=PASSWORD,
    )
    # MFA enrollment requires a verified email.
    user.is_verified = True
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


async def _create_user_with_session(
    persistence: Persistence,
    email: str,
) -> tuple[AppUser, UserSession]:
    user = await _create_user(persistence, email)
    user_session = await persistence.create_session(user.id)
    return user, user_session


def _mount_enable_mfa(session: _FakeSession, **attributes) -> EnableMFA:
    component = object.__new__(EnableMFA)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.password = ""
    component.temporary_two_factor_secret = ""
    component.verification_code = ""
    component.qr_code_image_bytes = None
    component.secret = None
    component.error_message = ""
    component.recovery_codes = ()
    component.show_recovery_codes = False
    component.email_unverified = False
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _mount_recovery_codes(
    session: _FakeSession,
    **attributes,
) -> ManageRecoveryCodes:
    component = object.__new__(ManageRecoveryCodes)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.password = ""
    component.verification_code = ""
    component.error_message = ""
    component.success_message = ""
    component.recovery_codes = ()
    component.show_recovery_codes = False
    component.recovery_codes_total = 0
    component.recovery_codes_remaining = 0
    component.last_generated_label = "Never generated"
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _mount_disable_mfa(session: _FakeSession, **attributes) -> DisableMFA:
    component = object.__new__(DisableMFA)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.password = ""
    component.verification_code = ""
    component.error_message = ""
    component.two_factor_enabled = True
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _current_secret(persistence: Persistence, user_id) -> str | None:
    row = persistence.conn.execute(
        "SELECT two_factor_secret FROM users WHERE id = ?",
        (str(user_id),),
    ).fetchone()
    assert row is not None
    return row[0]


def _recovery_code_hashes(persistence: Persistence, user_id) -> tuple[str, ...]:
    rows = persistence.conn.execute(
        """
        SELECT code_hash
        FROM two_factor_recovery_codes
        WHERE user_id = ?
        ORDER BY code_hash
        """,
        (str(user_id),),
    ).fetchall()
    return tuple(row[0] for row in rows)


def _rate_limit_bucket_count(persistence: Persistence, scope: str) -> int:
    row = persistence.conn.execute(
        "SELECT COUNT(*) FROM rate_limit_buckets WHERE scope = ?",
        (scope,),
    ).fetchone()
    assert row is not None
    return row[0]


def _stable_totp_now(secret: str, *, min_seconds_remaining: float = 2.0) -> str:
    totp = pyotp.TOTP(secret)
    interval = float(totp.interval)
    while True:
        remaining = interval - (time.time() % interval)
        if remaining >= min_seconds_remaining:
            return totp.now()
        time.sleep(remaining + 0.05)


def test_enrolled_on_populate_redirects_without_generating_setup_state(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "already-enrolled-populate@example.com",
        )
        temp_db.enroll_two_factor(user.id, pyotp.random_base32())
        enrolled_user = await temp_db.get_user_by_id(user.id)
        session = _FakeSession(temp_db, user_session, enrolled_user)
        page = _mount_enable_mfa(session)

        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("enrolled population must not generate MFA setup data")

        monkeypatch.setattr(enable_mfa_page.pyotp, "random_base32", fail_if_called)
        monkeypatch.setattr(enable_mfa_page.qrcode, "make", fail_if_called)

        await EnableMFA.on_populate(page)

        assert session.navigation_target == "/app/settings"
        assert session.navigation_replace is True
        assert page.temporary_two_factor_secret == ""
        assert page.qr_code_image_bytes is None
        assert page.recovery_codes == ()
        assert page.show_recovery_codes is False

    asyncio.run(scenario())


def test_stale_second_enrollment_is_denied_and_first_factor_remains_intact(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "stale-second-enrollment@example.com",
        )
        first_session = _FakeSession(temp_db, user_session, user)
        second_session = _FakeSession(temp_db, user_session, user)
        first_page = _mount_enable_mfa(first_session)
        second_page = _mount_enable_mfa(second_session)

        # Both pages are staged while MFA is disabled, just like two browser tabs.
        await EnableMFA.on_populate(first_page)
        await EnableMFA.on_populate(second_page)
        first_secret = first_page.temporary_two_factor_secret
        second_secret = second_page.temporary_two_factor_secret
        assert first_secret
        assert second_secret
        assert first_secret != second_secret

        first_page.password = PASSWORD
        first_page.verification_code = _stable_totp_now(first_secret)
        await EnableMFA._on_totp_entered(first_page)

        assert _current_secret(temp_db, user.id) == first_secret
        assert first_page.show_recovery_codes is True
        assert len(first_page.recovery_codes) == 10
        winner_code = first_page.recovery_codes[0]
        winner_hashes = _recovery_code_hashes(temp_db, user.id)
        assert len(winner_hashes) == 10

        second_page.password = PASSWORD
        second_page.verification_code = _stable_totp_now(second_secret)
        await EnableMFA._on_totp_entered(second_page)

        assert _current_secret(temp_db, user.id) == first_secret
        assert _recovery_code_hashes(temp_db, user.id) == winner_hashes
        assert second_page.error_message == "Two-factor authentication is already enabled."
        assert second_page.recovery_codes == ()
        assert second_page.show_recovery_codes is False
        assert second_session.navigation_target == "/app/settings"
        assert second_session.navigation_replace is True

        assert temp_db.verify_two_factor_challenge(
            user.id,
            _stable_totp_now(first_secret),
        ).ok
        assert temp_db.verify_two_factor_challenge(user.id, winner_code).ok

    asyncio.run(scenario())


def test_duplicate_enrollment_submission_preserves_displayed_recovery_codes(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "duplicate-enrollment-submit@example.com",
        )
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_enable_mfa(session)
        await EnableMFA.on_populate(page)

        secret = page.temporary_two_factor_secret
        page.password = PASSWORD
        page.verification_code = _stable_totp_now(secret)

        await EnableMFA._on_totp_entered(page)

        displayed_codes = page.recovery_codes
        stored_hashes = _recovery_code_hashes(temp_db, user.id)
        assert page.show_recovery_codes is True
        assert len(displayed_codes) == 10
        assert len(stored_hashes) == 10
        assert session.navigation_target is None

        # Simulate a second button/Enter event that was queued before the client
        # rendered the successful recovery-code view.
        await EnableMFA._on_totp_entered(page)

        assert page.show_recovery_codes is True
        assert page.recovery_codes == displayed_codes
        assert _current_secret(temp_db, user.id) == secret
        assert _recovery_code_hashes(temp_db, user.id) == stored_hashes
        assert _rate_limit_bucket_count(temp_db, "mfa_enable") == 0
        assert session.navigation_target is None

    asyncio.run(scenario())


def test_enrollment_conflict_keeps_rate_limit_attempt_and_exposes_no_codes(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "enrollment-conflict-rate-limit@example.com",
        )
        session = _FakeSession(temp_db, user_session, user)
        secret = pyotp.random_base32()
        page = _mount_enable_mfa(
            session,
            password=PASSWORD,
            temporary_two_factor_secret=secret,
            verification_code=_stable_totp_now(secret),
        )

        def lose_enrollment_race(*_args, **_kwargs):
            raise TwoFactorStateConflict("injected enrollment conflict")

        monkeypatch.setattr(temp_db, "enroll_two_factor", lose_enrollment_race)

        await EnableMFA._on_totp_entered(page)

        assert _rate_limit_bucket_count(temp_db, "mfa_enable") == 1
        assert _current_secret(temp_db, user.id) is None
        assert _recovery_code_hashes(temp_db, user.id) == ()
        assert page.recovery_codes == ()
        assert page.show_recovery_codes is False
        assert page.temporary_two_factor_secret == ""
        assert session.navigation_target == "/app/settings"
        assert session.navigation_replace is True

    asyncio.run(scenario())


def test_enrollment_still_displays_codes_when_rate_limit_cleanup_fails(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "enrollment-rate-limit-cleanup@example.com",
        )
        session = _FakeSession(temp_db, user_session, user)
        secret = pyotp.random_base32()
        page = _mount_enable_mfa(
            session,
            password=PASSWORD,
            temporary_two_factor_secret=secret,
            verification_code=_stable_totp_now(secret),
        )

        temp_db.conn.execute(
            """
            CREATE TRIGGER reject_mfa_enable_bucket_delete
            BEFORE DELETE ON rate_limit_buckets
            WHEN OLD.scope = 'mfa_enable'
            BEGIN
                SELECT RAISE(ABORT, 'injected rate-limit cleanup failure');
            END
            """
        )
        temp_db.conn.commit()

        await EnableMFA._on_totp_entered(page)

        assert not temp_db.conn.in_transaction
        assert _current_secret(temp_db, user.id) == secret
        assert page.show_recovery_codes is True
        assert len(page.recovery_codes) == 10
        assert temp_db.get_recovery_codes_summary(user.id)["total"] == 10
        assert _rate_limit_bucket_count(temp_db, "mfa_enable") == 1

    asyncio.run(scenario())


def test_persistence_rejects_second_enrollment_without_changing_first_factor(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "second-enrollment@example.com")
        first_secret = pyotp.random_base32()
        second_secret = pyotp.random_base32()
        first_codes = temp_db.enroll_two_factor(user.id, first_secret, count=2)
        hashes_before = _recovery_code_hashes(temp_db, user.id)

        with pytest.raises(TwoFactorStateConflict):
            temp_db.enroll_two_factor(user.id, second_secret, count=3)

        assert _current_secret(temp_db, user.id) == first_secret
        assert _recovery_code_hashes(temp_db, user.id) == hashes_before
        assert temp_db.verify_two_factor_challenge(user.id, first_codes[0]).ok

    asyncio.run(scenario())


def test_competing_enrollments_have_exactly_one_winner(temp_db: Persistence):
    async def setup() -> AppUser:
        return await _create_user(temp_db, "concurrent-enrollment@example.com")

    user = asyncio.run(setup())
    db_path = temp_db.db_path
    barrier = threading.Barrier(2)
    secrets = (pyotp.random_base32(), pyotp.random_base32())

    def attempt(secret: str) -> tuple[str, str, tuple[str, ...]]:
        persistence = Persistence(db_path=db_path)
        try:
            barrier.wait(timeout=5)
            try:
                codes = persistence.enroll_two_factor(user.id, secret, count=2)
            except TwoFactorStateConflict:
                return "conflict", secret, ()
            return "winner", secret, tuple(codes)
        finally:
            persistence.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(attempt, secrets))

    winners = [outcome for outcome in outcomes if outcome[0] == "winner"]
    conflicts = [outcome for outcome in outcomes if outcome[0] == "conflict"]
    assert len(winners) == 1
    assert len(conflicts) == 1
    assert _current_secret(temp_db, user.id) == winners[0][1]
    assert len(winners[0][2]) == 2
    assert temp_db.get_recovery_codes_summary(user.id)["total"] == 2
    assert temp_db.verify_two_factor_challenge(user.id, winners[0][2][0]).ok


def test_enrollment_accepts_legacy_empty_disabled_secret(temp_db: Persistence):
    async def scenario() -> None:
        user = await _create_user(temp_db, "legacy-empty-secret@example.com")
        secret = pyotp.random_base32()
        temp_db.conn.execute(
            "UPDATE users SET two_factor_secret = '' WHERE id = ?",
            (str(user.id),),
        )
        temp_db.conn.commit()

        recovery_codes = temp_db.enroll_two_factor(user.id, secret, count=2)

        assert _current_secret(temp_db, user.id) == secret
        assert len(recovery_codes) == 2
        assert temp_db.get_recovery_codes_summary(user.id)["total"] == 2

    asyncio.run(scenario())


def test_compatibility_setter_is_idempotent_but_rejects_replacement(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "idempotent-secret-setter@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)

        temp_db.set_2fa_secret(user.id, secret)

        assert _current_secret(temp_db, user.id) == secret
        with pytest.raises(TwoFactorStateConflict):
            temp_db.set_2fa_secret(user.id, pyotp.random_base32())
        assert _current_secret(temp_db, user.id) == secret

    asyncio.run(scenario())


def test_compatibility_setter_discards_dormant_recovery_codes_on_enable(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "dormant-recovery-code@example.com")
        now = datetime.now(timezone.utc)
        temp_db.conn.execute(
            """
            INSERT INTO two_factor_recovery_codes (
                user_id, code_hash, created_at, valid_until, used_at
            ) VALUES (?, ?, ?, ?, NULL)
            """,
            (
                str(user.id),
                "dormant-code-hash",
                now.timestamp(),
                (now + timedelta(hours=1)).timestamp(),
            ),
        )
        temp_db.conn.commit()
        assert _recovery_code_hashes(temp_db, user.id) == ("dormant-code-hash",)

        temp_db.set_2fa_secret(user.id, pyotp.random_base32())

        assert _recovery_code_hashes(temp_db, user.id) == ()

    asyncio.run(scenario())


def test_enrollment_rejects_nested_transaction_without_rolling_it_back(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "nested-enrollment-transaction@example.com")
        temp_db.conn.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            ("outer-transaction-change", str(user.id)),
        )
        assert temp_db.conn.in_transaction

        with pytest.raises(
            RuntimeError,
            match="cannot run inside an existing transaction",
        ):
            temp_db.enroll_two_factor(user.id, pyotp.random_base32())

        assert temp_db.conn.in_transaction
        row = temp_db.conn.execute(
            "SELECT username, two_factor_secret FROM users WHERE id = ?",
            (str(user.id),),
        ).fetchone()
        assert row == ("outer-transaction-change", None)

        temp_db.conn.rollback()
        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.username is None
        assert refreshed.two_factor_secret is None

    asyncio.run(scenario())


def test_recovery_code_insert_failure_rolls_back_enrollment(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "enrollment-rollback@example.com")

        def insert_then_fail(cursor, user_id, count):
            now = datetime.now(timezone.utc)
            cursor.execute(
                """
                INSERT INTO two_factor_recovery_codes (
                    user_id, code_hash, created_at, valid_until, used_at
                ) VALUES (?, ?, ?, ?, NULL)
                """,
                (
                    str(user_id),
                    "injected-code-hash",
                    now.timestamp(),
                    (now + timedelta(hours=1)).timestamp(),
                ),
            )
            raise RuntimeError("injected recovery-code insertion failure")

        monkeypatch.setattr(
            persistence_auth,
            "_replace_recovery_codes",
            insert_then_fail,
        )

        with pytest.raises(
            RuntimeError,
            match="injected recovery-code insertion failure",
        ):
            temp_db.enroll_two_factor(user.id, pyotp.random_base32())

        assert _current_secret(temp_db, user.id) is None
        assert _recovery_code_hashes(temp_db, user.id) == ()

    asyncio.run(scenario())


def test_recovery_code_regeneration_is_rejected_while_mfa_is_disabled(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "disabled-recovery-codes@example.com")

        with pytest.raises(TwoFactorStateConflict):
            temp_db.generate_recovery_codes(user.id)

        assert _current_secret(temp_db, user.id) is None
        assert _recovery_code_hashes(temp_db, user.id) == ()

    asyncio.run(scenario())


def test_recovery_code_regeneration_rejects_changed_factor(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "changed-factor-recovery-codes@example.com")
        verified_secret = pyotp.random_base32()
        changed_secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, verified_secret, count=2)
        hashes_before = _recovery_code_hashes(temp_db, user.id)
        temp_db.conn.execute(
            "UPDATE users SET two_factor_secret = ? WHERE id = ?",
            (changed_secret, str(user.id)),
        )
        temp_db.conn.commit()

        with pytest.raises(TwoFactorStateConflict):
            temp_db.generate_recovery_codes(
                user.id,
                expected_secret=verified_secret,
            )

        assert _current_secret(temp_db, user.id) == changed_secret
        assert _recovery_code_hashes(temp_db, user.id) == hashes_before

    asyncio.run(scenario())


def test_stale_recovery_code_handler_fails_closed_while_mfa_is_disabled(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "stale-disabled-recovery-codes@example.com",
        )
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_recovery_codes(
            session,
            password=PASSWORD,
            verification_code="",
        )

        await ManageRecoveryCodes._on_generate_pressed(page)

        assert page.error_message == "Two-factor authentication is no longer enabled."
        assert page.recovery_codes == ()
        assert page.show_recovery_codes is False
        assert _recovery_code_hashes(temp_db, user.id) == ()
        assert _rate_limit_bucket_count(temp_db, "recovery_codes_regenerate") == 0
        assert session.navigation_target == "/app/settings"
        assert session.navigation_replace is True

    asyncio.run(scenario())


def test_recovery_regeneration_displays_codes_when_cleanup_and_summary_fail(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "recovery-rate-limit-cleanup@example.com",
        )
        secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, secret, count=2)
        hashes_before = _recovery_code_hashes(temp_db, user.id)
        enrolled_user = await temp_db.get_user_by_id(user.id)
        session = _FakeSession(temp_db, user_session, enrolled_user)
        page = _mount_recovery_codes(
            session,
            password=PASSWORD,
            verification_code=_stable_totp_now(secret),
        )

        def fail_cleanup(*_args, **_kwargs):
            raise RuntimeError("injected rate-limit cleanup failure")

        def fail_summary(*_args, **_kwargs):
            raise RuntimeError("injected summary refresh failure")

        monkeypatch.setattr(temp_db, "clear_rate_limit", fail_cleanup)
        monkeypatch.setattr(page, "_refresh_summary", fail_summary)

        await ManageRecoveryCodes._on_generate_pressed(page)

        assert page.show_recovery_codes is True
        assert len(page.recovery_codes) == 10
        assert _recovery_code_hashes(temp_db, user.id) != hashes_before
        assert temp_db.get_recovery_codes_summary(user.id)["total"] == 10
        assert _rate_limit_bucket_count(temp_db, "recovery_codes_regenerate") == 1

    asyncio.run(scenario())


def test_recovery_regeneration_state_conflict_preserves_codes_and_attempt(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "recovery-state-conflict@example.com",
        )
        secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, secret, count=2)
        hashes_before = _recovery_code_hashes(temp_db, user.id)
        enrolled_user = await temp_db.get_user_by_id(user.id)
        session = _FakeSession(temp_db, user_session, enrolled_user)
        page = _mount_recovery_codes(
            session,
            password=PASSWORD,
            verification_code=_stable_totp_now(secret),
        )

        def lose_regeneration_race(*_args, **_kwargs):
            raise TwoFactorStateConflict("injected recovery-code conflict")

        monkeypatch.setattr(
            temp_db,
            "generate_recovery_codes",
            lose_regeneration_race,
        )

        await ManageRecoveryCodes._on_generate_pressed(page)

        assert _current_secret(temp_db, user.id) == secret
        assert _recovery_code_hashes(temp_db, user.id) == hashes_before
        assert page.error_message == "Two-factor authentication changed. Please try again."
        assert page.recovery_codes == ()
        assert page.show_recovery_codes is False
        assert _rate_limit_bucket_count(temp_db, "recovery_codes_regenerate") == 1
        assert session.navigation_target == "/app/settings"

    asyncio.run(scenario())


def test_disable_completes_when_rate_limit_cleanup_fails(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "disable-rate-limit-cleanup@example.com",
        )
        secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, secret, count=2)
        enrolled_user = await temp_db.get_user_by_id(user.id)
        session = _FakeSession(temp_db, user_session, enrolled_user)
        page = _mount_disable_mfa(
            session,
            password=PASSWORD,
            verification_code=_stable_totp_now(secret),
        )

        def fail_cleanup(*_args, **_kwargs):
            raise RuntimeError("injected rate-limit cleanup failure")

        monkeypatch.setattr(temp_db, "clear_rate_limit", fail_cleanup)

        await DisableMFA._on_totp_entered(page)

        assert _current_secret(temp_db, user.id) is None
        assert _recovery_code_hashes(temp_db, user.id) == ()
        assert page.two_factor_enabled is False
        assert session.navigation_target == "/app/settings"
        assert session.navigation_replace is True
        assert _rate_limit_bucket_count(temp_db, "mfa_disable") == 1

    asyncio.run(scenario())


def test_disable_state_conflict_preserves_factor_codes_and_attempt(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "disable-state-conflict@example.com",
        )
        secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, secret, count=2)
        hashes_before = _recovery_code_hashes(temp_db, user.id)
        enrolled_user = await temp_db.get_user_by_id(user.id)
        session = _FakeSession(temp_db, user_session, enrolled_user)
        page = _mount_disable_mfa(
            session,
            password=PASSWORD,
            verification_code=_stable_totp_now(secret),
        )

        monkeypatch.setattr(
            temp_db,
            "disable_two_factor",
            lambda *_args, **_kwargs: False,
        )

        await DisableMFA._on_totp_entered(page)

        assert _current_secret(temp_db, user.id) == secret
        assert _recovery_code_hashes(temp_db, user.id) == hashes_before
        assert page.error_message == "Two-factor authentication changed. Please try again."
        assert _rate_limit_bucket_count(temp_db, "mfa_disable") == 1
        assert session.navigation_target == "/app/settings"

    asyncio.run(scenario())


def test_disable_compare_and_swap_preserves_a_newly_changed_factor(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user = await _create_user(temp_db, "disable-cas@example.com")
        verified_secret = pyotp.random_base32()
        changed_secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, verified_secret, count=2)
        hashes_before = _recovery_code_hashes(temp_db, user.id)

        # Simulate another worker replacing the factor after this request verified it.
        temp_db.conn.execute(
            "UPDATE users SET two_factor_secret = ? WHERE id = ?",
            (changed_secret, str(user.id)),
        )
        temp_db.conn.commit()

        disabled = temp_db.disable_two_factor(
            user.id,
            expected_secret=verified_secret,
        )

        assert disabled is False
        assert _current_secret(temp_db, user.id) == changed_secret
        assert _recovery_code_hashes(temp_db, user.id) == hashes_before

    asyncio.run(scenario())


def test_unverified_email_cannot_enroll_two_factor(temp_db: Persistence):
    async def scenario() -> None:
        user = AppUser.create_new_user_with_default_settings(
            email="unverified-enroll@example.com",
            password=PASSWORD,
        )
        await temp_db._create_user_unchecked(user)

        with pytest.raises(persistence_auth.TwoFactorEmailUnverifiedError):
            temp_db.enroll_two_factor(user.id, pyotp.random_base32())

        assert _current_secret(temp_db, user.id) is None
        assert _recovery_code_hashes(temp_db, user.id) == ()

        with pytest.raises(persistence_auth.TwoFactorEmailUnverifiedError):
            persistence_auth.set_2fa_secret(
                temp_db,
                user.id,
                pyotp.random_base32(),
            )

        assert _current_secret(temp_db, user.id) is None
        assert _recovery_code_hashes(temp_db, user.id) == ()

    asyncio.run(scenario())


def test_unverified_email_on_populate_shows_gate_without_setup_state(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario() -> None:
        user = AppUser.create_new_user_with_default_settings(
            email="unverified-populate@example.com",
            password=PASSWORD,
        )
        await temp_db._create_user_unchecked(user)
        user = await temp_db.get_user_by_id(user.id)
        user_session = await temp_db.create_session(user.id)
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_enable_mfa(session)

        def fail_if_called(*_args, **_kwargs):
            raise AssertionError(
                "unverified population must not generate MFA setup data"
            )

        monkeypatch.setattr(enable_mfa_page.pyotp, "random_base32", fail_if_called)
        monkeypatch.setattr(enable_mfa_page.qrcode, "make", fail_if_called)

        await EnableMFA.on_populate(page)

        assert page.email_unverified is True
        assert page.temporary_two_factor_secret == ""
        assert page.qr_code_image_bytes is None
        assert session.navigation_target is None

    asyncio.run(scenario())


def test_enrollment_submit_blocked_when_verification_revoked_mid_setup(
    temp_db: Persistence,
):
    async def scenario() -> None:
        user, user_session = await _create_user_with_session(
            temp_db,
            "revoked-mid-setup@example.com",
        )
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_enable_mfa(session)
        await EnableMFA.on_populate(page)
        secret = page.temporary_two_factor_secret
        assert secret

        # Verification revoked between page load and submission.
        temp_db.conn.execute(
            "UPDATE users SET is_verified = 0 WHERE id = ?",
            (str(user.id),),
        )
        temp_db.conn.commit()

        page.password = PASSWORD
        page.verification_code = _stable_totp_now(secret)
        await EnableMFA._on_totp_entered(page)

        assert page.email_unverified is True
        assert page.show_recovery_codes is False
        assert page.temporary_two_factor_secret == ""
        assert _current_secret(temp_db, user.id) is None
        assert _recovery_code_hashes(temp_db, user.id) == ()

    asyncio.run(scenario())
