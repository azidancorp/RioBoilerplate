import asyncio
import concurrent.futures
import importlib.util
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest

from app.config import config
from app.data_models import AppUser, UserSession, UserSettings
from app.persistence import AdminMutationContext, Persistence


def _load_app_page_guard():
    module_name = "test_app_page_guard_module"
    module = sys.modules.get(module_name)
    if module is not None:
        return module.guard

    module_path = Path(__file__).resolve().parents[1] / "app" / "pages" / "app_page.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load app page guard from {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.guard


class FakeRioSession:
    def __init__(self, persistence: Persistence, user_session: UserSession):
        self.attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=user_session.id),
            UserSession: user_session,
        }
        self.navigation_target: str | None = None

    def __getitem__(self, attachment_type):
        try:
            return self.attachments[attachment_type]
        except KeyError:
            raise KeyError(attachment_type) from None

    def attach(self, attachment):
        self.attachments[type(attachment)] = attachment

    def detach(self, attachment_type):
        del self.attachments[attachment_type]

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url


class FreshRioSession:
    def __init__(self, persistence: Persistence, auth_token: str):
        self.attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=auth_token),
        }

    def __getitem__(self, attachment_type):
        try:
            return self.attachments[attachment_type]
        except KeyError:
            raise KeyError(attachment_type) from None

    def attach(self, attachment):
        self.attachments[type(attachment)] = attachment


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "test.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_root_session(persistence: Persistence) -> tuple[AppUser, UserSession]:
    user = AppUser.create_new_user_with_default_settings(
        email="root@example.com",
        password="password",
        username="root",
    )
    user.role = "root"
    await persistence._create_user_unchecked(user)
    user = await persistence.get_user_by_id(user.id)
    session = await persistence.create_session(user.id)
    return user, session


def _session_row_count(persistence: Persistence, auth_token: str) -> int:
    cursor = persistence._get_cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM user_sessions WHERE id = ?",
        (persistence._hash_one_time_token(auth_token),),
    )
    return cursor.fetchone()[0]


def _guard_event(persistence: Persistence, session: UserSession, url_segment: str):
    return SimpleNamespace(
        session=FakeRioSession(persistence, session),
        active_pages=[SimpleNamespace(url_segment=url_segment)],
    )


def test_guard_rejects_live_session_after_database_revocation(temp_db: Persistence):
    async def scenario():
        user, cached_session = await _create_root_session(temp_db)
        event = _guard_event(temp_db, cached_session, "admin")

        await temp_db.invalidate_all_sessions(user.id)

        assert cached_session.valid_until > datetime.now(timezone.utc)
        assert _load_app_page_guard()(event) == "/"
        assert UserSession not in event.session.attachments
        assert AppUser not in event.session.attachments
        assert event.session[UserSettings].auth_token == ""
        assert event.session.navigation_target is None

    asyncio.run(scenario())


def test_guard_refreshes_demoted_role_before_admin_access_check(temp_db: Persistence):
    async def scenario():
        user, cached_session = await _create_root_session(temp_db)
        event = _guard_event(temp_db, cached_session, "admin")

        await temp_db.update_user_role(user.id, "user")

        assert cached_session.role == "root"
        assert _load_app_page_guard()(event) == "/"
        assert event.session[UserSession].role == "user"
        assert event.session[AppUser].role == "user"

    asyncio.run(scenario())


def test_guard_rejects_live_session_after_database_expiry(temp_db: Persistence):
    async def scenario():
        _, cached_session = await _create_root_session(temp_db)
        event = _guard_event(temp_db, cached_session, "admin")

        cursor = temp_db._get_cursor()
        cursor.execute(
            "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
            (temp_db._hash_one_time_token(cached_session.id),),
        )
        temp_db.conn.commit()

        assert _load_app_page_guard()(event) == "/"
        assert UserSession not in event.session.attachments
        assert AppUser not in event.session.attachments
        assert event.session[UserSettings].auth_token == ""
        assert event.session.navigation_target is None

    asyncio.run(scenario())


def test_session_start_rejects_inactive_stored_auth_token(temp_db: Persistence):
    async def scenario():
        from app import on_session_start

        _, root_session = await _create_root_session(temp_db)
        user = AppUser.create_new_user_with_default_settings(
            email="inactive-session@example.com",
            password="password",
            username="inactive-session",
        )
        await temp_db._create_user_unchecked(user)
        user = await temp_db.get_user_by_id(user.id)
        cached_session = await temp_db.create_session(user.id)
        await temp_db.admin_set_user_active(
            user.id,
            False,
            admin_context=AdminMutationContext(auth_token=root_session.id),
        )

        fresh_session = FreshRioSession(temp_db, cached_session.id)
        await on_session_start(fresh_session)

        assert UserSession not in fresh_session.attachments
        assert AppUser not in fresh_session.attachments
        assert fresh_session[UserSettings].auth_token == ""

    asyncio.run(scenario())


def test_stale_validation_cannot_renew_an_invalidated_session(
    temp_db: Persistence,
):
    async def scenario():
        _, created_session = await _create_root_session(temp_db)
        stale_session, _ = temp_db.get_valid_session_by_auth_token(created_session.id)
        revoker = Persistence(db_path=temp_db.db_path)

        try:
            await revoker.invalidate_all_sessions(created_session.user_id)
        finally:
            revoker.close()

        assert stale_session.id == created_session.id
        assert _session_row_count(temp_db, created_session.id) == 0
        with pytest.raises(KeyError):
            await temp_db.get_and_extend_valid_session_by_auth_token(
                created_session.id,
                valid_for=timedelta(days=7),
            )
        with pytest.raises(KeyError):
            temp_db.get_valid_session_by_auth_token(created_session.id)

    asyncio.run(scenario())


def test_session_start_attaches_nothing_when_atomic_renewal_fails(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        from app import on_session_start

        _, created_session = await _create_root_session(temp_db)
        renewal_attempts: list[tuple[str, timedelta]] = []

        async def reject_renewal(
            auth_token: str,
            *,
            valid_for: timedelta,
        ) -> tuple[UserSession, AppUser]:
            renewal_attempts.append((auth_token, valid_for))
            raise KeyError("Session was revoked before renewal")

        monkeypatch.setattr(
            temp_db,
            "get_and_extend_valid_session_by_auth_token",
            reject_renewal,
        )
        fresh_session = FreshRioSession(temp_db, created_session.id)

        await on_session_start(fresh_session)

        assert renewal_attempts == [(created_session.id, timedelta(days=7))]
        assert UserSession not in fresh_session.attachments
        assert AppUser not in fresh_session.attachments
        assert fresh_session[UserSettings].auth_token == ""

    asyncio.run(scenario())


def test_concurrent_legitimate_session_renewals_both_succeed(
    temp_db: Persistence,
):
    _, created_session = asyncio.run(_create_root_session(temp_db))
    start_barrier = Barrier(2)

    def renew() -> tuple[UserSession, AppUser]:
        persistence = Persistence(db_path=temp_db.db_path)
        try:
            start_barrier.wait(timeout=10)
            return asyncio.run(
                persistence.get_and_extend_valid_session_by_auth_token(
                    created_session.id,
                    valid_for=timedelta(days=7),
                )
            )
        finally:
            persistence.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(renew) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]

    assert [session.id for session, _ in results] == [
        created_session.id,
        created_session.id,
    ]
    assert all(user.id == created_session.user_id for _, user in results)
    assert _session_row_count(temp_db, created_session.id) == 1
    temp_db.get_valid_session_by_auth_token(created_session.id)


@pytest.mark.parametrize(
    "ordering",
    ["renew_then_invalidate", "invalidate_then_renew"],
)
def test_session_renewal_and_invalidation_orderings_end_revoked(
    temp_db: Persistence,
    ordering: str,
):
    async def scenario():
        _, created_session = await _create_root_session(temp_db)

        if ordering == "renew_then_invalidate":
            renewed_session, _ = (
                await temp_db.get_and_extend_valid_session_by_auth_token(
                    created_session.id,
                    valid_for=timedelta(days=7),
                )
            )
            assert renewed_session.id == created_session.id
            await temp_db.invalidate_session(created_session.id)
        else:
            await temp_db.invalidate_session(created_session.id)
            with pytest.raises(KeyError):
                await temp_db.get_and_extend_valid_session_by_auth_token(
                    created_session.id,
                    valid_for=timedelta(days=7),
                )

        assert _session_row_count(temp_db, created_session.id) == 0
        with pytest.raises(KeyError):
            temp_db.get_valid_session_by_auth_token(created_session.id)

    asyncio.run(scenario())


def test_invalidate_session_is_idempotent(temp_db: Persistence):
    async def scenario():
        _, created_session = await _create_root_session(temp_db)

        await temp_db.invalidate_session(created_session.id)
        await temp_db.invalidate_session(created_session.id)

        assert _session_row_count(temp_db, created_session.id) == 0

    asyncio.run(scenario())


def test_session_renewal_clamps_to_absolute_deadline(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        monkeypatch.setattr(config, "SESSION_ABSOLUTE_MAX_DAYS", 2)
        _, created_session = await _create_root_session(temp_db)
        now = datetime.now(timezone.utc)
        created_at = now - timedelta(days=1)
        absolute_deadline = created_at + timedelta(days=2)
        cursor = temp_db._get_cursor()
        cursor.execute(
            """
            UPDATE user_sessions
            SET created_at = ?, valid_until = ?
            WHERE id = ?
            """,
            (
                created_at.timestamp(),
                (now + timedelta(hours=1)).timestamp(),
                temp_db._hash_one_time_token(created_session.id),
            ),
        )
        temp_db.conn.commit()

        renewed_session, _ = (
            await temp_db.get_and_extend_valid_session_by_auth_token(
                created_session.id,
                valid_for=timedelta(days=7),
            )
        )
        stored_session = await temp_db.get_session_by_auth_token(created_session.id)

        assert renewed_session.valid_until.timestamp() == pytest.approx(
            absolute_deadline.timestamp(),
            abs=1e-6,
        )
        assert stored_session.valid_until == renewed_session.valid_until

    asyncio.run(scenario())


def test_session_renewal_rejects_elapsed_absolute_deadline(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        from app import on_session_start

        monkeypatch.setattr(config, "SESSION_ABSOLUTE_MAX_DAYS", 1)
        _, created_session = await _create_root_session(temp_db)
        now = datetime.now(timezone.utc)
        cursor = temp_db._get_cursor()
        cursor.execute(
            """
            UPDATE user_sessions
            SET created_at = ?, valid_until = ?
            WHERE id = ?
            """,
            (
                (now - timedelta(days=2)).timestamp(),
                (now + timedelta(days=1)).timestamp(),
                temp_db._hash_one_time_token(created_session.id),
            ),
        )
        temp_db.conn.commit()

        # This represents a legacy row created before a shorter absolute limit
        # was configured: the sliding expiry is still in the future, but its
        # absolute lifetime has already elapsed.
        await temp_db.get_session_by_auth_token(created_session.id)
        with pytest.raises(KeyError):
            await temp_db.get_and_extend_valid_session_by_auth_token(
                created_session.id,
                valid_for=timedelta(days=7),
            )

        fresh_session = FreshRioSession(temp_db, created_session.id)
        await on_session_start(fresh_session)

        assert UserSession not in fresh_session.attachments
        assert AppUser not in fresh_session.attachments
        assert _session_row_count(temp_db, created_session.id) == 0
        with pytest.raises(KeyError):
            await temp_db.get_session_by_auth_token(created_session.id)

    asyncio.run(scenario())


def test_session_validation_enforces_elapsed_absolute_deadline(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        monkeypatch.setattr(config, "SESSION_ABSOLUTE_MAX_DAYS", 1)
        _, created_session = await _create_root_session(temp_db)
        now = datetime.now(timezone.utc)
        temp_db.conn.execute(
            """
            UPDATE user_sessions
            SET created_at = ?, valid_until = ?
            WHERE id = ?
            """,
            (
                (now - timedelta(days=2)).timestamp(),
                (now + timedelta(days=1)).timestamp(),
                temp_db._hash_one_time_token(created_session.id),
            ),
        )
        temp_db.conn.commit()

        raw_session = await temp_db.get_session_by_auth_token(created_session.id)
        assert raw_session.valid_until > now
        with pytest.raises(KeyError, match="absolute lifetime"):
            temp_db.get_valid_session_by_auth_token(created_session.id)

    asyncio.run(scenario())


def test_session_renewal_rejects_caller_owned_transaction(
    temp_db: Persistence,
):
    async def scenario():
        user, created_session = await _create_root_session(temp_db)
        original_valid_until = created_session.valid_until
        cursor = temp_db._get_cursor()

        # Simulate an unrelated caller-owned transaction with a pending write.
        temp_db.conn.execute("BEGIN")
        cursor.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            ("root-renamed", str(user.id)),
        )

        try:
            with pytest.raises(
                RuntimeError,
                match="Session renewal cannot run inside an existing transaction",
            ):
                await temp_db.get_and_extend_valid_session_by_auth_token(
                    created_session.id,
                    valid_for=timedelta(days=7),
                )

            # The caller's transaction and its pending write must survive.
            assert temp_db.conn.in_transaction
            cursor.execute(
                "SELECT username FROM users WHERE id = ?",
                (str(user.id),),
            )
            assert cursor.fetchone()[0] == "root-renamed"

            # A separate connection must still see the committed value, proving
            # the caller's write was neither committed nor replaced.
            with sqlite3.connect(temp_db.db_path) as verifier:
                assert verifier.execute(
                    "SELECT username FROM users WHERE id = ?",
                    (str(user.id),),
                ).fetchone() == ("root",)

            # Check before the caller rolls back so an in-transaction renewal
            # cannot be hidden by the cleanup below.
            session, _ = temp_db.get_valid_session_by_auth_token(created_session.id)
            assert session.valid_until == original_valid_until
        finally:
            temp_db.conn.rollback()

        # The session itself must be untouched by the rejected renewal.
        session, _ = temp_db.get_valid_session_by_auth_token(created_session.id)
        assert session.valid_until == original_valid_until

    asyncio.run(scenario())
