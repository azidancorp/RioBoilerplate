import asyncio
import sqlite3
import threading
from pathlib import Path

import pytest

from app.data_models import AppUser, UserSession
from app.persistence import AdminMutationContext, Persistence


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "session-creation-atomicity.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_root_and_target(
    persistence: Persistence,
) -> tuple[AppUser, AppUser]:
    root = AppUser.create_new_user_with_default_settings(
        email="session-race-root@example.com",
        password=PASSWORD,
        username="session-race-root",
    )
    root.role = "root"
    root.is_verified = True

    target = AppUser.create_new_user_with_default_settings(
        email="session-race-target@example.com",
        password=PASSWORD,
        username="session-race-target",
    )
    target.is_verified = True

    await persistence._create_user_unchecked(root)
    await persistence._create_user_unchecked(target)
    return (
        await persistence.get_user_by_id(root.id),
        await persistence.get_user_by_id(target.id),
    )


def _session_count(persistence: Persistence, user: AppUser) -> int:
    row = persistence.conn.execute(
        "SELECT COUNT(*) FROM user_sessions WHERE user_id = ?",
        (str(user.id),),
    ).fetchone()
    assert row is not None
    return int(row[0])


async def _admin_context(
    persistence: Persistence,
    actor: AppUser,
) -> AdminMutationContext:
    session = await persistence.create_session(actor.id)
    return AdminMutationContext(auth_token=session.id)


def test_deactivation_wins_before_session_creation_rereads_state(
    temp_db: Persistence,
):
    _, target = asyncio.run(_create_root_and_target(temp_db))
    deactivator = Persistence(db_path=temp_db.db_path)
    begin_attempted = threading.Event()
    outcome: dict[str, object] = {}

    deactivator.conn.execute("BEGIN IMMEDIATE")
    deactivator.conn.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (str(target.id),),
    )
    deactivator.conn.execute(
        "DELETE FROM user_sessions WHERE user_id = ?",
        (str(target.id),),
    )

    def create_session() -> None:
        persistence = Persistence(db_path=temp_db.db_path)

        def trace(statement: str) -> None:
            if statement.strip().upper().startswith("BEGIN IMMEDIATE"):
                begin_attempted.set()

        persistence.conn.set_trace_callback(trace)
        try:
            outcome["session"] = asyncio.run(
                persistence.create_session(target.id)
            )
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            outcome["in_transaction"] = persistence.conn.in_transaction
            persistence.close()

    creator_thread = threading.Thread(target=create_session)
    creator_thread.start()
    attempted = begin_attempted.wait(timeout=10)
    deactivator.conn.commit()
    creator_thread.join(timeout=10)
    deactivator.close()

    assert attempted is True
    assert creator_thread.is_alive() is False
    assert isinstance(outcome.get("error"), KeyError)
    assert "session" not in outcome
    assert outcome["in_transaction"] is False
    assert _session_count(temp_db, target) == 0


def test_session_creation_wins_then_deactivation_deletes_new_session(
    temp_db: Persistence,
):
    root, target = asyncio.run(_create_root_and_target(temp_db))
    admin_context = asyncio.run(_admin_context(temp_db, root))
    state_read_reached = threading.Event()
    allow_session_creation = threading.Event()
    deactivation_begin_attempted = threading.Event()
    outcome: dict[str, object] = {}

    def create_session() -> None:
        persistence = Persistence(db_path=temp_db.db_path)

        def trace(statement: str) -> None:
            normalized = " ".join(statement.upper().split())
            if (
                "SELECT IS_ACTIVE, ROLE FROM USERS" in normalized
                and not state_read_reached.is_set()
            ):
                state_read_reached.set()
                allow_session_creation.wait(timeout=10)

        persistence.conn.set_trace_callback(trace)
        try:
            outcome["session"] = asyncio.run(
                persistence.create_session(target.id)
            )
        except BaseException as exc:
            outcome["creator_error"] = exc
        finally:
            persistence.close()

    def deactivate() -> None:
        persistence = Persistence(db_path=temp_db.db_path)

        def trace(statement: str) -> None:
            if statement.strip().upper().startswith("BEGIN IMMEDIATE"):
                deactivation_begin_attempted.set()

        persistence.conn.set_trace_callback(trace)
        try:
            outcome["deactivated_user"] = asyncio.run(
                persistence.admin_set_user_active(
                    target.id,
                    False,
                    admin_context=admin_context,
                )
            )
        except BaseException as exc:
            outcome["deactivation_error"] = exc
        finally:
            persistence.close()

    creator_thread = threading.Thread(target=create_session)
    creator_thread.start()
    state_read_seen = state_read_reached.wait(timeout=10)

    deactivation_thread = threading.Thread(target=deactivate)
    if state_read_seen:
        deactivation_thread.start()
        deactivation_attempted = deactivation_begin_attempted.wait(timeout=10)
    else:
        deactivation_attempted = False

    allow_session_creation.set()
    creator_thread.join(timeout=10)
    if state_read_seen:
        deactivation_thread.join(timeout=10)

    assert state_read_seen is True
    assert deactivation_attempted is True
    assert creator_thread.is_alive() is False
    assert deactivation_thread.is_alive() is False
    assert "creator_error" not in outcome
    assert "deactivation_error" not in outcome

    created_session = outcome.get("session")
    assert isinstance(created_session, UserSession)
    deactivated_user = outcome.get("deactivated_user")
    assert isinstance(deactivated_user, AppUser)
    assert deactivated_user.is_active is False
    assert _session_count(temp_db, target) == 0
    with pytest.raises(KeyError):
        temp_db.get_valid_session_by_auth_token(created_session.id)


def test_reactivation_purges_a_legacy_dormant_session(temp_db: Persistence):
    async def scenario() -> None:
        root, target = await _create_root_and_target(temp_db)
        admin_context = await _admin_context(temp_db, root)
        session = await temp_db.create_session(target.id)

        temp_db.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(target.id),),
        )
        temp_db.conn.commit()

        assert (await temp_db.get_session_by_auth_token(session.id)).id == session.id
        with pytest.raises(KeyError):
            temp_db.get_valid_session_by_auth_token(session.id)

        reactivated = await temp_db.admin_set_user_active(
            target.id,
            True,
            admin_context=admin_context,
        )

        assert reactivated.is_active is True
        assert _session_count(temp_db, target) == 0
        with pytest.raises(KeyError):
            await temp_db.get_session_by_auth_token(session.id)

    asyncio.run(scenario())


def test_active_to_active_noop_preserves_live_sessions(temp_db: Persistence):
    async def scenario() -> None:
        root, target = await _create_root_and_target(temp_db)
        admin_context = await _admin_context(temp_db, root)
        session = await temp_db.create_session(target.id)

        unchanged = await temp_db.admin_set_user_active(
            target.id,
            True,
            admin_context=admin_context,
        )

        assert unchanged.is_active is True
        assert _session_count(temp_db, target) == 1
        validated, _ = temp_db.get_valid_session_by_auth_token(session.id)
        assert validated.id == session.id

    asyncio.run(scenario())


def test_deactivation_invalidates_pending_oauth_state(temp_db: Persistence):
    async def scenario() -> None:
        root, target = await _create_root_and_target(temp_db)
        admin_context = await _admin_context(temp_db, root)
        binding_digest = "a" * 64
        deletion_token_hash = temp_db._hash_one_time_token(
            "DELETE-START-" + "A" * 64
        )
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            user_id=target.id,
            provider="google",
        )
        temp_db.conn.execute(
            """
            INSERT INTO oauth_login_handoffs (
                token_hash, user_id, provider, created_at, valid_until, consumed_at
            )
            VALUES (?, ?, ?, 0, 99999999999, NULL)
            """,
            (
                deletion_token_hash,
                str(target.id),
                "google:delete-account:test-session",
            ),
        )
        temp_db.conn.commit()

        await temp_db.admin_set_user_active(
            target.id,
            False,
            admin_context=admin_context,
        )
        await temp_db.admin_set_user_active(
            target.id,
            True,
            admin_context=admin_context,
        )

        with pytest.raises(KeyError):
            await temp_db.consume_oauth_pending_login(binding_digest)
        assert temp_db.conn.execute(
            "SELECT COUNT(*) FROM oauth_pending_logins WHERE user_id = ?",
            (str(target.id),),
        ).fetchone() == (0,)
        assert temp_db.conn.execute(
            "SELECT COUNT(*) FROM oauth_login_handoffs WHERE user_id = ?",
            (str(target.id),),
        ).fetchone() == (0,)

    asyncio.run(scenario())


def test_create_session_refuses_caller_transaction_without_rolling_it_back(
    temp_db: Persistence,
):
    _, target = asyncio.run(_create_root_and_target(temp_db))

    temp_db.conn.execute("BEGIN IMMEDIATE")
    temp_db.conn.execute(
        "UPDATE users SET username = ? WHERE id = ?",
        ("pending-username", str(target.id)),
    )

    with pytest.raises(RuntimeError, match="existing transaction"):
        asyncio.run(temp_db.create_session(target.id))

    assert temp_db.conn.in_transaction is True
    assert temp_db.conn.execute(
        "SELECT username FROM users WHERE id = ?",
        (str(target.id),),
    ).fetchone() == ("pending-username",)
    temp_db.conn.rollback()

    assert temp_db.conn.execute(
        "SELECT username FROM users WHERE id = ?",
        (str(target.id),),
    ).fetchone() == ("session-race-target",)
    assert _session_count(temp_db, target) == 0


def test_session_insert_failure_rolls_back_owned_transaction(temp_db: Persistence):
    _, target = asyncio.run(_create_root_and_target(temp_db))
    temp_db.conn.execute(
        """
        CREATE TRIGGER reject_test_session_insert
        BEFORE INSERT ON user_sessions
        BEGIN
            SELECT RAISE(ABORT, 'forced session insert failure');
        END
        """
    )
    temp_db.conn.commit()

    with pytest.raises(sqlite3.IntegrityError, match="forced session insert failure"):
        asyncio.run(temp_db.create_session(target.id))

    assert temp_db.conn.in_transaction is False
    assert _session_count(temp_db, target) == 0
