"""Tests for the admin action audit log (persistence_audit + instrumentation).

Covers attribution (who/what/whom/when), atomicity with the mutation, survival
across user deletion (no FK cascade), filtering/ordering, secret hygiene, and the
backward-compatible actor-less call paths.
"""

import asyncio
import concurrent.futures
import sqlite3
import threading
import uuid
from pathlib import Path

import pytest

from app.data_models import AppUser
from app.persistence import AdminMutationContext, Persistence


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "audit-log.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_user(
    persistence: Persistence,
    email: str,
    *,
    role: str = "user",
    password: str = PASSWORD,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    user.role = role
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


async def _create_admin_context(
    persistence: Persistence,
    actor: AppUser,
    *,
    client_ip: str | None = None,
) -> AdminMutationContext:
    session = await persistence.create_session(actor.id)
    return AdminMutationContext(auth_token=session.id, client_ip=client_ip)


def test_role_change_writes_single_row_atomically(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "root@example.com", role="root")
        target = await _create_user(temp_db, "target@example.com", role="user")
        admin_context = await _create_admin_context(
            temp_db,
            admin,
            client_ip="203.0.113.7",
        )

        await temp_db.admin_update_user_role(
            target.id,
            "admin",
            admin_context=admin_context,
        )

        # State changed ...
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == "admin"

        # ... and exactly one audit row describes it.
        rows = temp_db.list_admin_actions(target_user_id=target.id, action="role_change")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_user_id"] == admin.id
        assert row["actor_role"] == "root"
        assert row["target_user_id"] == target.id
        assert row["target_label"] == "target@example.com"
        assert row["before"] == {"role": "user"}
        assert row["after"] == {"role": "admin"}
        assert row["client_ip"] == "203.0.113.7"
        assert row["outcome"] == "success"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("trigger_sql", "error_message"),
    [
        (
            """
            CREATE TRIGGER fail_role_session_update
            BEFORE UPDATE OF role ON user_sessions
            BEGIN
                SELECT RAISE(ABORT, 'injected session update failure');
            END
            """,
            "injected session update failure",
        ),
        (
            """
            CREATE TRIGGER fail_role_audit_insert
            BEFORE INSERT ON admin_audit_log
            WHEN NEW.action = 'role_change'
            BEGIN
                SELECT RAISE(ABORT, 'injected audit insert failure');
            END
            """,
            "injected audit insert failure",
        ),
    ],
    ids=("session-update", "audit-insert"),
)
def test_role_change_rolls_back_every_write_on_failure(
    temp_db: Persistence,
    trigger_sql: str,
    error_message: str,
):
    async def scenario():
        admin = await _create_user(temp_db, "rollback-root@example.com", role="root")
        target = await _create_user(temp_db, "rollback-target@example.com")
        admin_context = await _create_admin_context(temp_db, admin)
        await temp_db.create_session(target.id)

        temp_db.conn.execute(trigger_sql)
        temp_db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match=error_message):
            await temp_db.admin_update_user_role(
                target.id,
                "admin",
                admin_context=admin_context,
            )

        assert temp_db.conn.in_transaction is False
        assert (await temp_db.get_user_by_id(target.id)).role == "user"
        session_roles = temp_db.conn.execute(
            "SELECT role FROM user_sessions WHERE user_id = ?",
            (str(target.id),),
        ).fetchall()
        assert session_roles == [("user",)]
        assert temp_db.list_admin_actions(
            target_user_id=target.id,
            action="role_change",
        ) == []

        # A later, unrelated commit must not publish any part of the failed role
        # change on this connection.
        await temp_db.update_notification_preferences(
            admin.id,
            email_notifications_enabled=False,
        )
        with sqlite3.connect(temp_db.db_path) as verifier:
            assert verifier.execute(
                "SELECT role FROM users WHERE id = ?",
                (str(target.id),),
            ).fetchone() == ("user",)
            assert verifier.execute(
                "SELECT role FROM user_sessions WHERE user_id = ?",
                (str(target.id),),
            ).fetchall() == [("user",)]
            assert verifier.execute(
                """
                SELECT COUNT(*) FROM admin_audit_log
                WHERE target_user_id = ? AND action = 'role_change'
                """,
                (str(target.id),),
            ).fetchone() == (0,)

    asyncio.run(scenario())


def test_role_change_preserves_a_caller_owned_transaction(temp_db: Persistence):
    async def scenario():
        target = await _create_user(temp_db, "nested-role-change@example.com")
        temp_db.conn.execute(
            "UPDATE users SET email_notifications_enabled = 0 WHERE id = ?",
            (str(target.id),),
        )
        assert temp_db.conn.in_transaction is True

        with pytest.raises(
            RuntimeError,
            match="cannot run inside an existing transaction",
        ):
            await temp_db.update_user_role(target.id, "admin")

        assert temp_db.conn.in_transaction is True
        assert temp_db.conn.execute(
            "SELECT email_notifications_enabled FROM users WHERE id = ?",
            (str(target.id),),
        ).fetchone() == (0,)
        with sqlite3.connect(temp_db.db_path) as verifier:
            assert verifier.execute(
                "SELECT email_notifications_enabled FROM users WHERE id = ?",
                (str(target.id),),
            ).fetchone() == (1,)

        temp_db.conn.rollback()

    asyncio.run(scenario())


def test_concurrent_role_changes_record_a_coherent_audit_chain(
    temp_db: Persistence,
):
    async def setup():
        target = await _create_user(temp_db, "concurrent-role-change@example.com")
        await temp_db.create_session(target.id)
        return target

    target = asyncio.run(setup())
    original_get_user_by_id = temp_db.get_user_by_id
    coordinate_reads = threading.Event()
    stale_read_barrier = threading.Barrier(2)
    start_barrier = threading.Barrier(2)

    async def coordinated_get_user_by_id(user_id: uuid.UUID) -> AppUser:
        user = await original_get_user_by_id(user_id)
        if coordinate_reads.is_set() and not temp_db.conn.in_transaction:
            stale_read_barrier.wait(timeout=5)
        return user

    temp_db.get_user_by_id = coordinated_get_user_by_id
    coordinate_reads.set()

    def change_role(new_role: str) -> None:
        start_barrier.wait(timeout=5)
        try:
            asyncio.run(temp_db.update_user_role(target.id, new_role))
        finally:
            temp_db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(change_role, new_role)
            for new_role in ("admin", "root")
        ]
        for future in futures:
            future.result(timeout=10)

    coordinate_reads.clear()
    actions = sorted(
        temp_db.list_admin_actions(
            target_user_id=target.id,
            action="role_change",
        ),
        key=lambda action: action["id"],
    )
    assert len(actions) == 2

    expected_before = {"role": "user"}
    for action in actions:
        assert action["before"] == expected_before
        expected_before = action["after"]

    assert (asyncio.run(temp_db.get_user_by_id(target.id))).role == expected_before["role"]
    assert temp_db.conn.execute(
        "SELECT role FROM user_sessions WHERE user_id = ?",
        (str(target.id),),
    ).fetchall() == [(expected_before["role"],)]


def test_deletion_audit_row_survives_user_removal(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "admin@example.com", role="admin")
        target = await _create_user(temp_db, "victim@example.com", role="user")
        target_id = target.id
        admin_context = await _create_admin_context(
            temp_db,
            admin,
            client_ip="198.51.100.5",
        )

        deleted = await temp_db.admin_delete_user(
            target_id,
            admin_context=admin_context,
        )
        assert deleted is True

        # User is gone ...
        with pytest.raises(KeyError):
            await temp_db.get_user_by_id(target_id)

        # ... but the audit row (no FK cascade) survives, with snapshots intact.
        rows = temp_db.list_admin_actions(target_user_id=target_id, action="user_delete")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_user_id"] == admin.id
        assert row["target_label"] == "victim@example.com"
        assert row["before"] == {"email": "victim@example.com", "role": "user"}
        assert row["after"] is None

    asyncio.run(scenario())


def test_admin_delete_user_enforces_actor_hierarchy(temp_db: Persistence):
    async def scenario():
        root = await _create_user(temp_db, "root-delete-denied@example.com", role="root")
        admin = await _create_user(temp_db, "admin-delete-denied@example.com", role="admin")
        peer_admin = await _create_user(temp_db, "peer-delete-denied@example.com", role="admin")
        admin_context = await _create_admin_context(temp_db, admin)

        with pytest.raises(PermissionError):
            await temp_db.admin_delete_user(
                root.id,
                admin_context=admin_context,
            )

        with pytest.raises(PermissionError):
            await temp_db.admin_delete_user(
                peer_admin.id,
                admin_context=admin_context,
            )

        assert (await temp_db.get_user_by_id(root.id)).email == root.email
        assert (await temp_db.get_user_by_id(peer_admin.id)).email == peer_admin.email

    asyncio.run(scenario())


def test_self_service_deletion_is_tagged(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "selfie@example.com", role="user")
        session = await temp_db.create_session(user.id)

        deleted = await temp_db.delete_user(
            user.id,
            password=PASSWORD,
            auth_token=session.id,
        )
        assert deleted is True

        rows = temp_db.list_admin_actions(target_user_id=user.id, action="user_delete")
        assert len(rows) == 1
        row = rows[0]
        # Self-deletion: actor == target, tagged self_service.
        assert row["actor_user_id"] == user.id
        assert row["metadata"] == {"self_service": True}

    asyncio.run(scenario())


def test_outcome_failure_is_recordable(temp_db: Persistence):
    actor_id = uuid.uuid4()
    target_id = uuid.uuid4()
    temp_db.record_admin_action(
        actor_user_id=actor_id,
        actor_role="admin",
        action="role_change",
        target_user_id=target_id,
        target_label="denied@example.com",
        before={"role": "user"},
        after={"role": "root"},
        outcome="failure",
        commit=True,
    )

    rows = temp_db.list_admin_actions(target_user_id=target_id)
    assert len(rows) == 1
    assert rows[0]["outcome"] == "failure"


def test_list_admin_actions_filters_and_orders(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "root@example.com", role="root")
        a = await _create_user(temp_db, "a@example.com", role="user")
        b = await _create_user(temp_db, "b@example.com", role="user")
        admin_context = await _create_admin_context(temp_db, admin)

        await temp_db.admin_update_user_role(
            a.id,
            "admin",
            admin_context=admin_context,
        )
        await temp_db.admin_adjust_currency_balance(
            b.id,
            500,
            admin_context=admin_context,
        )

        # Filter by action.
        role_rows = temp_db.list_admin_actions(action="role_change")
        assert all(r["action"] == "role_change" for r in role_rows)
        assert any(r["target_user_id"] == a.id for r in role_rows)

        # Filter by target.
        b_rows = temp_db.list_admin_actions(target_user_id=b.id)
        assert len(b_rows) == 1
        assert b_rows[0]["action"] == "currency_adjust"

        # Filter by actor.
        actor_rows = temp_db.list_admin_actions(actor_user_id=admin.id)
        assert len(actor_rows) >= 2

        # Newest first.
        all_rows = temp_db.list_admin_actions()
        created = [r["created_at"] for r in all_rows]
        assert created == sorted(created, reverse=True)

    asyncio.run(scenario())


def test_no_secret_material_in_audit_columns(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "admin@example.com", role="admin")
        secret_pw = "Sup3rSecret-Password!"
        admin_context = await _create_admin_context(
            temp_db,
            admin,
            client_ip="203.0.113.9",
        )

        await temp_db.admin_create_user(
            email="created@example.com",
            password=secret_pw,
            role="user",
            admin_context=admin_context,
        )
        created = await temp_db.get_user_by_email("created@example.com")
        issuance = await temp_db.admin_issue_password_reset(
            created.id,
            admin_context=admin_context,
        )

        haystacks: list[str] = []
        for row in temp_db.list_admin_actions():
            for key in ("before", "after", "metadata"):
                if row[key] is not None:
                    haystacks.append(str(row[key]))
        blob = "\n".join(haystacks)

        assert secret_pw not in blob
        assert issuance.token not in blob

    asyncio.run(scenario())


def test_actorless_update_user_role_still_works(temp_db: Persistence):
    """Regression: the actor-less call contract (e.g. revalidation tests)."""

    async def scenario():
        user = await _create_user(temp_db, "noactor@example.com", role="user")

        # No actor / client_ip — must not raise; writes a null-actor audit row.
        await temp_db.update_user_role(user.id, "admin")

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.role == "admin"

        rows = temp_db.list_admin_actions(target_user_id=user.id, action="role_change")
        assert len(rows) == 1
        assert rows[0]["actor_user_id"] is None
        assert rows[0]["actor_role"] is None

    asyncio.run(scenario())


def test_currency_set_writes_thin_audit_row(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "admin@example.com", role="admin")
        target = await _create_user(temp_db, "wallet@example.com", role="user")
        admin_context = await _create_admin_context(
            temp_db,
            admin,
            client_ip="203.0.113.11",
        )

        entry = await temp_db.admin_set_currency_balance(
            target.id,
            1000,
            admin_context=admin_context,
        )

        rows = temp_db.list_admin_actions(target_user_id=target.id, action="currency_set")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_user_id"] == admin.id
        assert row["after"] == {"balance": 1000}
        assert row["metadata"] == {"ledger_id": entry.id}
        assert row["client_ip"] == "203.0.113.11"

    asyncio.run(scenario())
