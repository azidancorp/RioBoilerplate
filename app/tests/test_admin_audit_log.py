"""Tests for the admin action audit log (persistence_audit + instrumentation).

Covers attribution (who/what/whom/when), atomicity with the mutation, survival
across user deletion (no FK cascade), filtering/ordering, secret hygiene, and the
backward-compatible actor-less call paths.
"""

import asyncio
import uuid
from pathlib import Path

import pytest

from app.data_models import AppUser
from app.persistence import Persistence


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
    await persistence.create_user(user)
    # create_user may promote the first user to root; force the requested role.
    if user.role != role:
        cursor = persistence._get_cursor()
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role, str(user.id)))
        persistence.conn.commit()
    return await persistence.get_user_by_id(user.id)


def test_role_change_writes_single_row_atomically(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "admin@example.com", role="admin")
        target = await _create_user(temp_db, "target@example.com", role="user")

        await temp_db.update_user_role(
            target.id, "admin", actor=admin, client_ip="203.0.113.7"
        )

        # State changed ...
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == "admin"

        # ... and exactly one audit row describes it.
        rows = temp_db.list_admin_actions(target_user_id=target.id, action="role_change")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_user_id"] == admin.id
        assert row["actor_role"] == "admin"
        assert row["target_user_id"] == target.id
        assert row["target_label"] == "target@example.com"
        assert row["before"] == {"role": "user"}
        assert row["after"] == {"role": "admin"}
        assert row["client_ip"] == "203.0.113.7"
        assert row["outcome"] == "success"

    asyncio.run(scenario())


def test_deletion_audit_row_survives_user_removal(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "admin@example.com", role="admin")
        target = await _create_user(temp_db, "victim@example.com", role="user")
        target_id = target.id

        deleted = await temp_db.admin_delete_user(
            target_id,
            actor=admin,
            client_ip="198.51.100.5",
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

        with pytest.raises(PermissionError):
            await temp_db.admin_delete_user(root.id, actor=admin)

        with pytest.raises(PermissionError):
            await temp_db.admin_delete_user(peer_admin.id, actor=admin)

        assert (await temp_db.get_user_by_id(root.id)).email == root.email
        assert (await temp_db.get_user_by_id(peer_admin.id)).email == peer_admin.email

    asyncio.run(scenario())


def test_self_service_deletion_is_tagged(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "selfie@example.com", role="user")

        deleted = await temp_db.delete_user(user.id, password=PASSWORD)
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
        admin = await _create_user(temp_db, "admin@example.com", role="admin")
        a = await _create_user(temp_db, "a@example.com", role="user")
        b = await _create_user(temp_db, "b@example.com", role="user")

        await temp_db.update_user_role(a.id, "admin", actor=admin)
        await temp_db.adjust_currency_balance(
            b.id, 500, actor_user_id=admin.id, actor_role=admin.role
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

        await temp_db.admin_create_user(
            email="created@example.com",
            password=secret_pw,
            role="user",
            actor=admin,
            client_ip="203.0.113.9",
        )
        created = await temp_db.get_user_by_email("created@example.com")
        token = await temp_db.admin_issue_password_reset(created.id, actor=admin)

        haystacks: list[str] = []
        for row in temp_db.list_admin_actions():
            for key in ("before", "after", "metadata"):
                if row[key] is not None:
                    haystacks.append(str(row[key]))
        blob = "\n".join(haystacks)

        assert secret_pw not in blob
        assert token.token not in blob

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

        entry = await temp_db.set_currency_balance(
            target.id,
            1000,
            actor_user_id=admin.id,
            actor_role=admin.role,
            client_ip="203.0.113.11",
        )

        rows = temp_db.list_admin_actions(target_user_id=target.id, action="currency_set")
        assert len(rows) == 1
        row = rows[0]
        assert row["actor_user_id"] == admin.id
        assert row["after"] == {"balance": 1000}
        assert row["metadata"] == {"ledger_id": entry.id}
        assert row["client_ip"] == "203.0.113.11"

    asyncio.run(scenario())
