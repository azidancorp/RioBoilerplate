import asyncio
import concurrent.futures
import sqlite3
from pathlib import Path
from threading import Event

import pytest

from app import persistence_social
from app.data_models import AppUser
from app.persistence import AdminMutationContext, Persistence


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "oauth-handoff-atomicity.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_user(
    persistence: Persistence,
    *,
    email: str,
    role: str = "user",
    social: bool = False,
) -> AppUser:
    if social:
        user = AppUser.create_social_user(
            email=email,
            provider="google",
            provider_user_id=f"sub-{email}",
        )
    else:
        user = AppUser.create_new_user_with_default_settings(
            email=email,
            password=PASSWORD,
        )
    user.role = role
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def _handoff_count(persistence: Persistence, user_id) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM oauth_login_handoffs WHERE user_id = ?",
        (str(user_id),),
    ).fetchone()[0]


def test_deactivation_committing_first_blocks_stale_handoff_creation(
    temp_db: Persistence,
    monkeypatch,
):
    target = asyncio.run(
        _create_user(
            temp_db,
            email="oauth-ordering-target@example.com",
            social=True,
        )
    )
    creation_reached_transaction = Event()
    original_get_connection = persistence_social._get_connection

    def signal_transaction_boundary(persistence):
        conn = original_get_connection(persistence)
        creation_reached_transaction.set()
        return conn

    monkeypatch.setattr(
        persistence_social,
        "_get_connection",
        signal_transaction_boundary,
    )

    blocker = sqlite3.connect(temp_db.db_path, timeout=30.0)
    blocker.execute("PRAGMA foreign_keys = ON")
    blocker.execute("BEGIN IMMEDIATE")
    blocker.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (str(target.id),),
    )

    def create_handoff():
        worker = Persistence(db_path=temp_db.db_path)
        try:
            return asyncio.run(
                worker.create_oauth_handoff(
                    user_id=target.id,
                    provider="google",
                )
            )
        finally:
            worker.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(create_handoff)
            assert creation_reached_transaction.wait(timeout=10)
            blocker.commit()
            with pytest.raises(ValueError, match="inactive"):
                future.result(timeout=20)
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()

    assert asyncio.run(temp_db.get_user_by_id(target.id)).is_active is False
    assert _handoff_count(temp_db, target.id) == 0


def test_creation_committing_first_is_followed_by_deactivation_cleanup(
    temp_db: Persistence,
):
    async def scenario():
        root = await _create_user(
            temp_db,
            email="oauth-ordering-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            email="oauth-ordering-social@example.com",
            social=True,
        )
        root_session = await temp_db.create_session(root.id)
        token = await temp_db.create_oauth_handoff(
            user_id=target.id,
            provider="google",
        )
        assert _handoff_count(temp_db, target.id) == 1

        await temp_db.admin_set_user_active(
            target.id,
            False,
            admin_context=AdminMutationContext(auth_token=root_session.id),
        )

        assert _handoff_count(temp_db, target.id) == 0
        with pytest.raises(KeyError):
            await temp_db.consume_oauth_handoff(token)

    asyncio.run(scenario())


def test_oauth_handoff_helpers_preserve_caller_owned_transactions(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="oauth-transaction-owner@example.com",
            social=True,
        )
        token = await temp_db.create_oauth_handoff(
            user_id=user.id,
            provider="google",
        )
        before = _handoff_count(temp_db, user.id)

        for operation in ("create", "consume"):
            temp_db.conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (f"pending-{operation}", str(user.id)),
            )
            try:
                with pytest.raises(RuntimeError, match="existing transaction"):
                    if operation == "create":
                        await temp_db.create_oauth_handoff(
                            user_id=user.id,
                            provider="google",
                        )
                    else:
                        await temp_db.consume_oauth_handoff(token)

                assert temp_db.conn.in_transaction is True
                assert _handoff_count(temp_db, user.id) == before
                assert temp_db.conn.execute(
                    """
                    SELECT consumed_at
                    FROM oauth_login_handoffs
                    WHERE token_hash = ?
                    """,
                    (temp_db._hash_one_time_token(token),),
                ).fetchone() == (None,)
                with sqlite3.connect(temp_db.db_path) as verifier:
                    assert verifier.execute(
                        "SELECT username FROM users WHERE id = ?",
                        (str(user.id),),
                    ).fetchone() == (None,)
            finally:
                temp_db.conn.rollback()

    asyncio.run(scenario())


def test_oauth_handoff_rejects_invalid_lifetime(
    temp_db: Persistence,
):
    async def scenario():
        social_user = await _create_user(
            temp_db,
            email="oauth-invalid-lifetime@example.com",
            social=True,
        )

        with pytest.raises(ValueError, match="must be positive"):
            await temp_db.create_oauth_handoff(
                user_id=social_user.id,
                provider="google",
                ttl_minutes=0,
            )

        assert _handoff_count(temp_db, social_user.id) == 0

    asyncio.run(scenario())
