import asyncio
import concurrent.futures
import sqlite3
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest

from app.config import config
from app.data_models import AppUser
from app.persistence import AdminMutationContext, Persistence


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    original_balance = config.PRIMARY_CURRENCY_INITIAL_BALANCE
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0
    persistence = Persistence(db_path=tmp_path / "currency-idempotency.db")
    try:
        yield persistence
    finally:
        persistence.close()
        config.PRIMARY_CURRENCY_INITIAL_BALANCE = original_balance


async def _create_user(
    persistence: Persistence,
    *,
    email: str,
    role: str,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password=PASSWORD,
    )
    user.role = role
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def test_concurrent_same_key_currency_requests_apply_once(temp_db: Persistence):
    async def setup():
        actor = await _create_user(
            temp_db,
            email="concurrent-idempotency-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            email="concurrent-idempotency-target@example.com",
            role="user",
        )
        session = await temp_db.create_session(actor.id)
        return actor, target, session.id

    actor, target, auth_token = asyncio.run(setup())
    key = uuid4()
    fingerprint = "a" * 64
    start = Barrier(2)

    def adjust_once():
        worker = Persistence(db_path=temp_db.db_path)
        try:
            start.wait(timeout=10)
            return asyncio.run(
                worker.admin_adjust_currency_balance(
                    target.id,
                    25,
                    admin_context=AdminMutationContext(auth_token=auth_token),
                    reason="concurrent retry",
                    idempotency_key=key,
                    request_fingerprint=fingerprint,
                )
            )
        finally:
            worker.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(adjust_once) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]

    assert results[0].id == results[1].id
    assert results[0].balance_after == 25
    assert asyncio.run(
        temp_db.get_user_by_id(target.id)
    ).primary_currency_balance == 25
    assert temp_db.conn.execute(
        "SELECT COUNT(*) FROM user_currency_ledger WHERE user_id = ?",
        (str(target.id),),
    ).fetchone()[0] == 1
    assert temp_db.conn.execute(
        """
        SELECT COUNT(*)
        FROM admin_audit_log
        WHERE actor_user_id = ? AND action = 'currency_adjust'
        """,
        (str(actor.id),),
    ).fetchone()[0] == 1
    assert temp_db.conn.execute(
        "SELECT COUNT(*) FROM currency_mutation_idempotency",
    ).fetchone()[0] == 1


def test_failed_idempotency_record_rolls_back_entire_currency_mutation(
    temp_db: Persistence,
):
    async def scenario():
        actor = await _create_user(
            temp_db,
            email="idempotency-rollback-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            email="idempotency-rollback-target@example.com",
            role="user",
        )
        session = await temp_db.create_session(actor.id)
        context = AdminMutationContext(auth_token=session.id)
        key = uuid4()
        fingerprint = "b" * 64

        temp_db.conn.execute(
            """
            CREATE TRIGGER fail_currency_idempotency_insert
            BEFORE INSERT ON currency_mutation_idempotency
            BEGIN
                SELECT RAISE(ABORT, 'forced idempotency insertion failure');
            END
            """
        )
        temp_db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match="forced idempotency"):
            await temp_db.admin_adjust_currency_balance(
                target.id,
                25,
                admin_context=context,
                reason="must fully roll back",
                idempotency_key=key,
                request_fingerprint=fingerprint,
            )

        assert (await temp_db.get_user_by_id(target.id)).primary_currency_balance == 0
        assert temp_db.conn.execute(
            "SELECT COUNT(*) FROM user_currency_ledger WHERE user_id = ?",
            (str(target.id),),
        ).fetchone()[0] == 0
        assert temp_db.conn.execute(
            "SELECT COUNT(*) FROM admin_audit_log WHERE target_user_id = ?",
            (str(target.id),),
        ).fetchone()[0] == 0
        assert temp_db.conn.execute(
            "SELECT COUNT(*) FROM currency_mutation_idempotency",
        ).fetchone()[0] == 0

        temp_db.conn.execute("DROP TRIGGER fail_currency_idempotency_insert")
        temp_db.conn.commit()
        retry = await temp_db.admin_adjust_currency_balance(
            target.id,
            25,
            admin_context=context,
            reason="must fully roll back",
            idempotency_key=key,
            request_fingerprint=fingerprint,
        )
        assert retry.balance_after == 25

    asyncio.run(scenario())
