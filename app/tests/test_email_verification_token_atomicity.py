import asyncio
import concurrent.futures
import sqlite3
from pathlib import Path
from threading import Barrier

import pytest

from app.data_models import AppUser
from app.persistence import Persistence


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "verification-token-atomicity.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_user(persistence: Persistence, email: str) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password=PASSWORD,
    )
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def _stored_token_hashes(persistence: Persistence, user_id) -> list[str]:
    return [
        row[0]
        for row in persistence.conn.execute(
            """
            SELECT token_hash
            FROM email_verification_tokens
            WHERE user_id = ?
            ORDER BY token_hash
            """,
            (str(user_id),),
        ).fetchall()
    ]


def test_concurrent_verification_issuers_leave_one_usable_token(
    temp_db: Persistence,
):
    user = asyncio.run(
        _create_user(temp_db, "concurrent-verification@example.com")
    )
    start = Barrier(2)

    def issue_token():
        worker = Persistence(db_path=temp_db.db_path)
        try:
            start.wait(timeout=10)
            return asyncio.run(worker.create_email_verification_token(user.id))
        finally:
            worker.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(issue_token) for _ in range(2)]
        issued = [future.result(timeout=20) for future in futures]

    stored_hashes = _stored_token_hashes(temp_db, user.id)
    assert len(issued) == 2
    assert len(stored_hashes) == 1

    matching = [
        token
        for token in issued
        if temp_db._hash_one_time_token(token.token) == stored_hashes[0]
    ]
    stale = [token for token in issued if token not in matching]
    assert len(matching) == 1
    assert len(stale) == 1

    async def consume_results():
        with pytest.raises(KeyError, match="Invalid verification token"):
            await temp_db.consume_email_verification_token(stale[0].token)
        verified = await temp_db.consume_email_verification_token(matching[0].token)
        assert verified.id == user.id
        assert verified.is_verified is True

    asyncio.run(consume_results())


def test_failed_verification_replacement_restores_previous_token(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(
            temp_db,
            "verification-replacement-rollback@example.com",
        )
        previous = await temp_db.create_email_verification_token(user.id)
        previous_hashes = _stored_token_hashes(temp_db, user.id)
        assert previous_hashes == [
            temp_db._hash_one_time_token(previous.token)
        ]

        temp_db.conn.execute(
            """
            CREATE TRIGGER fail_verification_token_insert
            BEFORE INSERT ON email_verification_tokens
            BEGIN
                SELECT RAISE(ABORT, 'forced verification insert failure');
            END
            """
        )
        temp_db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match="forced verification"):
            await temp_db.create_email_verification_token(user.id)

        assert temp_db.conn.in_transaction is False
        assert _stored_token_hashes(temp_db, user.id) == previous_hashes

        temp_db.conn.execute("DROP TRIGGER fail_verification_token_insert")
        temp_db.conn.commit()
        verified = await temp_db.consume_email_verification_token(previous.token)
        assert verified.id == user.id

    asyncio.run(scenario())
