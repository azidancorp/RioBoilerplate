import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.config import config
from app.data_models import AppUser
from app.persistence import Persistence


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "auth-state-cleanup.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_user(
    persistence: Persistence,
    *,
    email: str,
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
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def _stored_session_hashes(persistence: Persistence) -> set[str]:
    return {
        row[0]
        for row in persistence.conn.execute(
            "SELECT id FROM user_sessions"
        ).fetchall()
    }


def _stored_handoff_hashes(persistence: Persistence) -> set[str]:
    return {
        row[0]
        for row in persistence.conn.execute(
            "SELECT token_hash FROM oauth_login_handoffs"
        ).fetchall()
    }


def test_session_creation_cleans_sliding_and_absolute_expiry_only(
    temp_db: Persistence,
    monkeypatch,
):
    async def scenario():
        monkeypatch.setattr(config, "SESSION_ABSOLUTE_MAX_DAYS", 1)
        first = await _create_user(
            temp_db,
            email="session-cleanup-first@example.com",
        )
        second = await _create_user(
            temp_db,
            email="session-cleanup-second@example.com",
        )
        expired = await temp_db.create_session(first.id)
        absolute_expired = await temp_db.create_session(first.id)
        live_other_user = await temp_db.create_session(second.id)
        now = datetime.now(timezone.utc)
        temp_db.conn.execute(
            "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
            (temp_db._hash_one_time_token(expired.id),),
        )
        temp_db.conn.execute(
            """
            UPDATE user_sessions
            SET created_at = ?, valid_until = ?
            WHERE id = ?
            """,
            (
                (now - timedelta(days=2)).timestamp(),
                (now + timedelta(days=1)).timestamp(),
                temp_db._hash_one_time_token(absolute_expired.id),
            ),
        )
        temp_db.conn.commit()

        new_session = await temp_db.create_session(second.id)
        stored = _stored_session_hashes(temp_db)

        assert temp_db._hash_one_time_token(expired.id) not in stored
        assert temp_db._hash_one_time_token(absolute_expired.id) not in stored
        assert temp_db._hash_one_time_token(live_other_user.id) in stored
        assert temp_db._hash_one_time_token(new_session.id) in stored

    asyncio.run(scenario())


def test_failed_session_insertion_rolls_back_cleanup(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="session-cleanup-rollback@example.com",
        )
        expired = await temp_db.create_session(user.id)
        expired_hash = temp_db._hash_one_time_token(expired.id)
        temp_db.conn.execute(
            "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
            (expired_hash,),
        )
        temp_db.conn.execute(
            """
            CREATE TRIGGER fail_session_insert_after_cleanup
            BEFORE INSERT ON user_sessions
            BEGIN
                SELECT RAISE(ABORT, 'forced session insertion failure');
            END
            """
        )
        temp_db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match="forced session"):
            await temp_db.create_session(user.id)

        assert expired_hash in _stored_session_hashes(temp_db)
        assert temp_db.conn.in_transaction is False

    asyncio.run(scenario())


def test_oauth_creation_cleans_expired_and_consumed_rows_and_preserves_live(
    temp_db: Persistence,
):
    async def scenario():
        first = await _create_user(
            temp_db,
            email="handoff-cleanup-first@example.com",
            social=True,
        )
        second = await _create_user(
            temp_db,
            email="handoff-cleanup-second@example.com",
            social=True,
        )
        expired = await temp_db.create_oauth_handoff(
            user_id=first.id,
            provider="google",
        )
        consumed = await temp_db.create_oauth_handoff(
            user_id=first.id,
            provider="google",
        )
        live_other_user = await temp_db.create_oauth_handoff(
            user_id=second.id,
            provider="google",
        )
        temp_db.conn.execute(
            "UPDATE oauth_login_handoffs SET valid_until = 0 WHERE token_hash = ?",
            (temp_db._hash_one_time_token(expired),),
        )
        temp_db.conn.execute(
            "UPDATE oauth_login_handoffs SET consumed_at = 1 WHERE token_hash = ?",
            (temp_db._hash_one_time_token(consumed),),
        )
        temp_db.conn.commit()

        new_handoff = await temp_db.create_oauth_handoff(
            user_id=first.id,
            provider="google",
        )
        stored = _stored_handoff_hashes(temp_db)

        assert temp_db._hash_one_time_token(expired) not in stored
        assert temp_db._hash_one_time_token(consumed) not in stored
        assert temp_db._hash_one_time_token(live_other_user) in stored
        assert temp_db._hash_one_time_token(new_handoff) in stored

        consumed_user = await temp_db.consume_oauth_handoff(new_handoff)
        assert consumed_user.id == first.id
        assert temp_db._hash_one_time_token(new_handoff) not in _stored_handoff_hashes(
            temp_db
        )

    asyncio.run(scenario())


def test_failed_handoff_insertion_rolls_back_cleanup(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="handoff-cleanup-rollback@example.com",
            social=True,
        )
        expired = await temp_db.create_oauth_handoff(
            user_id=user.id,
            provider="google",
        )
        expired_hash = temp_db._hash_one_time_token(expired)
        temp_db.conn.execute(
            "UPDATE oauth_login_handoffs SET valid_until = 0 WHERE token_hash = ?",
            (expired_hash,),
        )
        temp_db.conn.execute(
            """
            CREATE TRIGGER fail_handoff_insert_after_cleanup
            BEFORE INSERT ON oauth_login_handoffs
            BEGIN
                SELECT RAISE(ABORT, 'forced handoff insertion failure');
            END
            """
        )
        temp_db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match="forced handoff"):
            await temp_db.create_oauth_handoff(
                user_id=user.id,
                provider="google",
            )

        assert expired_hash in _stored_handoff_hashes(temp_db)
        assert temp_db.conn.in_transaction is False

    asyncio.run(scenario())
