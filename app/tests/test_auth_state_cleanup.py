import asyncio
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.config import config
from app.data_models import AppUser
from app.persistence import Persistence


PASSWORD = "VeryStrongPass!9"
FLOW_ID = "0123456789abcdef0123456789abcdef"


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


def _binding_digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _stored_pending_bindings(persistence: Persistence) -> set[str]:
    return {
        row[0]
        for row in persistence.conn.execute(
            "SELECT binding_digest FROM oauth_pending_logins"
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


def test_deletion_challenge_creation_cleans_expired_and_consumed_rows(
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
        first_session = await temp_db.create_session(first.id)
        second_session = await temp_db.create_session(second.id)
        expired = await temp_db.create_oauth_account_deletion_challenge(
            user_id=first.id,
            provider="google",
            auth_token=first_session.id,
        )
        consumed = await temp_db.create_oauth_account_deletion_challenge(
            user_id=first.id,
            provider="google",
            auth_token=first_session.id,
        )
        live_other_user = await temp_db.create_oauth_account_deletion_challenge(
            user_id=second.id,
            provider="google",
            auth_token=second_session.id,
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

        new_handoff = await temp_db.create_oauth_account_deletion_challenge(
            user_id=first.id,
            provider="google",
            auth_token=first_session.id,
        )
        stored = _stored_handoff_hashes(temp_db)

        assert temp_db._hash_one_time_token(expired) not in stored
        assert temp_db._hash_one_time_token(consumed) not in stored
        assert temp_db._hash_one_time_token(live_other_user) in stored
        assert temp_db._hash_one_time_token(new_handoff) in stored

    asyncio.run(scenario())


def test_failed_deletion_challenge_insertion_rolls_back_cleanup(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="handoff-cleanup-rollback@example.com",
            social=True,
        )
        user_session = await temp_db.create_session(user.id)
        expired = await temp_db.create_oauth_account_deletion_challenge(
            user_id=user.id,
            provider="google",
            auth_token=user_session.id,
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
            await temp_db.create_oauth_account_deletion_challenge(
                user_id=user.id,
                provider="google",
                auth_token=user_session.id,
            )

        assert expired_hash in _stored_handoff_hashes(temp_db)
        assert temp_db.conn.in_transaction is False

    asyncio.run(scenario())


def test_pending_login_creation_cleans_expired_rows_and_preserves_live(
    temp_db: Persistence,
):
    async def scenario():
        first = await _create_user(
            temp_db,
            email="pending-cleanup-first@example.com",
            social=True,
        )
        second = await _create_user(
            temp_db,
            email="pending-cleanup-second@example.com",
            social=True,
        )
        expired_digest = _binding_digest("expired-pending-login")
        live_other_digest = _binding_digest("live-other-pending-login")
        new_digest = _binding_digest("new-pending-login")

        await temp_db.create_oauth_pending_login(
            binding_digest=expired_digest,
            flow_id=FLOW_ID,
            user_id=first.id,
            provider="google",
        )
        await temp_db.create_oauth_pending_login(
            binding_digest=live_other_digest,
            flow_id=FLOW_ID,
            user_id=second.id,
            provider="google",
        )
        temp_db.conn.execute(
            "UPDATE oauth_pending_logins SET valid_until = 0 WHERE binding_digest = ?",
            (expired_digest,),
        )
        temp_db.conn.commit()

        await temp_db.create_oauth_pending_login(
            binding_digest=new_digest,
            flow_id=FLOW_ID,
            user_id=first.id,
            provider="google",
        )
        stored = _stored_pending_bindings(temp_db)

        assert expired_digest not in stored
        assert live_other_digest in stored
        assert new_digest in stored

        consumed_user = await temp_db.consume_oauth_pending_login(
            new_digest,
            FLOW_ID,
        )
        assert consumed_user.id == first.id
        assert new_digest not in _stored_pending_bindings(temp_db)

    asyncio.run(scenario())


def test_failed_pending_login_insertion_restores_cleanup_and_replacement(
    temp_db: Persistence,
):
    async def scenario():
        first = await _create_user(
            temp_db,
            email="pending-rollback-first@example.com",
            social=True,
        )
        second = await _create_user(
            temp_db,
            email="pending-rollback-second@example.com",
            social=True,
        )
        replacement_digest = _binding_digest("replacement-pending-login")
        expired_digest = _binding_digest("rollback-expired-pending-login")

        await temp_db.create_oauth_pending_login(
            binding_digest=replacement_digest,
            flow_id=FLOW_ID,
            user_id=first.id,
            provider="google",
        )
        await temp_db.create_oauth_pending_login(
            binding_digest=expired_digest,
            flow_id=FLOW_ID,
            user_id=first.id,
            provider="google",
        )
        temp_db.conn.execute(
            "UPDATE oauth_pending_logins SET valid_until = 0 WHERE binding_digest = ?",
            (expired_digest,),
        )
        temp_db.conn.execute(
            """
            CREATE TRIGGER fail_pending_login_insert_after_cleanup
            BEFORE INSERT ON oauth_pending_logins
            BEGIN
                SELECT RAISE(ABORT, 'forced pending login insertion failure');
            END
            """
        )
        temp_db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match="forced pending login"):
            await temp_db.create_oauth_pending_login(
                binding_digest=replacement_digest,
                flow_id=FLOW_ID,
                user_id=second.id,
                provider="google",
            )

        assert _stored_pending_bindings(temp_db) == {
            expired_digest,
            replacement_digest,
        }
        assert temp_db.conn.execute(
            "SELECT user_id FROM oauth_pending_logins WHERE binding_digest = ?",
            (replacement_digest,),
        ).fetchone() == (str(first.id),)
        assert temp_db.conn.in_transaction is False

    asyncio.run(scenario())
