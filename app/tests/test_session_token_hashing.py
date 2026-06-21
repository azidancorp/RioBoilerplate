"""Regression tests: session bearer tokens must be stored hashed at rest.

The session token returned to the client (``UserSession.id`` / ``UserSettings.auth_token``)
is the raw value, but ``user_sessions.id`` must hold only its SHA-256 hash, mirroring how
every other secret in ``persistence_auth`` is stored (reset/email/recovery tokens).
"""

import asyncio
from pathlib import Path

import pytest

from app.data_models import AppUser
from app.persistence import Persistence


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "session-hashing.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_session(persistence: Persistence):
    user = AppUser.create_new_user_with_default_settings(
        email="root@example.com",
        password="password",
        username="root",
    )
    await persistence.create_user(user)
    user = await persistence.get_user_by_id(user.id)
    session = await persistence.create_session(user.id)
    return user, session


def test_session_tokens_are_hashed_at_rest(temp_db: Persistence):
    async def scenario():
        _, session = await _create_session(temp_db)
        token = session.id  # raw token handed to the client
        token_hash = temp_db._hash_one_time_token(token)

        # The token must never equal its own stored hash (otherwise the test is vacuous).
        assert token != token_hash

        cursor = temp_db._get_cursor()

        # Row exists under the HASH...
        cursor.execute("SELECT 1 FROM user_sessions WHERE id = ?", (token_hash,))
        assert cursor.fetchone() is not None

        # ...and NOT under the raw token (no cleartext token at rest).
        cursor.execute("SELECT 1 FROM user_sessions WHERE id = ?", (token,))
        assert cursor.fetchone() is None

    asyncio.run(scenario())


def test_lookup_by_raw_token_succeeds_and_returns_raw_id(temp_db: Persistence):
    async def scenario():
        _, session = await _create_session(temp_db)
        token = session.id

        fetched = await temp_db.get_session_by_auth_token(token)
        assert fetched.id == token  # raw token round-trips, not the stored hash

        revalidated, _ = temp_db.get_valid_session_by_auth_token(token)
        assert revalidated.id == token

    asyncio.run(scenario())


def test_lookup_by_stored_hash_is_rejected(temp_db: Persistence):
    async def scenario():
        _, session = await _create_session(temp_db)
        token_hash = temp_db._hash_one_time_token(session.id)

        # A client never presents the hash; supplying it must not authenticate.
        with pytest.raises(KeyError):
            await temp_db.get_session_by_auth_token(token_hash)

        with pytest.raises(KeyError):
            temp_db.get_valid_session_by_auth_token(token_hash)

    asyncio.run(scenario())
