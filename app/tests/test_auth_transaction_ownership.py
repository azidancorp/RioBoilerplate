import asyncio
import sqlite3
from pathlib import Path

import pytest

from app.data_models import AppUser
from app.persistence import Persistence
from app import persistence_auth


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "auth-transaction-ownership.db")
    try:
        yield persistence
    finally:
        persistence.close()


def _auth_snapshot(persistence: Persistence, user_id) -> tuple:
    uid = str(user_id)
    return (
        persistence.conn.execute(
            "SELECT is_verified FROM users WHERE id = ?",
            (uid,),
        ).fetchone(),
        persistence.conn.execute(
            "SELECT id, valid_until FROM user_sessions WHERE user_id = ? ORDER BY id",
            (uid,),
        ).fetchall(),
        persistence.conn.execute(
            """
            SELECT token_hash, valid_until
            FROM password_reset_tokens
            WHERE user_id = ?
            ORDER BY token_hash
            """,
            (uid,),
        ).fetchall(),
        persistence.conn.execute(
            """
            SELECT token_hash, valid_until
            FROM email_verification_tokens
            WHERE user_id = ?
            ORDER BY token_hash
            """,
            (uid,),
        ).fetchall(),
        persistence.conn.execute(
            """
            SELECT code_hash, used_at
            FROM two_factor_recovery_codes
            WHERE user_id = ?
            ORDER BY code_hash
            """,
            (uid,),
        ).fetchall(),
    )


@pytest.mark.parametrize(
    "operation",
    [
        "invalidate_session",
        "invalidate_all_sessions",
        "get_expired_reset_token",
        "clear_reset_tokens",
        "set_user_verified",
        "create_email_verification_token",
        "clear_email_verification_tokens",
        "invalidate_recovery_codes",
    ],
)
def test_auth_helpers_never_commit_a_callers_transaction(
    temp_db: Persistence,
    operation: str,
):
    async def scenario():
        user = AppUser.create_new_user_with_default_settings(
            email=f"{operation}@example.com",
            password=PASSWORD,
        )
        await temp_db._create_user_unchecked(user)
        user = await temp_db.get_user_by_id(user.id)
        session = await temp_db.create_session(user.id)
        reset_token = await temp_db.create_reset_token(user.id)
        await temp_db.create_email_verification_token(user.id)
        temp_db.set_2fa_secret(user.id, "JBSWY3DPEHPK3PXP")
        temp_db.generate_recovery_codes(user.id, count=2)

        temp_db.conn.execute(
            "UPDATE password_reset_tokens SET valid_until = 0 WHERE user_id = ?",
            (str(user.id),),
        )
        temp_db.conn.commit()
        before = _auth_snapshot(temp_db, user.id)

        temp_db.conn.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            ("caller-pending", str(user.id)),
        )

        try:
            with pytest.raises(RuntimeError, match="existing transaction"):
                if operation == "invalidate_session":
                    await temp_db.invalidate_session(session.id)
                elif operation == "invalidate_all_sessions":
                    await temp_db.invalidate_all_sessions(user.id)
                elif operation == "get_expired_reset_token":
                    await temp_db.get_user_by_reset_token(reset_token.token)
                elif operation == "clear_reset_tokens":
                    await temp_db.clear_reset_tokens(user.id)
                elif operation == "set_user_verified":
                    await temp_db.set_user_verified(user.id)
                elif operation == "create_email_verification_token":
                    await temp_db.create_email_verification_token(user.id)
                elif operation == "clear_email_verification_tokens":
                    await temp_db.clear_email_verification_tokens(user.id)
                else:
                    persistence_auth.invalidate_recovery_codes(temp_db, user.id)

            assert temp_db.conn.in_transaction is True
            assert temp_db.conn.execute(
                "SELECT username FROM users WHERE id = ?",
                (str(user.id),),
            ).fetchone() == ("caller-pending",)
            assert _auth_snapshot(temp_db, user.id) == before

            with sqlite3.connect(temp_db.db_path) as verifier:
                assert verifier.execute(
                    "SELECT username FROM users WHERE id = ?",
                    (str(user.id),),
                ).fetchone() == (None,)
        finally:
            temp_db.conn.rollback()

        assert _auth_snapshot(temp_db, user.id) == before

    asyncio.run(scenario())


def test_uncommitted_recovery_code_cleanup_requires_a_transaction(
    temp_db: Persistence,
):
    user = AppUser.create_new_user_with_default_settings(
        email="recovery-contract@example.com",
        password=PASSWORD,
    )
    asyncio.run(temp_db._create_user_unchecked(user))

    with pytest.raises(RuntimeError, match="requires an open transaction"):
        persistence_auth.invalidate_recovery_codes(
            temp_db,
            user.id,
            commit=False,
        )
