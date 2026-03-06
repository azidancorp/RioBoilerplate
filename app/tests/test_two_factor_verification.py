import asyncio
import sqlite3
import time
from pathlib import Path

import pyotp
import pytest

from app.data_models import AppUser
from app.persistence import Persistence
from app.persistence_auth import TwoFactorFailure, TwoFactorMethod


@pytest.fixture
def temp_db(tmp_path: Path):
    db_path = tmp_path / "test.db"
    persistence = Persistence(db_path=db_path)
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_user(persistence: Persistence, email: str, password: str = "password") -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    await persistence.create_user(user)
    return await persistence.get_user_by_id(user.id)


def test_verify_two_factor_not_required_when_disabled(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "no2fa@example.com")
        result = temp_db.verify_two_factor_challenge(user.id, None)
        assert result.ok is True
        assert result.method == TwoFactorMethod.NOT_REQUIRED

    asyncio.run(scenario())


def test_verify_two_factor_missing_code_when_enabled(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "missing@example.com")
        temp_db.set_2fa_secret(user.id, pyotp.random_base32())

        result = temp_db.verify_two_factor_challenge(user.id, "")
        assert result.ok is False
        assert result.failure == TwoFactorFailure.MISSING_CODE

    asyncio.run(scenario())


def test_verify_two_factor_accepts_hyphenated_totp(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "totp@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)

        # Avoid rare flake at 30s boundary by retrying briefly.
        totp = pyotp.TOTP(secret)
        for _ in range(3):
            token = totp.now()
            token_hyphenated = f"{token[:3]}-{token[3:]}"
            result = temp_db.verify_two_factor_challenge(user.id, token_hyphenated)
            if result.ok:
                assert result.method == TwoFactorMethod.TOTP
                return
            time.sleep(1)

        pytest.fail("Expected hyphenated TOTP to verify successfully")

    asyncio.run(scenario())


def test_verify_two_factor_consumes_recovery_code(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "recovery@example.com")
        temp_db.set_2fa_secret(user.id, pyotp.random_base32())
        codes = temp_db.generate_recovery_codes(user.id, count=3)
        recovery_code = codes[0]

        ok1 = temp_db.verify_two_factor_challenge(user.id, recovery_code)
        assert ok1.ok is True
        assert ok1.method == TwoFactorMethod.RECOVERY_CODE
        assert ok1.used_recovery_code is True

        ok2 = temp_db.verify_two_factor_challenge(user.id, recovery_code)
        assert ok2.ok is False
        assert ok2.failure == TwoFactorFailure.INVALID_CODE

    asyncio.run(scenario())


def test_verify_two_factor_rejects_invalid_format(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "format@example.com")
        temp_db.set_2fa_secret(user.id, pyotp.random_base32())

        result = temp_db.verify_two_factor_challenge(user.id, "123!456")
        assert result.ok is False
        assert result.failure == TwoFactorFailure.INVALID_FORMAT

    asyncio.run(scenario())


def test_delete_user_requires_two_factor_when_enabled(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "delete@example.com", password="p@ssw0rd")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        totp = pyotp.TOTP(secret)

        assert await temp_db.delete_user(user.id, password="p@ssw0rd", two_factor_code=None) is False
        assert await temp_db.delete_user(user.id, password="p@ssw0rd", two_factor_code="000000") is False

        # Avoid rare flake at 30s boundary by retrying briefly.
        for _ in range(3):
            token = totp.now()
            if await temp_db.delete_user(user.id, password="p@ssw0rd", two_factor_code=token):
                break
            time.sleep(1)
        else:
            pytest.fail("Expected delete_user to succeed with valid TOTP")

        with pytest.raises(KeyError):
            await temp_db.get_user_by_id(user.id)

    asyncio.run(scenario())


def test_legacy_recovery_code_table_is_reset_to_current_schema(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                username TEXT,
                created_at REAL NOT NULL,
                password_hash BLOB,
                password_salt BLOB,
                auth_provider TEXT NOT NULL DEFAULT 'password',
                auth_provider_id TEXT,
                role TEXT NOT NULL,
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                two_factor_secret TEXT,
                referral_code TEXT DEFAULT '',
                email_notifications_enabled BOOLEAN NOT NULL DEFAULT 1,
                sms_notifications_enabled BOOLEAN NOT NULL DEFAULT 0,
                primary_currency_balance INTEGER NOT NULL DEFAULT 0,
                primary_currency_updated_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE two_factor_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                code_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at REAL NOT NULL,
                used_at REAL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

    persistence = Persistence(db_path=db_path)
    try:
        cursor = persistence._get_cursor()
        cursor.execute("PRAGMA table_info(two_factor_recovery_codes)")
        columns = {row[1] for row in cursor.fetchall()}
        assert "salt" not in columns
        assert {"code_hash", "valid_until", "used_at"}.issubset(columns)
    finally:
        persistence.close()
