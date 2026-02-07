import asyncio
import time
from pathlib import Path

import pyotp
import pytest

from app.data_models import AppUser
from app.persistence import Persistence, TwoFactorFailure, TwoFactorMethod


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

