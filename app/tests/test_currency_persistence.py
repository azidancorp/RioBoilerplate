import asyncio
from pathlib import Path

import pytest

from app.config import config
from app.data_models import AppUser
from app.persistence import Persistence


@pytest.fixture
def temp_db(tmp_path: Path):
    db_path = tmp_path / "test.db"
    persistence = Persistence(db_path=db_path)
    try:
        yield persistence
    finally:
        persistence.close()


@pytest.fixture(autouse=True)
def reset_currency_config():
    original = {
        "PRIMARY_CURRENCY_INITIAL_BALANCE": config.PRIMARY_CURRENCY_INITIAL_BALANCE,
        "PRIMARY_CURRENCY_ALLOW_NEGATIVE": config.PRIMARY_CURRENCY_ALLOW_NEGATIVE,
    }
    yield
    for key, value in original.items():
        setattr(config, key, value)


async def _create_user(persistence: Persistence, email: str, password: str = "password") -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    await persistence.create_user(user)
    return await persistence.get_user_by_id(user.id)


def test_create_user_honors_initial_balance(temp_db: Persistence):
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 250

    async def scenario():
        user = await _create_user(temp_db, "a@example.com")
        assert user.primary_currency_balance == 250

    asyncio.run(scenario())


def test_adjust_currency_balance_records_ledger(temp_db: Persistence):
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "b@example.com")
        entry = await temp_db.adjust_currency_balance(
            user.id,
            delta_minor=150,
            reason="signup bonus",
            metadata={"source": "test"},
            actor_user_id=None,
        )
        updated = await temp_db.get_user_by_id(user.id)
        assert updated.primary_currency_balance == 150
        assert entry.delta == 150
        ledger = await temp_db.list_currency_ledger(user.id)
        assert ledger[0].reason == "signup bonus"

    asyncio.run(scenario())


def test_disallow_negative_balance(temp_db: Persistence):
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0
    config.PRIMARY_CURRENCY_ALLOW_NEGATIVE = False

    async def scenario():
        user = await _create_user(temp_db, "c@example.com")
        with pytest.raises(ValueError):
            await temp_db.adjust_currency_balance(
                user.id,
                delta_minor=-10,
                reason="test",
            )

    asyncio.run(scenario())
