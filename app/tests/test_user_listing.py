import asyncio
import argparse
from pathlib import Path

import pytest

from app.data_models import AppUser
from app.persistence import Persistence
from app.scripts import currency_admin


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "user-listing.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_user(persistence: Persistence, email: str) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password="VeryStrongPass!9",
    )
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def test_user_listing_pages_are_stable_and_non_overlapping(temp_db: Persistence):
    async def scenario():
        users = [
            await _create_user(temp_db, f"paged-user-{index}@example.com")
            for index in range(5)
        ]
        temp_db.conn.execute("UPDATE users SET created_at = 1234567890")
        temp_db.conn.commit()

        first_page = await temp_db.list_users(limit=2, offset=0)
        second_page = await temp_db.list_users(limit=2, offset=2)
        final_page = await temp_db.list_users(limit=2, offset=4)
        expected_ids = sorted((str(user.id) for user in users), reverse=True)

        listed_ids = [
            str(user.id)
            for user in (*first_page, *second_page, *final_page)
        ]
        assert listed_ids == expected_ids
        assert len(set(listed_ids)) == len(users)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("limit", "offset", "message"),
    [
        (0, 0, "at least 1"),
        (-1, 0, "at least 1"),
        (1, -1, "cannot be negative"),
        (None, 1, "requires a limit"),
    ],
)
def test_user_listing_rejects_invalid_page_bounds(
    temp_db: Persistence,
    limit: int | None,
    offset: int,
    message: str,
):
    async def scenario():
        with pytest.raises(ValueError, match=message):
            await temp_db.list_users(limit=limit, offset=offset)

    asyncio.run(scenario())


def test_currency_list_cli_passes_its_limit_to_persistence(
    monkeypatch: pytest.MonkeyPatch,
):
    captured_limits: list[int | None] = []

    class FakePersistence:
        async def list_users(self, *, limit=None):
            captured_limits.append(limit)
            return []

        def close(self) -> None:
            pass

    monkeypatch.setattr(currency_admin, "Persistence", FakePersistence)

    asyncio.run(currency_admin.cmd_list(argparse.Namespace(limit=7)))

    assert captured_limits == [7]
