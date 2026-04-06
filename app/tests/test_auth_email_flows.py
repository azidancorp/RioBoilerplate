import asyncio
from collections import defaultdict
from pathlib import Path

import pytest

from app.data_models import AppUser
from app.pages.login import LoginPage
from app.persistence import Persistence


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


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeUrl:
    def __init__(self, query: dict[str, str]):
        self.query = query


class _FakeSession:
    def __init__(self, persistence: Persistence, query: dict[str, str]):
        self.active_page_url = _FakeUrl(query)
        self._persistence = persistence
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()

    def __getitem__(self, key):
        if key is Persistence:
            return self._persistence
        raise KeyError(key)

    def _register_dirty_component(self, component) -> None:
        pass


def test_email_verification_token_marks_user_verified(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "verify-flow@example.com")
        assert user.is_verified is False

        token = await temp_db.create_email_verification_token(user.id)
        assert len(token.token) >= 32

        token_hash = temp_db._hash_one_time_token(token.token)
        cursor = temp_db._get_cursor()
        cursor.execute(
            "SELECT 1 FROM email_verification_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        assert cursor.fetchone() is not None

        cursor.execute(
            "SELECT 1 FROM email_verification_tokens WHERE token_hash = ?",
            (token.token,),
        )
        assert cursor.fetchone() is None

        verified_user = await temp_db.consume_email_verification_token(token.token)
        assert verified_user.id == user.id
        assert verified_user.is_verified is True

        with pytest.raises(KeyError):
            await temp_db.consume_email_verification_token(token.token)

    asyncio.run(scenario())


def test_password_reset_token_is_hashed_and_single_use(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "reset-flow@example.com")

        reset_token = await temp_db.create_reset_token(user.id)
        assert len(reset_token.token) >= 32

        token_hash = temp_db._hash_one_time_token(reset_token.token)
        cursor = temp_db._get_cursor()
        cursor.execute(
            "SELECT 1 FROM password_reset_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        assert cursor.fetchone() is not None

        cursor.execute(
            "SELECT 1 FROM password_reset_tokens WHERE token_hash = ?",
            (reset_token.token,),
        )
        assert cursor.fetchone() is None

        owner = await temp_db.get_user_by_reset_token(reset_token.token)
        assert owner.id == user.id

        assert await temp_db.consume_reset_token(reset_token.token, user.id) is True
        assert await temp_db.consume_reset_token(reset_token.token, user.id) is False

    asyncio.run(scenario())


def test_expired_verification_token_is_rejected(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "expired-token@example.com")
        token = await temp_db.create_email_verification_token(user.id)

        token_hash = temp_db._hash_one_time_token(token.token)
        cursor = temp_db._get_cursor()
        cursor.execute(
            "UPDATE email_verification_tokens SET valid_until = 0 WHERE token_hash = ?",
            (token_hash,),
        )
        temp_db.conn.commit()

        with pytest.raises(KeyError):
            await temp_db.consume_email_verification_token(token.token)

        refreshed_user = await temp_db.get_user_by_id(user.id)
        assert refreshed_user.is_verified is False

    asyncio.run(scenario())


def test_reset_link_prefills_two_factor_requirement(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "reset-2fa@example.com")
        temp_db.set_2fa_secret(user.id, "ABCDEFGHIJKLMNOPQRSTUVWX23456789")
        reset_token = await temp_db.create_reset_token(user.id)

        page = object.__new__(LoginPage)
        page._session_ = _FakeSession(
            temp_db,
            {"reset_token": reset_token.token, "email": "reset-2fa@example.com"},
        )
        page._properties_assigned_after_creation_ = set()
        page.force_refresh = lambda: None
        page.current_form = "login"
        page.page_message = ""
        page.page_message_style = "success"
        page.reset_prefilled_email = ""
        page.reset_prefilled_token = ""
        page.reset_prefilled_message = ""
        page.reset_prefilled_message_style = "success"
        page.reset_prefilled_require_two_factor = False

        await LoginPage.on_populate(page)

        assert page.current_form == "reset"
        assert page.reset_prefilled_email == "reset-2fa@example.com"
        assert page.reset_prefilled_token == reset_token.token
        assert page.reset_prefilled_require_two_factor is True
        assert page.reset_prefilled_message == "Reset link received. Enter your new password below."

    asyncio.run(scenario())
