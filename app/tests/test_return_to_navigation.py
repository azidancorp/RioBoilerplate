import asyncio
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.data_models import AppUser, UserSettings
from app.pages.login import (
    _complete_login_session,
    _google_oauth_login_url,
    _login_destination,
)
from app.persistence import Persistence


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "return-to-navigation.db")
    try:
        yield persistence
    finally:
        persistence.close()


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(self, persistence: Persistence, return_to: object = None):
        query = {} if return_to is None else {"return_to": return_to}
        self.active_page_url = SimpleNamespace(query=query)
        self._store = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=""),
        }
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()
        self.navigated_to: str | None = None

    def __getitem__(self, key):
        return self._store[key]

    def attach(self, value) -> None:
        self._store[type(value)] = value

    def navigate_to(self, target: str) -> None:
        self.navigated_to = target

    def _register_dirty_component(self, component) -> None:
        pass


async def _create_user(
    persistence: Persistence,
    email: str,
    *,
    role: str = "user",
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password="VeryStrongPass!9",
    )
    user.role = role
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def test_login_completion_resumes_an_authorized_registered_destination(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(temp_db, "resume-settings@example.com")
        session = _FakeSession(temp_db, "/app/settings")

        assert await _complete_login_session(session, temp_db, user) is True
        assert session.navigated_to == "/app/settings"
        assert session[UserSettings].auth_token

    asyncio.run(scenario())


def test_login_completion_rechecks_the_live_session_role(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(temp_db, "role-return@example.com")
        session = _FakeSession(temp_db, "/app/admin")

        assert await _complete_login_session(session, temp_db, user) is True
        assert session.navigated_to == "/app/dashboard"

        root = await _create_user(
            temp_db,
            "root-return@example.com",
            role="root",
        )
        root_session = _FakeSession(temp_db, "/app/admin")
        assert await _complete_login_session(
            root_session,
            temp_db,
            root,
        ) is True
        assert root_session.navigated_to == "/app/admin"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "return_to",
    [
        "https://example.com/app/settings",
        "//example.com/app/settings",
        "/app/settings?next=https://example.com",
        "/app/settings#fragment",
        "/app/settings/",
        "/app/not-registered",
        123,
        None,
    ],
)
def test_login_destination_rejects_every_non_exact_return_target(
    temp_db: Persistence,
    return_to: object,
):
    session = _FakeSession(temp_db, return_to)
    assert _login_destination(session, "root") == "/app/dashboard"


def test_google_login_url_carries_only_an_allowlisted_return_destination(
    temp_db: Persistence,
):
    safe_session = _FakeSession(temp_db, "/app/settings")
    assert str(_google_oauth_login_url(safe_session)) == (
        "/auth/google/login?return_to=%2Fapp%2Fsettings"
    )

    unsafe_session = _FakeSession(temp_db, "//example.com/app/settings")
    assert str(_google_oauth_login_url(unsafe_session)) == "/auth/google/login"
