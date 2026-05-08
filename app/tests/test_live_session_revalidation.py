import asyncio
import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.data_models import AppUser, UserSession, UserSettings
from app.persistence import Persistence


def _load_app_page_guard():
    module_name = "test_app_page_guard_module"
    module = sys.modules.get(module_name)
    if module is not None:
        return module.guard

    module_path = Path(__file__).resolve().parents[1] / "app" / "pages" / "app_page.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load app page guard from {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.guard


class FakeRioSession:
    def __init__(self, persistence: Persistence, user_session: UserSession):
        self.attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=user_session.id),
            UserSession: user_session,
        }
        self.navigation_target: str | None = None

    def __getitem__(self, attachment_type):
        try:
            return self.attachments[attachment_type]
        except KeyError:
            raise KeyError(attachment_type) from None

    def attach(self, attachment):
        self.attachments[type(attachment)] = attachment

    def detach(self, attachment_type):
        del self.attachments[attachment_type]

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url


class FreshRioSession:
    def __init__(self, persistence: Persistence, auth_token: str):
        self.attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=auth_token),
        }

    def __getitem__(self, attachment_type):
        try:
            return self.attachments[attachment_type]
        except KeyError:
            raise KeyError(attachment_type) from None

    def attach(self, attachment):
        self.attachments[type(attachment)] = attachment


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "test.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_root_session(persistence: Persistence) -> tuple[AppUser, UserSession]:
    user = AppUser.create_new_user_with_default_settings(
        email="root@example.com",
        password="password",
        username="root",
    )
    await persistence.create_user(user)
    user = await persistence.get_user_by_id(user.id)
    session = await persistence.create_session(user.id)
    return user, session


def _guard_event(persistence: Persistence, session: UserSession, url_segment: str):
    return SimpleNamespace(
        session=FakeRioSession(persistence, session),
        active_pages=[SimpleNamespace(url_segment=url_segment)],
    )


def test_guard_rejects_live_session_after_database_revocation(temp_db: Persistence):
    async def scenario():
        user, cached_session = await _create_root_session(temp_db)
        event = _guard_event(temp_db, cached_session, "admin")

        await temp_db.invalidate_all_sessions(user.id)

        assert cached_session.valid_until > datetime.now(timezone.utc)
        assert _load_app_page_guard()(event) == "/"
        assert UserSession not in event.session.attachments
        assert AppUser not in event.session.attachments
        assert event.session[UserSettings].auth_token == ""
        assert event.session.navigation_target is None

    asyncio.run(scenario())


def test_guard_refreshes_demoted_role_before_admin_access_check(temp_db: Persistence):
    async def scenario():
        user, cached_session = await _create_root_session(temp_db)
        event = _guard_event(temp_db, cached_session, "admin")

        await temp_db.update_user_role(user.id, "user")

        assert cached_session.role == "root"
        assert _load_app_page_guard()(event) == "/"
        assert event.session[UserSession].role == "user"
        assert event.session[AppUser].role == "user"

    asyncio.run(scenario())


def test_guard_rejects_live_session_after_database_expiry(temp_db: Persistence):
    async def scenario():
        _, cached_session = await _create_root_session(temp_db)
        event = _guard_event(temp_db, cached_session, "admin")

        cursor = temp_db._get_cursor()
        cursor.execute(
            "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
            (cached_session.id,),
        )
        temp_db.conn.commit()

        assert _load_app_page_guard()(event) == "/"
        assert UserSession not in event.session.attachments
        assert AppUser not in event.session.attachments
        assert event.session[UserSettings].auth_token == ""
        assert event.session.navigation_target is None

    asyncio.run(scenario())


def test_session_start_rejects_inactive_stored_auth_token(temp_db: Persistence):
    async def scenario():
        from app import on_session_start

        root, _ = await _create_root_session(temp_db)
        user = AppUser.create_new_user_with_default_settings(
            email="inactive-session@example.com",
            password="password",
            username="inactive-session",
        )
        await temp_db.create_user(user)
        user = await temp_db.get_user_by_id(user.id)
        cached_session = await temp_db.create_session(user.id)
        await temp_db.admin_set_user_active(user.id, False, actor=root)

        fresh_session = FreshRioSession(temp_db, cached_session.id)
        await on_session_start(fresh_session)

        assert UserSession not in fresh_session.attachments
        assert AppUser not in fresh_session.attachments

    asyncio.run(scenario())
