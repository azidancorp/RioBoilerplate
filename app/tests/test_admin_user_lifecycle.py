import asyncio
import weakref
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest
import rio.global_state as rio_global_state

from app.config import config
from app.data_models import AppUser, UserSettings, UserSession
from app.pages.app_page import admin as admin_page_module
from app.pages.app_page.admin import AdminPage
from app.pages.login import LoginForm
from app.persistence import Persistence
from app.rate_limits import rate_limit_key, sensitive_action_policy
from app.scripts import message_utils


PASSWORD = "VeryStrongPass!9"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "admin-lifecycle.db")
    try:
        yield persistence
    finally:
        persistence.close()


@pytest.fixture(autouse=True)
def rate_limit_config():
    original = {
        "RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS": config.RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS,
    }
    config.RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS = 2
    yield
    for key, value in original.items():
        setattr(config, key, value)


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(
        self,
        persistence: Persistence,
        user_session: UserSession | None = None,
        user: AppUser | None = None,
    ):
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=user_session.id if user_session else ""),
        }
        if user_session is not None:
            self._attachments[UserSession] = user_session
        if user is not None:
            self._attachments[AppUser] = user
        self.client_ip = "198.51.100.40"
        self.user_agent = "pytest"
        self.http_headers: dict[str, str] = {}
        self.running_as_website = True
        self.window_width = 120
        self._date_format_string = "%Y-%m-%d"
        self.navigation_target: str | None = None
        self._next_free_component_id = 1
        self._newly_created_components = set()
        self._weak_components_by_id = weakref.WeakValueDictionary()
        self._page_change_callbacks = {}
        self._on_window_size_change_callbacks = {}
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()

    def __getitem__(self, key):
        try:
            return self._attachments[key]
        except KeyError as exc:
            raise KeyError(key) from exc

    def attach(self, value) -> None:
        self._attachments[type(value)] = value

    def detach(self, attachment_type) -> None:
        del self._attachments[attachment_type]

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url

    def _register_dirty_component(self, component) -> None:
        pass


async def _create_user(
    persistence: Persistence,
    email: str,
    password: str = PASSWORD,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    await persistence.create_user(user)
    return await persistence.get_user_by_id(user.id)


async def _create_root_session(persistence: Persistence) -> tuple[AppUser, UserSession]:
    root = await _create_user(persistence, "root-lifecycle@example.com")
    session = await persistence.create_session(root.id)
    return root, session


def _mount_admin(session: _FakeSession, **attributes) -> AdminPage:
    component = object.__new__(AdminPage)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.current_user = None
    component.users = []
    component.selected_role = {}
    component.df = None
    component.change_role_identifier = ""
    component.change_role_new_role = "user"
    component.change_role_error = ""
    component.create_user_email = ""
    component.create_user_username = ""
    component.create_user_full_name = ""
    component.create_user_password = ""
    component.create_user_role = "user"
    component.create_user_is_verified = False
    component.create_user_error = ""
    component.create_user_success = ""
    component.edit_user_identifier = ""
    component.edit_user_email = ""
    component.edit_user_username = ""
    component.edit_user_full_name = ""
    component.edit_user_error = ""
    component.edit_user_success = ""
    component.active_user_identifier = ""
    component.active_user_is_active = True
    component.active_user_confirmation = ""
    component.active_user_error = ""
    component.active_user_success = ""
    component.reset_user_identifier = ""
    component.reset_user_error = ""
    component.reset_user_success = ""
    component.delete_user_identifier = ""
    component.delete_user_confirmation = ""
    component.delete_user_password = ""
    component.delete_user_error = ""
    component.delete_user_success = ""
    component.currency_user_identifier = ""
    component.currency_amount = ""
    component.currency_reason = ""
    component.currency_mode_is_set = False
    component.currency_error = ""
    component.currency_success = ""
    component.step_up_visible = False
    component.step_up_password = ""
    component.step_up_2fa = ""
    component.step_up_error = ""
    component.step_up_pending_identifier = ""
    component.step_up_pending_new_role = ""
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _mount_login(session: _FakeSession, *, email: str, password: str) -> LoginForm:
    component = object.__new__(LoginForm)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.identifier = email
    component.password = password
    component.verification_code = ""
    component.error_message = ""
    component.banner_style = "danger"
    component.pending_verification_email = ""
    component._currently_logging_in = False
    component.on_toggle_form = None
    return component


def _bucket_count(persistence: Persistence, scope: str) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM rate_limit_buckets WHERE scope = ?",
        (scope,),
    ).fetchone()[0]


def _reset_token_count(persistence: Persistence, user_id) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ?",
        (str(user_id),),
    ).fetchone()[0]


def _email_verification_token_count(persistence: Persistence, user_id) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = ?",
        (str(user_id),),
    ).fetchone()[0]


def _session_count(persistence: Persistence, user_id) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM user_sessions WHERE user_id = ?",
        (str(user_id),),
    ).fetchone()[0]


def test_admin_create_user_does_not_public_root_bootstrap(
    temp_db: Persistence,
):
    async def scenario():
        root, _ = await _create_root_session(temp_db)
        created = await temp_db.admin_create_user(
            email="created-on-empty@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
            full_name="Created User",
            is_verified=True,
        )

        assert created.role == "user"
        assert created.is_active is True
        assert created.is_verified is True
        assert temp_db.get_user_count() == 2
        profile = await temp_db.get_profile_by_user_id(str(created.id))
        assert profile["full_name"] == "Created User"

    asyncio.run(scenario())


def test_admin_page_can_create_lower_privilege_user_and_clear_limit(
    temp_db: Persistence,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            create_user_email="new-user@example.com",
            create_user_username="newuser",
            create_user_full_name="New User",
            create_user_password=PASSWORD,
            create_user_role="user",
            create_user_is_verified=True,
        )
        key = rate_limit_key("admin_create_user", f"{root.id}:new-user@example.com")
        temp_db.check_rate_limit(
            policy=sensitive_action_policy("admin_create_user"),
            key=key,
        )
        assert _bucket_count(temp_db, "admin_create_user") == 1

        await AdminPage._on_create_user_pressed(page)

        assert page.create_user_error == ""
        assert "new-user@example.com" in page.create_user_success
        assert _bucket_count(temp_db, "admin_create_user") == 0
        created = await temp_db.get_user_by_email("new-user@example.com")
        assert created.role == "user"
        assert created.is_verified is True
        profile = await temp_db.get_profile_by_user_id(str(created.id))
        assert profile["full_name"] == "New User"

    asyncio.run(scenario())


def test_admin_page_duplicate_email_uses_friendly_error(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            create_user_email=root.email,
            create_user_password=PASSWORD,
            create_user_role="user",
        )

        await AdminPage._on_create_user_pressed(page)

        assert page.create_user_error == "A user with that email already exists."
        assert "UNIQUE constraint failed" not in page.create_user_error

    asyncio.run(scenario())


def test_admin_page_rejects_equal_or_higher_role_creation(temp_db: Persistence):
    async def scenario():
        root, _ = await _create_root_session(temp_db)
        admin = await temp_db.admin_create_user(
            email="admin-peer@example.com",
            password=PASSWORD,
            role="admin",
            actor=root,
        )
        admin_session = await temp_db.create_session(admin.id)
        session = _FakeSession(temp_db, admin_session, admin)
        page = _mount_admin(
            session,
            create_user_email="peer-admin@example.com",
            create_user_password=PASSWORD,
            create_user_role="admin",
        )

        await AdminPage._on_create_user_pressed(page)

        assert "do not have permission" in page.create_user_error
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("peer-admin@example.com")
        assert root.role == "root"

    asyncio.run(scenario())


def test_persistence_admin_methods_enforce_actor_hierarchy(temp_db: Persistence):
    async def scenario():
        root, _ = await _create_root_session(temp_db)
        admin = await temp_db.admin_create_user(
            email="actor-admin@example.com",
            password=PASSWORD,
            role="admin",
            actor=root,
        )
        target = await temp_db.admin_create_user(
            email="actor-user@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
        )

        with pytest.raises(PermissionError):
            await temp_db.admin_create_user(
                email="actor-peer-admin@example.com",
                password=PASSWORD,
                role="admin",
                actor=admin,
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_update_user_profile(
                root.id,
                actor=admin,
                username="blocked",
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_set_user_active(root.id, False, actor=admin)
        with pytest.raises(PermissionError):
            await temp_db.admin_issue_password_reset(root.id, actor=admin)

        await temp_db.admin_set_user_active(target.id, False, actor=admin)
        assert (await temp_db.get_user_by_id(target.id)).is_active is False

    asyncio.run(scenario())


def test_authenticated_admin_page_builds_lifecycle_controls(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        await temp_db.admin_create_user(
            email="build-visible-user@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
            username="builduser",
        )
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(session)

        await AdminPage._load_user_data(page)
        previous_component = rio_global_state.currently_building_component
        previous_session = rio_global_state.currently_building_session
        previous_key_components = rio_global_state.key_to_component
        rio_global_state.currently_building_component = page
        rio_global_state.currently_building_session = session
        rio_global_state.key_to_component = {}
        try:
            rendered = AdminPage.build(page)
        finally:
            rio_global_state.currently_building_component = previous_component
            rio_global_state.currently_building_session = previous_session
            rio_global_state.key_to_component = previous_key_components

        assert type(rendered).__name__ == "CenterComponent"
        assert page.df is not None
        assert "Active" in page.df.columns
        assert "build-visible-user@example.com" in set(page.df["Email"])

    asyncio.run(scenario())


def test_admin_page_rejects_higher_role_edit_status_and_reset(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(
        admin_page_module,
        "send_password_reset_email",
        lambda **kwargs: sent.append(kwargs),
    )

    async def scenario():
        root, _ = await _create_root_session(temp_db)
        admin = await temp_db.admin_create_user(
            email="limited-admin@example.com",
            password=PASSWORD,
            role="admin",
            actor=root,
        )
        admin_session = await temp_db.create_session(admin.id)
        session = _FakeSession(temp_db, admin_session, admin)

        edit_page = _mount_admin(
            session,
            edit_user_identifier=root.email,
            edit_user_username="should-not-apply",
        )
        await AdminPage._on_edit_user_pressed(edit_page)

        assert "do not have permission" in edit_page.edit_user_error
        assert (await temp_db.get_user_by_id(root.id)).username != "should-not-apply"

        deactivate_page = _mount_admin(
            session,
            active_user_identifier=root.email,
            active_user_is_active=False,
        )
        await AdminPage._on_set_active_pressed(deactivate_page)

        assert "do not have permission" in deactivate_page.active_user_error
        assert (await temp_db.get_user_by_id(root.id)).is_active is True

        reset_page = _mount_admin(
            session,
            reset_user_identifier=root.email,
        )
        await AdminPage._on_send_reset_pressed(reset_page)

        assert "do not have permission" in reset_page.reset_user_error
        assert sent == []

    asyncio.run(scenario())


def test_admin_update_user_profile_updates_user_and_profile(
    temp_db: Persistence,
):
    async def scenario():
        root, _ = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="old-profile@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
            username="oldname",
            full_name="Old Name",
        )
        reset_token = await temp_db.create_reset_token(target.id)
        verification_token = await temp_db.create_email_verification_token(target.id)

        updated = await temp_db.admin_update_user_profile(
            target.id,
            actor=root,
            email="new-profile@example.com",
            username="newname",
            full_name="New Name",
        )

        assert updated.email == "new-profile@example.com"
        assert updated.username == "newname"
        profile = await temp_db.get_profile_by_user_id(str(target.id))
        assert profile["email"] == "new-profile@example.com"
        assert profile["full_name"] == "New Name"
        with pytest.raises(KeyError):
            await temp_db.get_user_by_reset_token(reset_token.token)
        with pytest.raises(KeyError):
            await temp_db.consume_email_verification_token(verification_token.token)

    asyncio.run(scenario())


def test_inactive_reset_checks_reject_retained_stale_tokens(temp_db: Persistence):
    async def scenario():
        root, _ = await _create_root_session(temp_db)
        lookup_target = await temp_db.admin_create_user(
            email="stale-lookup-token@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
        )
        lookup_token = await temp_db.create_reset_token(lookup_target.id)
        temp_db.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(lookup_target.id),),
        )
        temp_db.conn.commit()

        with pytest.raises(KeyError):
            await temp_db.get_user_by_reset_token(lookup_token.token)
        assert _reset_token_count(temp_db, lookup_target.id) == 0

        consume_target = await temp_db.admin_create_user(
            email="stale-consume-token@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
        )
        consume_token = await temp_db.create_reset_token(consume_target.id)
        temp_db.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(consume_target.id),),
        )
        temp_db.conn.commit()

        assert await temp_db.consume_reset_token_and_update_password(
            consume_token.token,
            consume_target.id,
            "DifferentStrongPass!9",
        ) is False
        assert _reset_token_count(temp_db, consume_target.id) == 0

        verification_target = await temp_db.admin_create_user(
            email="stale-verification-token@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
            is_verified=False,
        )
        verification_token = await temp_db.create_email_verification_token(
            verification_target.id,
        )
        temp_db.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(verification_target.id),),
        )
        temp_db.conn.commit()

        with pytest.raises(KeyError):
            await temp_db.consume_email_verification_token(verification_token.token)
        assert _email_verification_token_count(temp_db, verification_target.id) == 0

    asyncio.run(scenario())


def test_deactivated_user_cannot_login_refresh_session_or_reset_password(
    temp_db: Persistence,
):
    async def scenario():
        root, _ = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="inactive-user@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
        )
        target_session = await temp_db.create_session(target.id)
        reset_token = await temp_db.create_reset_token(target.id)
        verification_token = await temp_db.create_email_verification_token(target.id)

        updated = await temp_db.admin_set_user_active(
            target.id,
            False,
            actor=root,
        )

        assert updated.is_active is False
        with pytest.raises(KeyError):
            temp_db.get_valid_session_by_auth_token(target_session.id)
        assert _session_count(temp_db, target.id) == 0
        with pytest.raises(KeyError):
            await temp_db.create_session(target.id)
        with pytest.raises(ValueError):
            await temp_db.create_reset_token(target.id)
        with pytest.raises(KeyError):
            await temp_db.get_user_by_reset_token(reset_token.token)
        with pytest.raises(KeyError):
            await temp_db.consume_email_verification_token(verification_token.token)

        login_session = _FakeSession(temp_db)
        login_form = _mount_login(
            login_session,
            email="inactive-user@example.com",
            password=PASSWORD,
        )
        await LoginForm.login(login_form)

        assert login_form.error_message == "This account is inactive. Contact an administrator."
        assert login_session.navigation_target is None

    asyncio.run(scenario())


def test_admin_page_deactivation_requires_confirmation(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="confirm-target@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
        )
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            active_user_identifier=target.email,
            active_user_is_active=False,
        )

        await AdminPage._on_set_active_pressed(page)

        assert 'Type "DEACTIVATE confirm-target@example.com"' in page.active_user_error
        assert (await temp_db.get_user_by_id(target.id)).is_active is True
        assert page.active_user_is_active is False

    asyncio.run(scenario())


def test_admin_page_deactivates_reactivates_and_sends_password_reset(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    sent: list[dict[str, object]] = []

    def fake_send_password_reset_email(**kwargs):
        sent.append(kwargs)

    monkeypatch.setattr(
        admin_page_module,
        "send_password_reset_email",
        fake_send_password_reset_email,
    )

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="reset-target@example.com",
            password=PASSWORD,
            role="user",
            actor=root,
        )
        session = _FakeSession(temp_db, root_session, root)

        deactivate_page = _mount_admin(
            session,
            active_user_identifier=target.email,
            active_user_is_active=False,
            active_user_confirmation=f"DEACTIVATE {target.email}",
        )
        await AdminPage._on_set_active_pressed(deactivate_page)
        assert deactivate_page.active_user_error == ""
        assert "deactivated" in deactivate_page.active_user_success
        assert deactivate_page.active_user_is_active is True
        assert (await temp_db.get_user_by_id(target.id)).is_active is False

        reset_inactive_page = _mount_admin(
            session,
            reset_user_identifier=target.email,
        )
        await AdminPage._on_send_reset_pressed(reset_inactive_page)
        assert "Reactivate" in reset_inactive_page.reset_user_error
        assert sent == []

        reactivate_page = _mount_admin(
            session,
            active_user_identifier=target.email,
            active_user_is_active=True,
        )
        await AdminPage._on_set_active_pressed(reactivate_page)
        assert reactivate_page.active_user_error == ""
        assert "activated" in reactivate_page.active_user_success

        reset_page = _mount_admin(
            session,
            reset_user_identifier=target.email,
        )
        await AdminPage._on_send_reset_pressed(reset_page)

        assert reset_page.reset_user_error == ""
        assert "reset-target@example.com" in reset_page.reset_user_success
        assert len(sent) == 1
        assert sent[0]["recipient"] == "reset-target@example.com"
        token = sent[0]["token"]
        assert isinstance(token, str)
        assert "reset-target@example.com" not in token
        owner = await temp_db.get_user_by_reset_token(token)
        assert owner.id == target.id

    asyncio.run(scenario())


def test_password_reset_email_link_remains_token_only(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, str] = {}

    def fake_send_email(*, recipient: str, subject: str, body: str, **kwargs):
        captured["recipient"] = recipient
        captured["subject"] = subject
        captured["body"] = body

    monkeypatch.setattr(message_utils, "send_email", fake_send_email)
    monkeypatch.setattr(config, "APP_URL", "https://example.test")

    message_utils.send_password_reset_email(
        recipient="reset-link-check@example.com",
        token="RESETTOKEN123",
        valid_until=datetime(2026, 5, 8, tzinfo=timezone.utc),
    )

    assert "https://example.test/login?reset_token=RESETTOKEN123" in captured["body"]
    assert "email=" not in captured["body"]
