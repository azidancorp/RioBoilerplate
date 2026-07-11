import asyncio
import weakref
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest
import rio
import rio.global_state as rio_global_state

from app import permissions
from app.config import config
from app.data_models import AppUser, UserSettings, UserSession
from app.pages.app_page import admin as admin_page_module
from app.pages.app_page.admin import AdminPage
from app.pages.login import LoginForm
from app.persistence import AdminMutationContext, Persistence
from app.rate_limits import rate_limit_key, sensitive_action_policy
from app.scripts import message_utils
from app.session_validation import StepUpResult


PASSWORD = "VeryStrongPass!9"


def _admin_context(user_session: UserSession) -> AdminMutationContext:
    return AdminMutationContext(
        auth_token=user_session.id,
        client_ip="198.51.100.40",
    )


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
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


async def _create_root_session(persistence: Persistence) -> tuple[AppUser, UserSession]:
    root = AppUser.create_new_user_with_default_settings(
        email="root-lifecycle@example.com",
        password=PASSWORD,
    )
    root.role = "root"
    await persistence._create_user_unchecked(root)
    root = await persistence.get_user_by_id(root.id)
    session = await persistence.create_session(root.id)
    return root, session


async def _create_oauth_root_session(persistence: Persistence) -> tuple[AppUser, UserSession]:
    root = AppUser.create_social_user(
        email="oauth-root-lifecycle@example.com",
        provider="google",
        provider_user_id="oauth-root-lifecycle",
    )
    root.role = "root"
    await persistence._create_user_unchecked(root)
    root = await persistence.get_user_by_id(root.id)
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
    component.create_user_password_strength = 0
    component.create_user_acknowledge_weak_password = False
    component.create_user_role = "user"
    component.create_user_is_verified = False
    component.create_user_step_up_password = ""
    component.create_user_step_up_2fa = ""
    component.create_user_error = ""
    component.create_user_success = ""
    component.edit_user_identifier = ""
    component.edit_user_email = ""
    component.edit_user_username = ""
    component.edit_user_full_name = ""
    component.edit_user_step_up_password = ""
    component.edit_user_step_up_2fa = ""
    component.edit_user_error = ""
    component.edit_user_success = ""
    component.active_user_identifier = ""
    component.active_user_is_active = True
    component.active_user_confirmation = ""
    component.active_user_step_up_password = ""
    component.active_user_step_up_2fa = ""
    component.active_user_error = ""
    component.active_user_success = ""
    component.reset_user_identifier = ""
    component.reset_user_step_up_password = ""
    component.reset_user_step_up_2fa = ""
    component.reset_user_error = ""
    component.reset_user_success = ""
    component.delete_user_identifier = ""
    component.delete_user_confirmation = ""
    component.delete_user_step_up_password = ""
    component.delete_user_step_up_2fa = ""
    component.delete_user_error = ""
    component.delete_user_success = ""
    component.currency_user_identifier = ""
    component.currency_amount = ""
    component.currency_reason = ""
    component.currency_mode_is_set = False
    component.currency_step_up_password = ""
    component.currency_step_up_2fa = ""
    component.currency_error = ""
    component.currency_success = ""
    component.step_up_visible = False
    component.step_up_password = ""
    component.step_up_2fa = ""
    component.step_up_error = ""
    component.step_up_pending_identifier = ""
    component.step_up_pending_user_id = ""
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


def _admin_action_count(
    persistence: Persistence,
    *,
    action: str,
    target_user_id,
) -> int:
    return persistence.conn.execute(
        """
        SELECT COUNT(*)
        FROM admin_audit_log
        WHERE action = ? AND target_user_id = ?
        """,
        (action, str(target_user_id)),
    ).fetchone()[0]


def _race_admin_authorization(
    persistence: Persistence,
    *,
    actor_user_id,
    authorization_change: str,
) -> None:
    if authorization_change == "demote":
        persistence.conn.execute(
            "UPDATE users SET role = 'user' WHERE id = ?",
            (str(actor_user_id),),
        )
        persistence.conn.execute(
            "UPDATE user_sessions SET role = 'user' WHERE user_id = ?",
            (str(actor_user_id),),
        )
    elif authorization_change == "revoke":
        persistence.conn.execute(
            "DELETE FROM user_sessions WHERE user_id = ?",
            (str(actor_user_id),),
        )
    else:
        raise AssertionError(f"Unexpected authorization change: {authorization_change}")
    persistence.conn.commit()


def test_admin_create_user_does_not_public_root_bootstrap(
    temp_db: Persistence,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        created = await temp_db.admin_create_user(
            email="created-on-empty@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
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


def test_admin_creation_requires_weak_password_acknowledgement_when_allowed(
    temp_db: Persistence,
    monkeypatch,
):
    async def scenario():
        monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", True)
        root, root_session = await _create_root_session(temp_db)
        page = _mount_admin(
            _FakeSession(temp_db, root_session, root),
            create_user_email="weak-admin-created@example.com",
            create_user_password="weak",
            create_user_role="user",
        )

        await AdminPage._on_create_user_pressed(page)
        assert "acknowledge" in page.create_user_error
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("weak-admin-created@example.com")

        page.create_user_acknowledge_weak_password = True
        await AdminPage._on_create_user_pressed(page)

        assert page.create_user_error == ""
        created = await temp_db.get_user_by_email("weak-admin-created@example.com")
        assert created.verify_password("weak")

    asyncio.run(scenario())


def test_admin_page_privileged_creation_requires_actor_step_up(
    temp_db: Persistence,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            create_user_email="step-up-admin@example.com",
            create_user_password="AttackerChosen!9",
            create_user_role="admin",
            create_user_is_verified=True,
            create_user_step_up_password="not-the-root-password",
        )

        await AdminPage._on_create_user_pressed(page)

        assert page.create_user_error == "Current password is incorrect"
        assert page.create_user_step_up_password == ""
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("step-up-admin@example.com")

        page.create_user_step_up_password = PASSWORD
        await AdminPage._on_create_user_pressed(page)

        assert page.create_user_error == ""
        assert page.create_user_step_up_password == ""
        created = await temp_db.get_user_by_email("step-up-admin@example.com")
        assert created.role == "admin"
        assert created.is_active is True
        assert created.is_verified is True
        assert created.verify_password("AttackerChosen!9") is True

    asyncio.run(scenario())


def test_new_admin_step_up_actions_warn_when_recovery_codes_are_used(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(
        admin_page_module,
        "send_password_reset_email",
        lambda **kwargs: sent.append(kwargs),
    )

    async def use_recovery_code(*args, **kwargs):
        return StepUpResult(ok=True, used_recovery_code=True)

    monkeypatch.setattr(
        AdminPage,
        "_verify_actor_step_up",
        use_recovery_code,
    )
    expected_warning = (
        "A recovery code was used. Generate a new set to stay protected."
    )

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)
        target = await temp_db.admin_create_user(
            email="recovery-warning-target@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )

        create_page = _mount_admin(
            session,
            create_user_email="recovery-warning-admin@example.com",
            create_user_password="AttackerChosen!9",
            create_user_role="admin",
            create_user_step_up_password=PASSWORD,
        )
        await AdminPage._on_create_user_pressed(create_page)
        assert "recovery-warning-admin@example.com" in create_page.create_user_success
        assert create_page.create_user_error == expected_warning

        duplicate_create_page = _mount_admin(
            session,
            create_user_email="recovery-warning-admin@example.com",
            create_user_password="AttackerChosen!9",
            create_user_role="admin",
            create_user_step_up_password=PASSWORD,
        )
        await AdminPage._on_create_user_pressed(duplicate_create_page)
        assert duplicate_create_page.create_user_success == ""
        assert duplicate_create_page.create_user_error == (
            f"A user with that email already exists. {expected_warning}"
        )

        reset_page = _mount_admin(
            session,
            reset_user_identifier=target.email,
            reset_user_step_up_password=PASSWORD,
        )
        await AdminPage._on_send_reset_pressed(reset_page)
        assert target.email in reset_page.reset_user_success
        assert reset_page.reset_user_error == expected_warning
        assert len(sent) == 1

        active_page = _mount_admin(
            session,
            active_user_identifier=target.email,
            active_user_is_active=False,
            active_user_confirmation=f"DEACTIVATE {target.email}",
            active_user_step_up_password=PASSWORD,
        )
        await AdminPage._on_set_active_pressed(active_page)
        assert "deactivated" in active_page.active_user_success
        assert active_page.active_user_error == expected_warning
        assert (await temp_db.get_user_by_id(target.id)).is_active is False

    asyncio.run(scenario())


def test_privileged_creation_gate_uses_configured_role_hierarchy(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        permissions,
        "ROLE_HIERARCHY",
        {"root": 1, "admin": 3, "user": 4},
    )

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        page = _mount_admin(
            _FakeSession(temp_db, root_session, root),
            create_user_email="renumbered-admin@example.com",
            create_user_password="AttackerChosen!9",
            create_user_role="admin",
            create_user_step_up_password="not-the-root-password",
        )

        await AdminPage._on_create_user_pressed(page)

        assert page.create_user_error == "Current password is incorrect"
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("renumbered-admin@example.com")

    asyncio.run(scenario())


def test_create_role_change_clears_hidden_step_up_credentials(
    temp_db: Persistence,
):
    page = _mount_admin(
        _FakeSession(temp_db),
        create_user_role="admin",
        create_user_step_up_password="secret-password",
        create_user_step_up_2fa="123456",
    )

    AdminPage._on_create_role_change(
        page,
        rio.DropdownChangeEvent(value="user"),
    )

    assert page.create_user_role == "user"
    assert page.create_user_step_up_password == ""
    assert page.create_user_step_up_2fa == ""


def test_privileged_creation_rechecks_actor_role_after_step_up(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            create_user_email="demotion-race-admin@example.com",
            create_user_password="AttackerChosen!9",
            create_user_role="admin",
            create_user_step_up_password=PASSWORD,
        )

        async def demote_actor_during_step_up(*args, **kwargs):
            temp_db.conn.execute(
                "UPDATE users SET role = ? WHERE id = ?",
                ("admin", str(root.id)),
            )
            temp_db.conn.commit()
            return StepUpResult(ok=True)

        monkeypatch.setattr(
            AdminPage,
            "_verify_actor_step_up",
            demote_actor_during_step_up,
        )

        await AdminPage._on_create_user_pressed(page)

        assert "do not have permission" in page.create_user_error
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("demotion-race-admin@example.com")

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
        root, root_session = await _create_root_session(temp_db)
        admin = await temp_db.admin_create_user(
            email="admin-peer@example.com",
            password=PASSWORD,
            role="admin",
            admin_context=_admin_context(root_session),
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
        root, root_session = await _create_root_session(temp_db)
        admin = await temp_db.admin_create_user(
            email="actor-admin@example.com",
            password=PASSWORD,
            role="admin",
            admin_context=_admin_context(root_session),
        )
        target = await temp_db.admin_create_user(
            email="actor-user@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )
        admin_session = await temp_db.create_session(admin.id)

        with pytest.raises(PermissionError):
            await temp_db.admin_create_user(
                email="actor-peer-admin@example.com",
                password=PASSWORD,
                role="admin",
                admin_context=_admin_context(admin_session),
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_update_user_profile(
                root.id,
                admin_context=_admin_context(admin_session),
                username="blocked",
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_set_user_active(
                root.id,
                False,
                admin_context=_admin_context(admin_session),
            )
        with pytest.raises(PermissionError):
            await temp_db.admin_issue_password_reset(
                root.id,
                admin_context=_admin_context(admin_session),
            )

        await temp_db.admin_set_user_active(
            target.id,
            False,
            admin_context=_admin_context(admin_session),
        )
        assert (await temp_db.get_user_by_id(target.id)).is_active is False

    asyncio.run(scenario())


def test_authenticated_admin_page_builds_lifecycle_controls(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        await temp_db.admin_create_user(
            email="build-visible-user@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
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
        root, root_session = await _create_root_session(temp_db)
        admin = await temp_db.admin_create_user(
            email="limited-admin@example.com",
            password=PASSWORD,
            role="admin",
            admin_context=_admin_context(root_session),
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


def test_admin_email_edit_requires_actor_step_up(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="email-stepup-target@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            edit_user_identifier=target.email,
            edit_user_email="new-email-stepup-target@example.com",
            edit_user_step_up_password="wrong-password",
        )

        await AdminPage._on_edit_user_pressed(page)

        assert page.edit_user_error == "Current password is incorrect"
        assert page.edit_user_step_up_password == ""
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.email == target.email

        page.edit_user_step_up_password = PASSWORD
        await AdminPage._on_edit_user_pressed(page)

        assert page.edit_user_error == ""
        assert "new-email-stepup-target@example.com" in page.edit_user_success
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.email == "new-email-stepup-target@example.com"

    asyncio.run(scenario())


@pytest.mark.parametrize("authorization_change", ["demote", "revoke"])
def test_admin_email_edit_rejects_authorization_lost_during_step_up(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
    authorization_change: str,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="email-race-target@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )
        await temp_db.create_reset_token(target.id)
        await temp_db.create_email_verification_token(target.id)
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            edit_user_identifier=target.email,
            edit_user_email="email-race-mutated@example.com",
            edit_user_step_up_password=PASSWORD,
            edit_user_step_up_2fa="should-be-cleared",
        )

        async def lose_authorization_during_step_up(*args, **kwargs):
            _race_admin_authorization(
                temp_db,
                actor_user_id=root.id,
                authorization_change=authorization_change,
            )
            return StepUpResult(ok=True)

        monkeypatch.setattr(
            AdminPage,
            "_verify_actor_step_up",
            lose_authorization_during_step_up,
        )

        await AdminPage._on_edit_user_pressed(page)

        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.email == target.email
        assert _reset_token_count(temp_db, target.id) == 1
        assert _email_verification_token_count(temp_db, target.id) == 1
        assert _admin_action_count(
            temp_db,
            action="user_edit",
            target_user_id=target.id,
        ) == 0
        assert page.edit_user_success == ""
        assert page.edit_user_step_up_password == ""
        assert page.edit_user_step_up_2fa == ""
        assert session.navigation_target == "/"

    asyncio.run(scenario())


def test_oauth_admin_without_step_up_path_gets_actionable_errors(
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
        root, root_session = await _create_oauth_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="oauth-stepup-target@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )
        session = _FakeSession(temp_db, root_session, root)
        expected = "Set up a password or 2FA to perform this action."

        create_page = _mount_admin(
            session,
            create_user_email="oauth-created-admin@example.com",
            create_user_password=PASSWORD,
            create_user_role="admin",
            create_user_is_verified=True,
        )
        await AdminPage._on_create_user_pressed(create_page)
        assert create_page.create_user_error == expected
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("oauth-created-admin@example.com")

        active_page = _mount_admin(
            session,
            active_user_identifier=target.email,
            active_user_is_active=False,
            active_user_confirmation=f"DEACTIVATE {target.email}",
        )
        await AdminPage._on_set_active_pressed(active_page)
        assert active_page.active_user_error == expected
        assert (await temp_db.get_user_by_id(target.id)).is_active is True

        reset_page = _mount_admin(
            session,
            reset_user_identifier=target.email,
        )
        await AdminPage._on_send_reset_pressed(reset_page)
        assert reset_page.reset_user_error == expected
        assert sent == []
        assert _reset_token_count(temp_db, target.id) == 0

        role_page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )
        await AdminPage._on_change_role_pressed(role_page)
        assert role_page.change_role_error == expected
        assert role_page.step_up_visible is False
        assert (await temp_db.get_user_by_id(target.id)).role == "user"

        edit_page = _mount_admin(
            session,
            edit_user_identifier=target.email,
            edit_user_email="oauth-stepup-new@example.com",
        )
        await AdminPage._on_edit_user_pressed(edit_page)
        assert edit_page.edit_user_error == expected
        assert (await temp_db.get_user_by_id(target.id)).email == target.email

        delete_page = _mount_admin(
            session,
            delete_user_identifier=target.email,
            delete_user_confirmation=f"DELETE USER {target.email}",
        )
        await AdminPage._on_delete_user_pressed(delete_page)
        assert delete_page.delete_user_error == expected
        assert (await temp_db.get_user_by_id(target.id)).email == target.email

        currency_page = _mount_admin(
            session,
            currency_user_identifier=target.email,
            currency_amount="25",
        )
        await AdminPage._on_currency_submit(currency_page)
        assert currency_page.currency_error == expected
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.primary_currency_balance == target.primary_currency_balance

    asyncio.run(scenario())


def test_admin_non_email_profile_edit_does_not_require_step_up(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="non-email-edit-target@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            edit_user_identifier=target.email,
            edit_user_username="newusername",
            edit_user_full_name="New Display Name",
        )

        await AdminPage._on_edit_user_pressed(page)

        assert page.edit_user_error == ""
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.email == target.email
        assert refreshed.username == "newusername"
        profile = await temp_db.get_profile_by_user_id(str(target.id))
        assert profile["full_name"] == "New Display Name"

    asyncio.run(scenario())


def test_admin_email_step_up_prompt_uses_cached_target_email(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="same-email-target@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
            username="sameemail",
        )
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(session)
        page.users = [target]

        page.edit_user_identifier = target.email
        page.edit_user_email = target.email.upper()
        assert page._edit_email_step_up_may_be_required() is False

        page.edit_user_identifier = "sameemail"
        page.edit_user_email = "changed-email-target@example.com"
        assert page._edit_email_step_up_may_be_required() is True

    asyncio.run(scenario())


def test_admin_update_user_profile_updates_user_and_profile(
    temp_db: Persistence,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="old-profile@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
            username="oldname",
            full_name="Old Name",
        )
        reset_token = await temp_db.create_reset_token(target.id)
        verification_token = await temp_db.create_email_verification_token(target.id)

        updated = await temp_db.admin_update_user_profile(
            target.id,
            admin_context=_admin_context(root_session),
            email="new-profile@example.com",
            expected_email=target.email,
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
        root, root_session = await _create_root_session(temp_db)
        lookup_target = await temp_db.admin_create_user(
            email="stale-lookup-token@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
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
            admin_context=_admin_context(root_session),
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
            admin_context=_admin_context(root_session),
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
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="inactive-user@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )
        target_session = await temp_db.create_session(target.id)
        reset_token = await temp_db.create_reset_token(target.id)
        verification_token = await temp_db.create_email_verification_token(target.id)

        updated = await temp_db.admin_set_user_active(
            target.id,
            False,
            admin_context=_admin_context(root_session),
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


def test_login_handles_late_session_creation_rejection_without_partial_auth(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="late-session-rejection@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
        )

        async def reject_session_creation(user_id):
            assert user_id == target.id
            raise KeyError(user_id)

        monkeypatch.setattr(temp_db, "create_session", reject_session_creation)
        login_session = _FakeSession(temp_db)
        login_form = _mount_login(
            login_session,
            email=target.email,
            password=PASSWORD,
        )

        await LoginForm.login(login_form)

        assert login_form.banner_style == "danger"
        assert "changed or became inactive" in login_form.error_message
        assert login_form._currently_logging_in is False
        assert UserSession not in login_session._attachments
        assert AppUser not in login_session._attachments
        assert login_session[UserSettings].auth_token == ""
        assert login_session.navigation_target is None

    asyncio.run(scenario())


def test_admin_page_deactivation_requires_confirmation(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await temp_db.admin_create_user(
            email="confirm-target@example.com",
            password=PASSWORD,
            role="user",
            admin_context=_admin_context(root_session),
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
            admin_context=_admin_context(root_session),
        )
        session = _FakeSession(temp_db, root_session, root)

        deactivate_page = _mount_admin(
            session,
            active_user_identifier=target.email,
            active_user_is_active=False,
            active_user_confirmation=f"DEACTIVATE {target.email}",
            active_user_step_up_password="wrong-password",
        )
        await AdminPage._on_set_active_pressed(deactivate_page)
        assert deactivate_page.active_user_error == "Current password is incorrect"
        assert deactivate_page.active_user_step_up_password == ""
        assert (await temp_db.get_user_by_id(target.id)).is_active is True

        deactivate_page.active_user_step_up_password = PASSWORD
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
            active_user_step_up_password="wrong-password",
        )
        await AdminPage._on_set_active_pressed(reactivate_page)
        assert reactivate_page.active_user_error == "Current password is incorrect"
        assert reactivate_page.active_user_step_up_password == ""
        assert (await temp_db.get_user_by_id(target.id)).is_active is False

        reactivate_page.active_user_step_up_password = PASSWORD
        await AdminPage._on_set_active_pressed(reactivate_page)
        assert reactivate_page.active_user_error == ""
        assert "activated" in reactivate_page.active_user_success

        reset_page = _mount_admin(
            session,
            reset_user_identifier=target.email,
            reset_user_step_up_password="wrong-password",
        )
        await AdminPage._on_send_reset_pressed(reset_page)

        assert reset_page.reset_user_error == "Current password is incorrect"
        assert reset_page.reset_user_step_up_password == ""
        assert sent == []
        assert _reset_token_count(temp_db, target.id) == 0

        reset_page.reset_user_step_up_password = PASSWORD
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
