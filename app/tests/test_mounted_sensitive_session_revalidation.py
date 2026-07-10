import asyncio
from collections import defaultdict
from pathlib import Path

import pyotp
import pytest

from app.data_models import AppUser, UserSettings, UserSession
from app.components.navbar import Navbar
from app.pages.app_page.dashboard import Overview
from app.pages.app_page.disable_mfa import DisableMFA
from app.pages.app_page.enable_mfa import EnableMFA
from app.pages.app_page.notifications import NotificationsPage
from app.pages.app_page.recovery_codes import ManageRecoveryCodes
from app.pages.app_page.settings import Settings
from app.persistence import Persistence


PASSWORD = "OldPass!234"
NEW_PASSWORD = "NewPass!234"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "mounted-session-revalidation.db")
    try:
        yield persistence
    finally:
        persistence.close()


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(
        self,
        persistence: Persistence,
        user_session: UserSession,
        user: AppUser,
    ):
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=user_session.id),
            UserSession: user_session,
            AppUser: user,
        }
        self.client_ip = "198.51.100.77"
        self.user_agent = "pytest"
        self.http_headers: dict[str, str] = {}
        self.running_as_website = True
        self.navigation_target: str | None = None
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()

    def __getitem__(self, key):
        try:
            return self._attachments[key]
        except KeyError as exc:
            raise KeyError(key) from exc

    def attach(self, value) -> None:
        self._attachments[type(value)] = value

    def detach(self, key) -> None:
        del self._attachments[key]

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url

    def _register_dirty_component(self, component) -> None:
        pass


async def _create_user_with_session(
    persistence: Persistence,
    email: str,
) -> tuple[AppUser, UserSession, _FakeSession]:
    user = AppUser.create_new_user_with_default_settings(email=email, password=PASSWORD)
    await persistence._create_user_unchecked(user)
    user = await persistence.get_user_by_id(user.id)
    user_session = await persistence.create_session(user.id)
    return user, user_session, _FakeSession(persistence, user_session, user)


async def _expire_database_session(persistence: Persistence, user_session: UserSession) -> None:
    cursor = persistence._get_cursor()
    cursor.execute(
        "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
        (persistence._hash_one_time_token(user_session.id),),
    )
    persistence.conn.commit()


def _assert_logged_out(session: _FakeSession) -> None:
    assert UserSession not in session._attachments
    assert AppUser not in session._attachments
    assert session[UserSettings].auth_token == ""
    assert session.navigation_target == "/"


def _bucket_count(persistence: Persistence, scope: str) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM rate_limit_buckets WHERE scope = ?",
        (scope,),
    ).fetchone()[0]


def _mount_settings(session: _FakeSession, **attributes) -> Settings:
    component = object.__new__(Settings)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.error_message = ""
    component.profile_success_message = ""
    component.recovery_code_notice = ""
    component.change_password_current_password = ""
    component.change_password_new_password = ""
    component.change_password_confirm_password = ""
    component.change_password_2fa = ""
    component.change_password_new_password_strength = 0
    component.change_password_passwords_match = False
    component.delete_account_password = ""
    component.delete_account_2fa = ""
    component.delete_account_confirmation = ""
    component.delete_account_error = ""
    component.two_factor_enabled = False
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _mount_navbar(session: _FakeSession) -> Navbar:
    component = object.__new__(Navbar)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.show_hamburger = False
    component.on_hamburger_press = None
    return component


def _mount_dashboard_overview(session: _FakeSession) -> Overview:
    component = object.__new__(Overview)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.currency_overview = object()
    return component


def _mount_notifications(session: _FakeSession, **attributes) -> NotificationsPage:
    component = object.__new__(NotificationsPage)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.notification_data = []
    component.error_message = ""
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _mount_enable_mfa(session: _FakeSession, **attributes) -> EnableMFA:
    component = object.__new__(EnableMFA)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.password = ""
    component.temporary_two_factor_secret = pyotp.random_base32()
    component.verification_code = ""
    component.qr_code_image_bytes = None
    component.secret = None
    component.error_message = ""
    component.recovery_codes = ()
    component.show_recovery_codes = False
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _mount_disable_mfa(session: _FakeSession, **attributes) -> DisableMFA:
    component = object.__new__(DisableMFA)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.password = ""
    component.verification_code = ""
    component.error_message = ""
    component.two_factor_enabled = True
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def _mount_recovery_codes(session: _FakeSession, **attributes) -> ManageRecoveryCodes:
    component = object.__new__(ManageRecoveryCodes)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.password = ""
    component.verification_code = ""
    component.error_message = ""
    component.success_message = ""
    component.recovery_codes = ()
    component.show_recovery_codes = False
    component.recovery_codes_total = 0
    component.recovery_codes_remaining = 0
    component.last_generated_label = "Never generated"
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def test_revoked_mounted_settings_session_cannot_change_password(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "mounted-password@example.com",
        )
        page = _mount_settings(
            session,
            change_password_current_password=PASSWORD,
            change_password_new_password=NEW_PASSWORD,
            change_password_confirm_password=NEW_PASSWORD,
            change_password_passwords_match=True,
        )

        await temp_db.invalidate_all_sessions(user.id)
        await Settings._on_confirm_password_change_pressed(page)

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.verify_password(PASSWORD)
        assert not refreshed.verify_password(NEW_PASSWORD)
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_expired_mounted_settings_session_cannot_change_password(temp_db: Persistence):
    async def scenario():
        user, user_session, session = await _create_user_with_session(
            temp_db,
            "expired-mounted-password@example.com",
        )
        page = _mount_settings(
            session,
            change_password_current_password=PASSWORD,
            change_password_new_password=NEW_PASSWORD,
            change_password_confirm_password=NEW_PASSWORD,
            change_password_passwords_match=True,
        )

        await _expire_database_session(temp_db, user_session)
        await Settings._on_confirm_password_change_pressed(page)

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.verify_password(PASSWORD)
        assert not refreshed.verify_password(NEW_PASSWORD)
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_successful_mounted_password_change_logs_out_invalidated_session(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "fresh-mounted-password@example.com",
        )
        page = _mount_settings(
            session,
            change_password_current_password=PASSWORD,
            change_password_new_password=NEW_PASSWORD,
            change_password_confirm_password=NEW_PASSWORD,
            change_password_passwords_match=True,
        )

        await Settings._on_confirm_password_change_pressed(page)

        refreshed = await temp_db.get_user_by_id(user.id)
        assert not refreshed.verify_password(PASSWORD)
        assert refreshed.verify_password(NEW_PASSWORD)
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_successful_mounted_password_change_clears_rate_limit_bucket(
    temp_db: Persistence,
):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "fresh-mounted-password-clear@example.com",
        )
        page = _mount_settings(
            session,
            change_password_current_password="wrong-password",
            change_password_new_password=NEW_PASSWORD,
            change_password_confirm_password=NEW_PASSWORD,
            change_password_passwords_match=True,
        )

        await Settings._on_confirm_password_change_pressed(page)
        assert page.error_message == "Current password is incorrect"
        assert _bucket_count(temp_db, "settings_password_change") == 1

        page.change_password_current_password = PASSWORD
        await Settings._on_confirm_password_change_pressed(page)

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.verify_password(NEW_PASSWORD)
        assert _bucket_count(temp_db, "settings_password_change") == 0
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_revoked_mounted_settings_session_cannot_delete_account(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "mounted-delete@example.com",
        )
        page = _mount_settings(
            session,
            delete_account_confirmation="DELETE MY ACCOUNT",
            delete_account_password=PASSWORD,
        )

        await temp_db.invalidate_all_sessions(user.id)
        await Settings._on_delete_account_pressed(page)

        assert await temp_db.get_user_by_id(user.id)
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_delete_account_invalid_confirmation_does_not_mutate_two_factor_ui_state(
    temp_db: Persistence,
):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "delete-confirmation-ui@example.com",
        )
        temp_db.set_2fa_secret(user.id, pyotp.random_base32())
        page = _mount_settings(
            session,
            delete_account_confirmation="not the phrase",
            delete_account_password=PASSWORD,
            two_factor_enabled=False,
        )

        await Settings._on_delete_account_pressed(page)

        assert page.two_factor_enabled is False
        assert page.delete_account_error == "Please type 'DELETE MY ACCOUNT' exactly to confirm deletion"
        assert await temp_db.get_user_by_id(user.id)

    asyncio.run(scenario())


def test_revoked_mounted_dashboard_overview_rejects_session(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "mounted-dashboard@example.com",
        )
        page = _mount_dashboard_overview(session)

        await temp_db.invalidate_all_sessions(user.id)
        await Overview.on_populate(page)

        assert page.currency_overview is None
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_revoked_mounted_notifications_do_not_clear_local_state(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "mounted-notifications@example.com",
        )
        page = _mount_notifications(
            session,
            notification_data=[{"type": "INFO", "message": "keep me"}],
        )

        await temp_db.invalidate_all_sessions(user.id)
        await NotificationsPage.on_clear_all_notifications_pressed(page)

        assert page.notification_data == [{"type": "INFO", "message": "keep me"}]
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_navbar_logout_clears_client_auth_token(temp_db: Persistence):
    async def scenario():
        _, user_session, session = await _create_user_with_session(
            temp_db,
            "navbar-logout@example.com",
        )
        navbar = _mount_navbar(session)

        await Navbar.on_logout(navbar)

        with pytest.raises(KeyError):
            temp_db.get_valid_session_by_auth_token(user_session.id)
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_revoked_mounted_session_cannot_enable_mfa(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "mounted-enable-mfa@example.com",
        )
        secret = pyotp.random_base32()
        page = _mount_enable_mfa(
            session,
            password=PASSWORD,
            temporary_two_factor_secret=secret,
            verification_code=pyotp.TOTP(secret).now(),
        )

        await temp_db.invalidate_all_sessions(user.id)
        await EnableMFA._on_totp_entered(page)

        refreshed = await temp_db.get_user_by_id(user.id)
        assert not refreshed.two_factor_enabled
        assert temp_db.get_recovery_codes_summary(user.id)["total"] == 0
        assert not page.show_recovery_codes
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_revoked_mounted_session_cannot_disable_mfa(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "mounted-disable-mfa@example.com",
        )
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        page = _mount_disable_mfa(
            session,
            password=PASSWORD,
            verification_code=pyotp.TOTP(secret).now(),
        )

        await temp_db.invalidate_all_sessions(user.id)
        await DisableMFA._on_totp_entered(page)

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.two_factor_enabled
        _assert_logged_out(session)

    asyncio.run(scenario())


def test_revoked_mounted_session_cannot_regenerate_recovery_codes(temp_db: Persistence):
    async def scenario():
        user, _, session = await _create_user_with_session(
            temp_db,
            "mounted-recovery-codes@example.com",
        )
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        page = _mount_recovery_codes(
            session,
            password=PASSWORD,
            verification_code=pyotp.TOTP(secret).now(),
        )

        await temp_db.invalidate_all_sessions(user.id)
        await ManageRecoveryCodes._on_generate_pressed(page)

        assert temp_db.get_recovery_codes_summary(user.id)["total"] == 0
        assert not page.show_recovery_codes
        _assert_logged_out(session)

    asyncio.run(scenario())
