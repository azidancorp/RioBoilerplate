import asyncio
import time
from collections import defaultdict
from pathlib import Path

import pyotp
import pytest

from app.config import config
from app.data_models import AppUser, UserSettings, UserSession
from app.pages.app_page.admin import AdminPage
from app.pages.app_page.disable_mfa import DisableMFA
from app.pages.app_page.enable_mfa import EnableMFA
from app.pages.app_page.recovery_codes import ManageRecoveryCodes
from app.persistence import Persistence
from app.rate_limits import rate_limit_key, sensitive_action_policy


@pytest.fixture
def temp_db(tmp_path: Path):
    db_path = tmp_path / "sensitive-rate-limits.db"
    persistence = Persistence(db_path=db_path)
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
        user_session: UserSession,
        user: AppUser,
    ):
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=user_session.id),
            UserSession: user_session,
            AppUser: user,
        }
        self.client_ip = "198.51.100.40"
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

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url

    def _register_dirty_component(self, component) -> None:
        pass


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


def _mount_admin(session: _FakeSession, **attributes) -> AdminPage:
    component = object.__new__(AdminPage)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.current_user = None
    component.users = []
    component.selected_role = {}
    component.df = None
    component.user_page_index = 0
    component.user_total_count = 0
    component.change_role_identifier = ""
    component.change_role_new_role = "user"
    component.change_role_error = ""
    component.delete_user_identifier = ""
    component.delete_user_confirmation = ""
    component.delete_user_step_up_password = ""
    component.delete_user_step_up_2fa = ""
    component.delete_user_error = ""
    component.delete_user_success = ""
    component.currency_step_up_password = ""
    component.currency_step_up_2fa = ""
    component.step_up_visible = False
    component.step_up_password = ""
    component.step_up_2fa = ""
    component.step_up_error = ""
    component.step_up_pending_identifier = ""
    component.step_up_pending_new_role = ""
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


async def _create_user(
    persistence: Persistence,
    email: str,
    password: str = "VeryStrongPass!9",
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def _bucket_count(persistence: Persistence, scope: str) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM rate_limit_buckets WHERE scope = ?",
        (scope,),
    ).fetchone()[0]


def _stable_totp_now(secret: str, *, min_seconds_remaining: float = 2.0) -> str:
    totp = pyotp.TOTP(secret)
    interval = float(totp.interval)
    while True:
        remaining = interval - (time.time() % interval)
        if remaining >= min_seconds_remaining:
            return totp.now()
        time.sleep(remaining + 0.05)


def test_disable_mfa_is_rate_limited_after_repeated_bad_passwords(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "disable-mfa-limit@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        user = await temp_db.get_user_by_id(user.id)
        user_session = await temp_db.create_session(user.id)
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_disable_mfa(
            session,
            password="wrong-password",
            verification_code="000000",
        )

        for _ in range(config.RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS):
            await DisableMFA._on_totp_entered(page)
            assert page.error_message == "Invalid password. Please try again."

        page.password = "VeryStrongPass!9"
        page.verification_code = _stable_totp_now(secret)
        await DisableMFA._on_totp_entered(page)

        assert "Too many two-factor disable attempts." in page.error_message
        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.two_factor_enabled is True

    asyncio.run(scenario())


def test_disable_mfa_success_clears_rate_limit_bucket(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "disable-mfa-clear@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        user = await temp_db.get_user_by_id(user.id)
        user_session = await temp_db.create_session(user.id)
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_disable_mfa(
            session,
            password="wrong-password",
            verification_code="000000",
        )

        await DisableMFA._on_totp_entered(page)
        assert _bucket_count(temp_db, "mfa_disable") == 1

        page.password = "VeryStrongPass!9"
        page.verification_code = _stable_totp_now(secret)
        await DisableMFA._on_totp_entered(page)

        assert _bucket_count(temp_db, "mfa_disable") == 0
        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.two_factor_enabled is False

    asyncio.run(scenario())


def test_enable_mfa_is_rate_limited_after_repeated_bad_passwords(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "enable-mfa-limit@example.com")
        user_session = await temp_db.create_session(user.id)
        session = _FakeSession(temp_db, user_session, user)
        secret = pyotp.random_base32()
        page = _mount_enable_mfa(
            session,
            password="wrong-password",
            temporary_two_factor_secret=secret,
            verification_code="000000",
        )

        for _ in range(config.RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS):
            await EnableMFA._on_totp_entered(page)
            assert page.error_message == "Invalid password. Please try again."

        page.password = "VeryStrongPass!9"
        page.verification_code = _stable_totp_now(secret)
        await EnableMFA._on_totp_entered(page)

        assert "Too many two-factor setup attempts." in page.error_message
        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.two_factor_enabled is False
        assert page.show_recovery_codes is False

    asyncio.run(scenario())


def test_enable_mfa_success_clears_rate_limit_bucket(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "enable-mfa-clear@example.com")
        user_session = await temp_db.create_session(user.id)
        session = _FakeSession(temp_db, user_session, user)
        secret = pyotp.random_base32()
        page = _mount_enable_mfa(
            session,
            password="wrong-password",
            temporary_two_factor_secret=secret,
            verification_code="000000",
        )

        await EnableMFA._on_totp_entered(page)
        assert _bucket_count(temp_db, "mfa_enable") == 1

        page.password = "VeryStrongPass!9"
        page.verification_code = _stable_totp_now(secret)
        await EnableMFA._on_totp_entered(page)

        assert _bucket_count(temp_db, "mfa_enable") == 0
        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.two_factor_enabled is True

    asyncio.run(scenario())


def test_recovery_code_regeneration_is_rate_limited_after_bad_passwords(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(temp_db, "recovery-limit@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        user = await temp_db.get_user_by_id(user.id)
        user_session = await temp_db.create_session(user.id)
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_recovery_codes(
            session,
            password="wrong-password",
            verification_code="000000",
        )

        for _ in range(config.RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS):
            await ManageRecoveryCodes._on_generate_pressed(page)
            assert page.error_message == "Invalid password. Please try again."

        page.password = "VeryStrongPass!9"
        page.verification_code = _stable_totp_now(secret)
        await ManageRecoveryCodes._on_generate_pressed(page)

        assert "Too many recovery-code attempts." in page.error_message
        assert page.show_recovery_codes is False
        assert temp_db.get_recovery_codes_summary(user.id)["total"] == 0

    asyncio.run(scenario())


def test_recovery_code_regeneration_success_clears_rate_limit_bucket(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(temp_db, "recovery-clear@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        user = await temp_db.get_user_by_id(user.id)
        user_session = await temp_db.create_session(user.id)
        session = _FakeSession(temp_db, user_session, user)
        page = _mount_recovery_codes(
            session,
            password="wrong-password",
            verification_code="000000",
        )

        await ManageRecoveryCodes._on_generate_pressed(page)
        assert _bucket_count(temp_db, "recovery_codes_regenerate") == 1

        page.password = "VeryStrongPass!9"
        page.verification_code = _stable_totp_now(secret)
        await ManageRecoveryCodes._on_generate_pressed(page)

        assert _bucket_count(temp_db, "recovery_codes_regenerate") == 0
        assert page.show_recovery_codes is True
        assert temp_db.get_recovery_codes_summary(user.id)["total"] > 0

    asyncio.run(scenario())


def test_admin_change_role_success_clears_rate_limit_bucket(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "admin-role-clear@example.com")
        target = await _create_user(temp_db, "target-role-clear@example.com")
        admin.role = "root"
        temp_db.conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (admin.role, str(admin.id))
        )
        temp_db.conn.commit()
        admin_session = await temp_db.create_session(admin.id)
        session = _FakeSession(temp_db, admin_session, admin)
        page = _mount_admin(session)
        key = rate_limit_key("admin_change_role", f"{admin.id}:{target.id}")

        temp_db.check_rate_limit(
            policy=sensitive_action_policy("admin_change_role"),
            key=key,
        )
        assert _bucket_count(temp_db, "admin_change_role") == 1

        # Bypass the per-action credential prompt so this test exercises the
        # rate-limit clearing rather than the step-up gate.
        updated = await AdminPage._update_role(
            page, target.email, "admin", step_up_verified=True
        )

        assert updated is True
        assert _bucket_count(temp_db, "admin_change_role") == 0
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == "admin"

    asyncio.run(scenario())


def test_admin_delete_user_success_clears_rate_limit_bucket(temp_db: Persistence):
    async def scenario():
        admin = await _create_user(temp_db, "admin-delete-clear@example.com")
        target = await _create_user(temp_db, "target-delete-clear@example.com")
        admin.role = "root"
        temp_db.conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (admin.role, str(admin.id))
        )
        temp_db.conn.commit()
        admin_session = await temp_db.create_session(admin.id)
        session = _FakeSession(temp_db, admin_session, admin)
        page = _mount_admin(
            session,
            delete_user_identifier=target.email,
            delete_user_confirmation=f"DELETE USER {target.email}",
            delete_user_step_up_password="VeryStrongPass!9",
        )
        key = rate_limit_key("admin_delete_user", f"{admin.id}:{target.id}")

        temp_db.check_rate_limit(
            policy=sensitive_action_policy("admin_delete_user"),
            key=key,
        )
        assert _bucket_count(temp_db, "admin_delete_user") == 1

        await AdminPage._on_delete_user_pressed(page)

        assert _bucket_count(temp_db, "admin_delete_user") == 0
        assert page.delete_user_error == ""
        assert target.email in page.delete_user_success
        with pytest.raises(KeyError):
            await temp_db.get_user_by_id(target.id)

    asyncio.run(scenario())
