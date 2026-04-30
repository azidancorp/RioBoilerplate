import asyncio
from collections import defaultdict
from pathlib import Path

import pyotp
import pytest

from app.config import config
from app.data_models import AppUser, UserSettings, UserSession
from app.pages.app_page.disable_mfa import DisableMFA
from app.pages.app_page.enable_mfa import EnableMFA
from app.pages.app_page.recovery_codes import ManageRecoveryCodes
from app.persistence import Persistence


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


async def _create_user(
    persistence: Persistence,
    email: str,
    password: str = "VeryStrongPass!9",
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    await persistence.create_user(user)
    return await persistence.get_user_by_id(user.id)


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
        page.verification_code = pyotp.TOTP(secret).now()
        await DisableMFA._on_totp_entered(page)

        assert "Too many two-factor disable attempts." in page.error_message
        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.two_factor_enabled is True

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
        page.verification_code = pyotp.TOTP(secret).now()
        await EnableMFA._on_totp_entered(page)

        assert "Too many two-factor setup attempts." in page.error_message
        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.two_factor_enabled is False
        assert page.show_recovery_codes is False

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
        page.verification_code = pyotp.TOTP(secret).now()
        await ManageRecoveryCodes._on_generate_pressed(page)

        assert "Too many recovery-code attempts." in page.error_message
        assert page.show_recovery_codes is False
        assert temp_db.get_recovery_codes_summary(user.id)["total"] == 0

    asyncio.run(scenario())
