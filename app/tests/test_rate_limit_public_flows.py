import asyncio
from collections import defaultdict
from pathlib import Path

import pyotp
import pytest
import rio

from app.config import config
from app.data_models import AppUser, UserSettings
from app.pages import contact as contact_page_module
from app.pages import login as login_page_module
from app.pages.contact import ContactPage
from app.pages.login import LoginForm, ResetPasswordForm, SignUpForm
from app.persistence import Persistence


@pytest.fixture
def temp_db(tmp_path: Path):
    db_path = tmp_path / "public-rate-limits.db"
    persistence = Persistence(db_path=db_path)
    try:
        yield persistence
    finally:
        persistence.close()


@pytest.fixture(autouse=True)
def rate_limit_config():
    original = {
        "RATE_LIMIT_LOGIN_IDENTIFIER_ATTEMPTS": config.RATE_LIMIT_LOGIN_IDENTIFIER_ATTEMPTS,
        "RATE_LIMIT_LOGIN_IP_ATTEMPTS": config.RATE_LIMIT_LOGIN_IP_ATTEMPTS,
        "RATE_LIMIT_PASSWORD_RESET_EMAIL_ATTEMPTS": config.RATE_LIMIT_PASSWORD_RESET_EMAIL_ATTEMPTS,
        "RATE_LIMIT_PASSWORD_RESET_IP_ATTEMPTS": config.RATE_LIMIT_PASSWORD_RESET_IP_ATTEMPTS,
        "RATE_LIMIT_PASSWORD_RESET_TOKEN_ATTEMPTS": config.RATE_LIMIT_PASSWORD_RESET_TOKEN_ATTEMPTS,
        "RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_ATTEMPTS": config.RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_ATTEMPTS,
        "RATE_LIMIT_MFA_ATTEMPTS": config.RATE_LIMIT_MFA_ATTEMPTS,
        "RATE_LIMIT_CONTACT_IP_ATTEMPTS": config.RATE_LIMIT_CONTACT_IP_ATTEMPTS,
        "RATE_LIMIT_SIGNUP_EMAIL_ATTEMPTS": config.RATE_LIMIT_SIGNUP_EMAIL_ATTEMPTS,
        "RATE_LIMIT_SIGNUP_IP_ATTEMPTS": config.RATE_LIMIT_SIGNUP_IP_ATTEMPTS,
        "RATE_LIMIT_VERIFICATION_EMAIL_ATTEMPTS": config.RATE_LIMIT_VERIFICATION_EMAIL_ATTEMPTS,
        "RATE_LIMIT_VERIFICATION_IP_ATTEMPTS": config.RATE_LIMIT_VERIFICATION_IP_ATTEMPTS,
    }
    config.RATE_LIMIT_LOGIN_IDENTIFIER_ATTEMPTS = 2
    config.RATE_LIMIT_LOGIN_IP_ATTEMPTS = 100
    config.RATE_LIMIT_PASSWORD_RESET_EMAIL_ATTEMPTS = 2
    config.RATE_LIMIT_PASSWORD_RESET_IP_ATTEMPTS = 100
    config.RATE_LIMIT_PASSWORD_RESET_TOKEN_ATTEMPTS = 2
    config.RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_ATTEMPTS = 100
    config.RATE_LIMIT_MFA_ATTEMPTS = 2
    config.RATE_LIMIT_CONTACT_IP_ATTEMPTS = 2
    config.RATE_LIMIT_SIGNUP_EMAIL_ATTEMPTS = 2
    config.RATE_LIMIT_SIGNUP_IP_ATTEMPTS = 100
    config.RATE_LIMIT_VERIFICATION_EMAIL_ATTEMPTS = 2
    config.RATE_LIMIT_VERIFICATION_IP_ATTEMPTS = 100
    yield
    for key, value in original.items():
        setattr(config, key, value)


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(self, persistence: Persistence, client_ip: str = "198.51.100.20"):
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=""),
        }
        self.client_ip = client_ip
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


def _mount_component(component_cls, session: _FakeSession, **attributes):
    component = object.__new__(component_cls)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    if component_cls is LoginForm:
        component._currently_logging_in = False
        component.pending_verification_email = ""
        component.banner_style = "danger"
        component.error_message = ""
        component.verification_code = ""
    if component_cls is ResetPasswordForm:
        component.code_sent = False
        component.require_two_factor = False
        component.reset_token = ""
        component.new_password = ""
        component.confirm_password = ""
        component.verification_code = ""
        component.error_message = ""
        component.banner_style = "danger"
        component.password_strength = 0
        component.do_passwords_match = False
        component.acknowledge_weak_password = False
        component.password_policy_error_visible = False
        component.prefilled_email = ""
        component.prefilled_username = ""
    if component_cls is SignUpForm:
        component.email = ""
        component.password = ""
        component.confirm_password = ""
        component.referral_code = ""
        component.error_message = ""
        component.banner_style = "danger"
        component.is_email_valid = False
        component.passwords_valid = False
        component.password_strength = 0
        component.do_passwords_match = False
        component.acknowledge_weak_password = False
        component.password_policy_error_visible = False
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


async def _create_user(
    persistence: Persistence,
    email: str,
    password: str = "VeryStrongPass!9",
    *,
    username: str | None = None,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    user.username = username
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def test_signup_strength_meter_tracks_live_email_context(temp_db: Persistence):
    async def scenario():
        password = "signup-meter@example.com"
        form = _mount_component(
            SignUpForm,
            _FakeSession(temp_db),
            email="unrelated@example.com",
        )

        await SignUpForm.update_password(
            form,
            rio.TextInputChangeEvent(password),
        )
        assert form.password_strength >= config.PASSWORD_STRENGTH_WARNING_THRESHOLD

        form.acknowledge_weak_password = True
        await SignUpForm.update_email(
            form,
            rio.TextInputChangeEvent(password),
        )
        assert form.acknowledge_weak_password is False
        assert form.password_strength < config.PASSWORD_STRENGTH_WARNING_THRESHOLD

    asyncio.run(scenario())


def test_reset_strength_meter_tracks_live_identifier_context(
    temp_db: Persistence,
):
    async def scenario():
        password = "reset-meter@example.com"
        form = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db),
            code_sent=True,
            email="unrelated@example.com",
        )

        await ResetPasswordForm.update_new_password(
            form,
            rio.TextInputChangeEvent(password),
        )
        assert form.password_strength >= config.PASSWORD_STRENGTH_WARNING_THRESHOLD

        form.acknowledge_weak_password = True
        await ResetPasswordForm.update_email(
            form,
            rio.TextInputChangeEvent(password),
        )
        assert form.acknowledge_weak_password is False
        assert form.password_strength < config.PASSWORD_STRENGTH_WARNING_THRESHOLD

        username_password = "ResetUsernameMeter2026"
        form.email = "reset-owner@example.com"
        form.prefilled_email = form.email
        form.prefilled_username = username_password
        await ResetPasswordForm.update_new_password(
            form,
            rio.TextInputChangeEvent(username_password),
        )
        assert form.password_strength < config.PASSWORD_STRENGTH_WARNING_THRESHOLD

    asyncio.run(scenario())


def test_reset_resolved_username_policy_error_precedes_mfa(
    temp_db: Persistence,
):
    async def scenario():
        username = "ResetUsernameContext2026"
        user = await _create_user(
            temp_db,
            "reset-username-context@example.com",
            username=username,
        )
        temp_db.set_2fa_secret(user.id, pyotp.random_base32())
        reset_token = await temp_db.create_reset_token(user.id)
        form = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db),
            code_sent=True,
            email=user.email,
            reset_token=reset_token.token,
            new_password=username,
            confirm_password=username,
            acknowledge_weak_password=True,
        )

        await ResetPasswordForm._update_password(form)

        assert "account identifier" in form.error_message
        assert "predictable" in form.error_message
        assert "2FA" not in form.error_message
        assert form.acknowledge_weak_password is False
        assert form.password_strength < config.PASSWORD_STRENGTH_WARNING_THRESHOLD
        assert (await temp_db.get_user_by_id(user.id)).verify_password(username) is False
        assert (await temp_db.get_user_by_reset_token(reset_token.token)).id == user.id

    asyncio.run(scenario())


def test_public_password_edits_clear_only_policy_banners(
    temp_db: Persistence,
):
    async def scenario():
        signup = _mount_component(
            SignUpForm,
            _FakeSession(temp_db),
            email="signup-banner@example.com",
            error_message="This password is too common or predictable.",
            acknowledge_weak_password=True,
            password_policy_error_visible=True,
        )
        await SignUpForm.update_password(
            signup,
            rio.TextInputChangeEvent("ChangedSignupPassword!2026"),
        )
        assert signup.error_message == ""
        assert signup.acknowledge_weak_password is False
        assert signup.password_policy_error_visible is False

        reset = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db),
            code_sent=True,
            email="reset-banner@example.com",
            error_message="Check your inbox and enter the token below.",
            acknowledge_weak_password=True,
        )
        await ResetPasswordForm.update_new_password(
            reset,
            rio.TextInputChangeEvent("ChangedResetPassword!2026"),
        )
        assert reset.error_message == "Check your inbox and enter the token below."
        assert reset.acknowledge_weak_password is False

        reset.error_message = "This password is too common or predictable."
        reset.password_policy_error_visible = True
        await ResetPasswordForm.update_email(
            reset,
            rio.TextInputChangeEvent("changed-reset-banner@example.com"),
        )
        assert reset.error_message == ""
        assert reset.password_policy_error_visible is False

    asyncio.run(scenario())


def test_public_acknowledgement_handlers_clear_only_policy_banners(
    temp_db: Persistence,
):
    signup = _mount_component(
        SignUpForm,
        _FakeSession(temp_db),
        error_message="Please acknowledge these warnings.",
        password_policy_error_visible=True,
    )
    SignUpForm.on_acknowledge_weak_password_change(
        signup,
        rio.SwitchChangeEvent(True),
    )
    assert signup.acknowledge_weak_password is True
    assert signup.error_message == ""
    assert signup.password_policy_error_visible is False

    signup.error_message = "This email is already registered"
    SignUpForm.on_acknowledge_weak_password_change(
        signup,
        rio.SwitchChangeEvent(True),
    )
    assert signup.error_message == "This email is already registered"

    reset = _mount_component(
        ResetPasswordForm,
        _FakeSession(temp_db),
        error_message="Please acknowledge these warnings.",
        password_policy_error_visible=True,
    )
    ResetPasswordForm.on_acknowledge_weak_password_change(
        reset,
        rio.SwitchChangeEvent(True),
    )
    assert reset.acknowledge_weak_password is True
    assert reset.error_message == ""
    assert reset.password_policy_error_visible is False

    reset.error_message = "Invalid or expired reset token."
    ResetPasswordForm.on_acknowledge_weak_password_change(
        reset,
        rio.SwitchChangeEvent(True),
    )
    assert reset.error_message == "Invalid or expired reset token."


def test_signup_passes_warning_acknowledgement_to_persistence(
    temp_db: Persistence,
):
    async def scenario():
        await _create_user(temp_db, "existing-root@example.com")
        form = _mount_component(
            SignUpForm,
            _FakeSession(temp_db),
            email="acknowledged-signup@example.com",
            password="weak",
            confirm_password="weak",
            acknowledge_weak_password=True,
        )

        await SignUpForm.on_sign_up_pressed(form)

        created = await temp_db.get_user_by_email(
            "acknowledged-signup@example.com"
        )
        assert created.verify_password("weak")

    asyncio.run(scenario())


def test_reset_passes_warning_acknowledgement_without_reasking(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(temp_db, "acknowledged-reset@example.com")
        reset_token = await temp_db.create_reset_token(user.id)
        form = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db),
            code_sent=True,
            email=user.email,
            reset_token=reset_token.token,
            new_password="weak",
            confirm_password="weak",
            acknowledge_weak_password=True,
        )

        await ResetPasswordForm._update_password(form)

        assert "updated" in form.error_message.lower()
        assert (await temp_db.get_user_by_id(user.id)).verify_password("weak")

    asyncio.run(scenario())


def test_reset_surfaces_transactional_policy_race_message(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        user = await _create_user(
            temp_db,
            "reset-policy-race@example.com",
        )
        reset_token = await temp_db.create_reset_token(user.id)
        form = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db),
            code_sent=True,
            email=user.email,
            reset_token=reset_token.token,
            new_password="RaceSafePasswordChoice!2026",
            confirm_password="RaceSafePasswordChoice!2026",
        )
        policy_message = (
            "This password now matches an account identifier. "
            "Please choose a different password."
        )

        async def reject_changed_context(*args, **kwargs):
            raise ValueError(policy_message)

        monkeypatch.setattr(
            temp_db,
            "consume_reset_token_and_update_password",
            reject_changed_context,
        )

        await ResetPasswordForm._update_password(form)

        assert form.error_message == policy_message
        assert form.password_policy_error_visible is True
        assert (await temp_db.get_user_by_reset_token(reset_token.token)).id == user.id

    asyncio.run(scenario())


def _reset_token_hashes(persistence: Persistence, user_id) -> list[str]:
    return [
        row[0]
        for row in persistence.conn.execute(
            "SELECT token_hash FROM password_reset_tokens WHERE user_id = ? ORDER BY created_at",
            (str(user_id),),
        )
    ]


def _verification_token_hashes(persistence: Persistence, user_id) -> list[str]:
    return [
        row[0]
        for row in persistence.conn.execute(
            "SELECT token_hash FROM email_verification_tokens WHERE user_id = ? ORDER BY created_at",
            (str(user_id),),
        )
    ]


def test_reset_request_uses_same_visible_state_for_existing_and_unknown_email(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    sent: list[dict] = []
    monkeypatch.setattr(login_page_module, "send_password_reset_email", lambda **kwargs: sent.append(kwargs))

    async def scenario():
        user = await _create_user(temp_db, "reset-visible@example.com")
        temp_db.set_2fa_secret(user.id, "ABCDEFGHIJKLMNOPQRSTUVWX23456789")

        existing = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db, "198.51.100.21"),
            email="reset-visible@example.com",
        )
        missing = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db, "198.51.100.22"),
            email="missing-visible@example.com",
        )

        await ResetPasswordForm._send_reset_token(existing)
        await ResetPasswordForm._send_reset_token(missing)

        assert existing.code_sent is True
        assert missing.code_sent is True
        assert existing.require_two_factor is False
        assert missing.require_two_factor is False
        assert existing.banner_style == missing.banner_style == "success"
        assert existing.error_message == missing.error_message
        assert len(sent) == 1

    asyncio.run(scenario())


def test_rate_limited_reset_request_does_not_rotate_token_or_send_email(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    config.RATE_LIMIT_PASSWORD_RESET_EMAIL_ATTEMPTS = 1
    sent: list[dict] = []
    monkeypatch.setattr(login_page_module, "send_password_reset_email", lambda **kwargs: sent.append(kwargs))

    async def scenario():
        user = await _create_user(temp_db, "reset-limit@example.com")
        original_token = await temp_db.create_reset_token(user.id)
        assert original_token.token

        form = _mount_component(
            ResetPasswordForm,
            _FakeSession(temp_db, "198.51.100.23"),
            email="reset-limit@example.com",
        )
        await ResetPasswordForm._send_reset_token(form)
        allowed_hashes = _reset_token_hashes(temp_db, user.id)
        assert len(sent) == 1

        await ResetPasswordForm._send_reset_token(form)

        assert "Too many password reset requests." in form.error_message
        assert _reset_token_hashes(temp_db, user.id) == allowed_hashes
        assert len(sent) == 1

    asyncio.run(scenario())


def test_verification_resend_rate_limit_does_not_rotate_token_or_send_email(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    config.RATE_LIMIT_VERIFICATION_EMAIL_ATTEMPTS = 1
    sent: list[dict] = []
    monkeypatch.setattr(login_page_module, "send_email_verification_email", lambda **kwargs: sent.append(kwargs))

    async def scenario():
        user = await _create_user(temp_db, "verify-limit@example.com")
        original_token = await temp_db.create_email_verification_token(user.id)
        assert original_token.token

        form = _mount_component(
            LoginForm,
            _FakeSession(temp_db, "198.51.100.27"),
            identifier=user.email,
            pending_verification_email=user.email,
        )
        await LoginForm.resend_verification_email(form)
        allowed_hashes = _verification_token_hashes(temp_db, user.id)
        assert form.banner_style == "success"
        assert len(sent) == 1

        await LoginForm.resend_verification_email(form)

        assert "Too many verification email requests." in form.error_message
        assert _verification_token_hashes(temp_db, user.id) == allowed_hashes
        assert len(sent) == 1

    asyncio.run(scenario())


def test_signup_rate_limit_blocks_repeated_duplicate_identifier_attempts(temp_db: Persistence):
    config.RATE_LIMIT_SIGNUP_EMAIL_ATTEMPTS = 1

    async def scenario():
        existing = await _create_user(temp_db, "signup-limit@example.com")
        form = _mount_component(
            SignUpForm,
            _FakeSession(temp_db, "198.51.100.28"),
            email=existing.email,
            password="VeryStrongPass!9",
            confirm_password="VeryStrongPass!9",
        )

        await SignUpForm.on_sign_up_pressed(form)
        assert form.error_message == "This email is already registered"

        await SignUpForm.on_sign_up_pressed(form)

        assert "Too many sign-up attempts." in form.error_message
        count = temp_db.conn.execute(
            "SELECT COUNT(*) FROM users WHERE email = ?",
            (existing.email,),
        ).fetchone()[0]
        assert count == 1

    asyncio.run(scenario())


def test_login_rate_limit_blocks_even_valid_password_after_failures(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "login-limit@example.com")
        session = _FakeSession(temp_db, "198.51.100.24")
        form = _mount_component(
            LoginForm,
            session,
            identifier=user.email,
            password="wrong-password",
        )

        for _ in range(config.RATE_LIMIT_LOGIN_IDENTIFIER_ATTEMPTS):
            await LoginForm.login(form)
            assert form.error_message == "Invalid email or password. Please try again."

        form.password = "VeryStrongPass!9"
        await LoginForm.login(form)

        assert "Too many login attempts." in form.error_message
        assert session.navigation_target is None
        assert session[UserSettings].auth_token == ""

    asyncio.run(scenario())


def test_login_ip_rate_limit_blocks_varied_identifiers_from_same_ip(temp_db: Persistence):
    config.RATE_LIMIT_LOGIN_IDENTIFIER_ATTEMPTS = 100
    config.RATE_LIMIT_LOGIN_IP_ATTEMPTS = 2

    async def scenario():
        user = await _create_user(temp_db, "login-ip-limit@example.com")
        session = _FakeSession(temp_db, "198.51.100.31")
        form = _mount_component(LoginForm, session, password="wrong-password")

        for index in range(config.RATE_LIMIT_LOGIN_IP_ATTEMPTS):
            form.identifier = f"missing-{index}@example.com"
            await LoginForm.login(form)
            assert form.error_message == "Invalid email or password. Please try again."

        form.identifier = user.email
        form.password = "VeryStrongPass!9"
        await LoginForm.login(form)

        assert "Too many login attempts." in form.error_message
        assert session.navigation_target is None
        assert session[UserSettings].auth_token == ""

    asyncio.run(scenario())


def test_login_mfa_rate_limit_blocks_valid_code_after_bad_codes(temp_db: Persistence):
    config.RATE_LIMIT_LOGIN_IDENTIFIER_ATTEMPTS = 100
    config.RATE_LIMIT_LOGIN_IP_ATTEMPTS = 100

    async def scenario():
        user = await _create_user(temp_db, "login-mfa-limit@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)

        session = _FakeSession(temp_db, "198.51.100.32")
        form = _mount_component(
            LoginForm,
            session,
            identifier=user.email,
            password="VeryStrongPass!9",
            verification_code="000000",
        )

        for _ in range(config.RATE_LIMIT_MFA_ATTEMPTS):
            await LoginForm.login(form)
            assert "Invalid verification or recovery code." in form.error_message

        form.verification_code = pyotp.TOTP(secret).now()
        await LoginForm.login(form)

        assert "Too many two-factor attempts." in form.error_message
        assert session.navigation_target is None
        assert session[UserSettings].auth_token == ""

    asyncio.run(scenario())


def test_reset_token_rate_limit_blocks_valid_token_after_guessing(temp_db: Persistence):
    async def scenario():
        user = await _create_user(temp_db, "reset-token-limit@example.com")
        reset_token = await temp_db.create_reset_token(user.id)
        session = _FakeSession(temp_db, "198.51.100.25")
        form = _mount_component(
            ResetPasswordForm,
            session,
            code_sent=True,
            email="wrong-email@example.com",
            reset_token=reset_token.token,
            new_password="EvenStrongerPass!7",
            confirm_password="EvenStrongerPass!7",
        )

        for _ in range(config.RATE_LIMIT_PASSWORD_RESET_TOKEN_ATTEMPTS):
            await ResetPasswordForm._update_password(form)
            assert "Invalid or expired reset token." in form.error_message

        form.email = user.email
        await ResetPasswordForm._update_password(form)

        assert "Too many password reset attempts." in form.error_message
        refreshed_user = await temp_db.get_user_by_id(user.id)
        assert refreshed_user.verify_password("EvenStrongerPass!7") is False
        assert _reset_token_hashes(temp_db, user.id)

    asyncio.run(scenario())


def test_verification_ip_rate_limit_blocks_varied_emails_from_same_ip(temp_db: Persistence):
    config.RATE_LIMIT_VERIFICATION_EMAIL_ATTEMPTS = 100
    config.RATE_LIMIT_VERIFICATION_IP_ATTEMPTS = 2

    async def scenario():
        session = _FakeSession(temp_db, "198.51.100.33")
        form = _mount_component(LoginForm, session)

        for index in range(config.RATE_LIMIT_VERIFICATION_IP_ATTEMPTS):
            form.identifier = f"missing-verify-{index}@example.com"
            await LoginForm.resend_verification_email(form)
            assert form.banner_style == "success"

        form.identifier = "missing-verify-final@example.com"
        await LoginForm.resend_verification_email(form)

        assert "Too many verification email requests." in form.error_message

    asyncio.run(scenario())


def test_password_reset_completion_ip_rate_limit_blocks_varied_tokens(
    temp_db: Persistence,
):
    config.RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_ATTEMPTS = 2
    config.RATE_LIMIT_PASSWORD_RESET_TOKEN_ATTEMPTS = 100

    async def scenario():
        user = await _create_user(temp_db, "reset-completion-ip-limit@example.com")
        reset_token = await temp_db.create_reset_token(user.id)
        session = _FakeSession(temp_db, "198.51.100.34")
        form = _mount_component(
            ResetPasswordForm,
            session,
            code_sent=True,
            email=user.email,
            new_password="EvenStrongerPass!7",
            confirm_password="EvenStrongerPass!7",
        )

        for index in range(config.RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_ATTEMPTS):
            form.reset_token = f"wrong-token-{index}"
            await ResetPasswordForm._update_password(form)
            assert "Invalid or expired reset token." in form.error_message

        form.reset_token = reset_token.token
        await ResetPasswordForm._update_password(form)

        assert "Too many password reset attempts." in form.error_message
        refreshed_user = await temp_db.get_user_by_id(user.id)
        assert refreshed_user.verify_password("EvenStrongerPass!7") is False

    asyncio.run(scenario())


def test_password_reset_mfa_rate_limit_blocks_valid_code_after_bad_codes(
    temp_db: Persistence,
):
    config.RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_ATTEMPTS = 100
    config.RATE_LIMIT_PASSWORD_RESET_TOKEN_ATTEMPTS = 100

    async def scenario():
        user = await _create_user(temp_db, "reset-mfa-limit@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        reset_token = await temp_db.create_reset_token(user.id)
        session = _FakeSession(temp_db, "198.51.100.35")
        form = _mount_component(
            ResetPasswordForm,
            session,
            code_sent=True,
            email=user.email,
            reset_token=reset_token.token,
            new_password="EvenStrongerPass!7",
            confirm_password="EvenStrongerPass!7",
            verification_code="000000",
        )

        for _ in range(config.RATE_LIMIT_MFA_ATTEMPTS):
            await ResetPasswordForm._update_password(form)
            assert "Invalid verification or recovery code." in form.error_message

        form.verification_code = pyotp.TOTP(secret).now()
        await ResetPasswordForm._update_password(form)

        assert "Too many two-factor attempts." in form.error_message
        refreshed_user = await temp_db.get_user_by_id(user.id)
        assert refreshed_user.verify_password("EvenStrongerPass!7") is False

    asyncio.run(scenario())


def test_contact_form_rate_limits_by_ip(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    submissions: list[tuple[str, str, str]] = []

    def fake_create_contact_submission(*, name: str, email: str, message: str):
        submissions.append((name, email, message))
        return {"id": len(submissions)}

    monkeypatch.setattr(contact_page_module, "create_contact_submission", fake_create_contact_submission)

    page = _mount_component(
        ContactPage,
        _FakeSession(temp_db, "198.51.100.26"),
        name="Casey",
        email="casey@example.com",
        message="Hello from the test form.",
        error_message="",
        banner_style="danger",
        is_submitting=False,
    )

    for _ in range(config.RATE_LIMIT_CONTACT_IP_ATTEMPTS):
        ContactPage.on_submit_pressed(page)
        assert "sent successfully" in page.error_message.lower()
        page.name = "Casey"
        page.email = "casey@example.com"
        page.message = "Another message."

    ContactPage.on_submit_pressed(page)

    assert "Too many messages sent." in page.error_message
    assert len(submissions) == config.RATE_LIMIT_CONTACT_IP_ATTEMPTS
