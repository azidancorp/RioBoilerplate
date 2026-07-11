from __future__ import annotations

import json
import typing as t
import uuid

import rio
from fastapi import HTTPException

from app.persistence import BootstrapRequiredError, Persistence
from app.data_models import AppUser, UserSettings, RecoveryCodeUsage
from app.navigation import get_registered_app_path
from app.permissions import check_access
from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_NARROW
from app.scripts.utils import (
    get_password_strength,
    get_password_strength_color,
    get_password_strength_status,
)
from app.scripts.message_utils import (
    send_email_verification_email,
    send_password_reset_email,
)
from app.request_context import context_from_rio_session
from app.rate_limits import (
    first_blocked,
    login_identifier_policy,
    login_ip_policy,
    login_mfa_policy,
    password_reset_completion_ip_policy,
    password_reset_email_policy,
    password_reset_ip_policy,
    password_reset_mfa_policy,
    password_reset_token_policy,
    rate_limit_key,
    rate_limited_message,
    signup_email_policy,
    signup_ip_policy,
    token_rate_limit_key,
    verification_email_policy,
    verification_ip_policy,
)
from app.validation import SecuritySanitizer
from app.config import config
from app.password_policy import evaluate_new_password


def guard(event: rio.GuardEvent) -> str | None:
    """
    A guard which only allows the user to access this page if they are not
    logged in yet. If the user is already logged in, the login page will be
    skipped and the user will be redirected to the home page instead.
    """
    try:
        event.session[AppUser]
    except KeyError:
        return None

    return "/"


def _consume_rate_limits(
    pers: Persistence,
    checks: t.Iterable[tuple[object, str]],
):
    decisions = [
        pers.check_rate_limit(policy=policy, key=key)
        for policy, key in checks
    ]
    return first_blocked(decisions)


def _generic_reset_message() -> str:
    return (
        "If an account exists with that email, we've sent a reset link. "
        "Check your inbox and enter the token below with your new password."
    )


def _account_changed_during_login_message() -> str:
    return (
        "This account changed or became inactive during sign-in. "
        "Please try again or contact an administrator."
    )


async def _complete_login_session(
    session: rio.Session,
    pers: Persistence,
    user_info: AppUser,
    *,
    recovery_code_used: bool = False,
) -> bool:
    try:
        user_session = await pers.create_session(user_id=user_info.id)
    except KeyError:
        return False

    session.attach(user_session)
    session.attach(user_info)

    settings = session[UserSettings]
    settings.auth_token = user_session.id
    session.attach(settings)

    if recovery_code_used:
        try:
            usage = session[RecoveryCodeUsage]
        except KeyError:
            usage = RecoveryCodeUsage()
            session.attach(usage)
        usage.used_at_login = True

    session.navigate_to(_login_destination(session, user_session.role))
    return True


def _login_destination(session: rio.Session, user_role: str) -> str:
    active_page_url = getattr(session, "active_page_url", None)
    query = getattr(active_page_url, "query", {})
    requested_path = get_registered_app_path(query.get("return_to"))
    if requested_path and check_access(requested_path, user_role):
        return requested_path
    return "/app/dashboard"


def _oauth_error_message(error_code: str) -> str:
    messages = {
        "provider_failed": "Google sign-in failed. Please try again.",
        "provider_not_configured": "Google sign-in is not configured yet.",
        "unsupported_provider": "That sign-in provider is not supported.",
        "missing_provider_id": "Google did not return a valid account identifier.",
        "unverified_email": "Google sign-in requires a verified email address.",
        "bootstrap_required": (
            "This deployment must be initialized by an operator before Google "
            "sign-in can create an account."
        ),
        "account_exists": (
            "An account with this email already exists. Log in with your password, "
            "then link Google in settings once connected accounts are available."
        ),
        "account_inactive": "This account is inactive. Contact an administrator.",
    }
    return messages.get(error_code, "Google sign-in failed. Please try again.")


def _google_oauth_login_url(session: rio.Session) -> rio.URL | str:
    try:
        return session.base_url.joinpath("auth", "google", "login")
    except Exception:
        return "/auth/google/login"


def _navigate_to_google_oauth(session: rio.Session) -> None:
    url = str(_google_oauth_login_url(session))

    async def worker() -> None:
        # Rio page navigation treats same-origin unknown paths as app pages.
        # OAuth must leave the SPA so FastAPI can own the provider redirect.
        await session._evaluate_javascript(
            f"window.location.href = {json.dumps(url)};",
        )

    session.create_task(worker(), name="Navigate to Google OAuth")


################################################################################
# Segmented Forms
################################################################################

class LoginForm(rio.Component):
    """
    This Component handles the login flow, including 2FA verification if needed.

    Email is treated as the primary identifier, but administrators can still
    enable username-based sign-in flows later because the backend falls back to
    username lookups when provided.
    """

    identifier: str = ""
    password: str = ""
    verification_code: str = ""
    error_message: str = ""
    banner_style: str = "danger"
    pending_verification_email: str = ""

    _currently_logging_in: bool = False

    # We'll expose an event so that the parent page can toggle forms
    on_toggle_form: t.Callable[[str], None] | None = None

    async def login(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Attempt to log in the user, checking 2FA if necessary.
        """
        if self._currently_logging_in:
            return

        try:
            self._currently_logging_in = True
            self.force_refresh()

            pers = self.session[Persistence]
            request_context = context_from_rio_session(
                self.session,
                identifier=self.identifier,
            )
            login_identifier_key = rate_limit_key("identifier", self.identifier)
            login_ip_key = rate_limit_key("ip", request_context.client_ip)
            blocked = _consume_rate_limits(
                pers,
                (
                    (login_identifier_policy(), login_identifier_key),
                    (login_ip_policy(), login_ip_key),
                ),
            )
            if blocked:
                self.pending_verification_email = ""
                self.banner_style = "danger"
                self.error_message = rate_limited_message(
                    "Too many login attempts.",
                    blocked.retry_after_seconds,
                )
                return

            #  Try to find a user with this identifier (email first, username fallback)
            try:
                user_info = await pers.get_user_by_identity(identifier=self.identifier)
            except KeyError:
                self.pending_verification_email = ""
                self.banner_style = "danger"
                self.error_message = "Invalid email or password. Please try again."
                return

            if user_info.auth_provider != "password":
                self.pending_verification_email = ""
                self.banner_style = "danger"
                self.error_message = "Invalid email or password. Please try again."
                return

            # Make sure their password matches
            password_result = user_info.verify_password_result(self.password)
            if not password_result.ok:
                self.pending_verification_email = ""
                self.banner_style = "danger"
                self.error_message = "Invalid email or password. Please try again."
                return

            if not user_info.is_active:
                self.pending_verification_email = ""
                self.banner_style = "danger"
                self.error_message = "This account is inactive. Contact an administrator."
                return

            if config.REQUIRE_EMAIL_VERIFICATION and not user_info.is_verified:
                self.pending_verification_email = user_info.email
                self.banner_style = "danger"
                self.error_message = (
                    "Please verify your email address before logging in. Use the resend button below if needed."
                )
                return

            # Check if 2FA is enabled for this user
            recovery_code_used = False
            if user_info.two_factor_enabled:
                # Keep MFA attempts account-scoped: this limits code guessing even
                # when an attacker rotates IPs, at the cost of a short account-level
                # lockout if the password is already compromised.
                mfa_key = rate_limit_key("user", user_info.id)
                blocked = _consume_rate_limits(
                    pers,
                    ((login_mfa_policy(), mfa_key),),
                )
                if blocked:
                    self.banner_style = "danger"
                    self.error_message = rate_limited_message(
                        "Too many two-factor attempts.",
                        blocked.retry_after_seconds,
                    )
                    return

                result = pers.verify_two_factor_challenge(user_info.id, self.verification_code)
                if not result.ok:
                    self.banner_style = "danger"
                    self.error_message = result.get_error_message()
                    return
                recovery_code_used = result.used_recovery_code
                pers.clear_rate_limit(scope=login_mfa_policy().scope, key=mfa_key)

            # The login was successful
            if password_result.needs_rehash:
                user_info = await pers.upgrade_user_password_hash(
                    user_info.id,
                    self.password,
                )

            self.pending_verification_email = ""
            self.banner_style = "danger"
            self.error_message = ""
            pers.clear_rate_limit(
                scope=login_identifier_policy().scope,
                key=login_identifier_key,
            )

            session_created = await _complete_login_session(
                self.session,
                pers,
                user_info,
                recovery_code_used=recovery_code_used,
            )
            if not session_created:
                self.banner_style = "danger"
                self.error_message = _account_changed_during_login_message()

        finally:
            self._currently_logging_in = False

    async def resend_verification_email(self, _=None) -> None:
        """
        Resend verification email for an account that is not yet verified.
        """
        target_identifier = (self.pending_verification_email or self.identifier).strip()
        if not target_identifier:
            self.banner_style = "danger"
            self.error_message = "Enter your email first to resend verification."
            return

        _generic_verify_msg = (
            "If an account exists with that email, a verification email has been sent."
        )

        pers = self.session[Persistence]
        request_context = context_from_rio_session(
            self.session,
            identifier=target_identifier,
        )
        blocked = _consume_rate_limits(
            pers,
            (
                (verification_email_policy(), rate_limit_key("identifier", target_identifier)),
                (verification_ip_policy(), rate_limit_key("ip", request_context.client_ip)),
            ),
        )
        if blocked:
            self.banner_style = "danger"
            self.error_message = rate_limited_message(
                "Too many verification email requests.",
                blocked.retry_after_seconds,
            )
            return

        try:
            user_info = await pers.get_user_by_identity(identifier=target_identifier)
        except KeyError:
            self.banner_style = "success"
            self.error_message = _generic_verify_msg
            return

        if user_info.is_verified:
            # Don't reveal verification status — use the same generic message.
            self.banner_style = "success"
            self.error_message = _generic_verify_msg
            return

        try:
            token = await pers.create_email_verification_token(user_info.id)
        except Exception:
            self.banner_style = "success"
            self.error_message = _generic_verify_msg
            return

        try:
            send_email_verification_email(
                recipient=user_info.email,
                token=token.token,
                valid_until=token.valid_until,
            )
        except Exception:
            self.banner_style = "success"
            self.error_message = _generic_verify_msg
            return

        self.banner_style = "success"
        self.error_message = _generic_verify_msg

    def on_sign_up_button_pressed(self):
        """
        Handle sign-up button press: request the parent to show the SignUp form.
        """
        if self.on_toggle_form:
            self.on_toggle_form("signup")

    def on_reset_password_button_pressed(self):
        """
        Handle reset password button press: request the parent to show the ResetPassword form.
        """
        if self.on_toggle_form:
            self.on_toggle_form("reset")

    def on_google_login_pressed(self) -> None:
        _navigate_to_google_oauth(self.session)

    def build(self) -> rio.Component:
        social_login_components: list[rio.Component] = []
        if config.ENABLE_GOOGLE_LOGIN:
            social_login_components.extend(
                [
                    rio.Separator(),
                    rio.Button(
                        "Continue with Google",
                        on_press=self.on_google_login_pressed,
                        style="minor",
                        shape="rounded",
                        grow_x=True,
                    ),
                ]
            )

        return rio.Card(
            rio.Column(
                rio.Text("Login", style="heading1", justify="center"),
                rio.Banner(
                    text=self.error_message,
                    style=self.banner_style,
                    margin_top=1,
                ),
                rio.TextInput(
                    text=self.bind().identifier,
                    label="Email",
                    on_confirm=self.login
                ),
                rio.TextInput(
                    text=self.bind().password,
                    label="Password",
                    is_secret=True,
                    on_confirm=self.login
                ),
                rio.TextInput(
                    text=self.bind().verification_code,
                    label="2FA or recovery code (if applicable)",
                    on_confirm=self.login,
                ),
                rio.FlowContainer(
                    rio.Button(
                        "Login",
                        on_press=self.login,
                        is_loading=self._currently_logging_in,
                        shape='rounded',
                    ),
                    rio.Button(
                        "Sign up",
                        on_press=self.on_sign_up_button_pressed,
                        shape='rounded',
                    ),
                    rio.Button(
                        "Reset Password",
                        on_press=self.on_reset_password_button_pressed,
                        shape='rounded',
                    ),
                    *(
                        [
                            rio.Button(
                                "Resend Verification Email",
                                on_press=self.resend_verification_email,
                                shape='rounded',
                            )
                        ]
                        if config.REQUIRE_EMAIL_VERIFICATION
                        else []
                    ),
                    row_spacing=1,
                    column_spacing=1,
                ),
                *social_login_components,
                spacing=1,
                margin=2,
            ),
            align_y=0,
        )

class SignUpForm(rio.Component):
    """
    Provides interface for users to sign up for a new account.

    Email addresses are treated as the primary identifier. Username-only signup
    is reserved for a deliberate future anonymous-app mode; it needs matching
    UI copy plus reset/verification-flow changes before shipping.
    """

    # Fields
    email: str = ""
    password: str = ""
    confirm_password: str = ""
    referral_code: str = ""
    error_message: str = ""
    banner_style: str = "danger"
    is_email_valid: bool = False
    passwords_valid: bool = False
    password_strength: int = 0
    do_passwords_match: bool = False
    acknowledge_weak_password: bool = False

    # We'll expose an event so that the parent page can toggle forms
    on_toggle_form: t.Callable[[str], None] | None = None

    async def on_sign_up_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Handles the sign-up process when the user submits the sign-up form.

        It will check if the user already exists and if the passwords match. If
        the user does not exist and the passwords match, a new user will be
        created and stored in the database.
        """
        # Get the persistence instance. It was attached to the session earlier,
        # so we can easily access it from anywhere.
        pers = self.session[Persistence]

        # Make sure all fields are populated
        if (
            not self.email
            or not self.password
            or not self.confirm_password
        ):
            self.banner_style = "danger"
            self.error_message = "Please fill in all fields"
            self.passwords_valid = False
            self.is_email_valid = False
            return

        # BACKEND VALIDATION: Always run through the central email/identifier
        # validator. The config controls strict email syntax, not safety checks.
        # Relaxed identifier mode is not the default for current apps.
        try:
            self.email = SecuritySanitizer.validate_email_format(
                self.email,
                require_valid=config.REQUIRE_VALID_EMAIL,
            )
        except Exception as e:
            self.banner_style = "danger"
            self.error_message = f"Invalid email: {str(e.detail if hasattr(e, 'detail') else e)}"
            self.is_email_valid = False
            return

        # Check if the passwords match
        if self.password != self.confirm_password:
            self.banner_style = "danger"
            self.error_message = "Passwords do not match"
            self.passwords_valid = False
            self.is_email_valid = True
            return

        password_policy = evaluate_new_password(
            self.password,
            acknowledged_weak=self.acknowledge_weak_password,
        )
        if not password_policy.ok:
            self.banner_style = "danger"
            self.error_message = password_policy.message or "Password is not allowed."
            return

        if pers.get_user_count() == 0:
            self.banner_style = "danger"
            self.error_message = (
                "This deployment must be initialized by an operator. "
                "Run python -m app.scripts.bootstrap_root."
            )
            return

        request_context = context_from_rio_session(self.session, identifier=self.email)
        blocked = _consume_rate_limits(
            pers,
            (
                (signup_email_policy(), rate_limit_key("identifier", self.email)),
                (signup_ip_policy(), rate_limit_key("ip", request_context.client_ip)),
            ),
        )
        if blocked:
            self.banner_style = "danger"
            self.error_message = rate_limited_message(
                "Too many sign-up attempts.",
                blocked.retry_after_seconds,
            )
            return

        # Check if the email is already registered
        try:
            await pers.get_user_by_email(email=self.email)
            self.banner_style = "danger"
            self.error_message = "This email is already registered"
            self.is_email_valid = False
            self.passwords_valid = True
            return
        except KeyError:
            # Good news, we can create the user.
            pass

        # Create a new user
        user_info = AppUser.create_new_user_with_default_settings(
            email=self.email,
            password=self.password,
            referral_code=self.referral_code,
        )

        # Store the user in the database
        try:
            await pers.create_user(user_info)
        except BootstrapRequiredError as exc:
            self.banner_style = "danger"
            self.error_message = str(exc)
            return

        if config.REQUIRE_EMAIL_VERIFICATION:
            try:
                token = await pers.create_email_verification_token(user_info.id)
            except Exception:
                self.banner_style = "danger"
                self.error_message = (
                    "Account created, but verification email could not be sent: "
                    "We could not create a verification email at this time. Please try again."
                )
                return

            try:
                send_email_verification_email(
                    recipient=user_info.email,
                    token=token.token,
                    valid_until=token.valid_until,
                )
            except HTTPException as exc:
                detail = getattr(exc, "detail", "Failed to send verification email.")
                self.banner_style = "danger"
                self.error_message = (
                    f"Account created, but verification email could not be sent: {detail}"
                )
                return
            except Exception:
                self.banner_style = "danger"
                self.error_message = (
                    "Account created, but verification email could not be sent: "
                    "Failed to send verification email. Please try again."
                )
                return

            self.banner_style = "success"
            self.error_message = (
                "Account created. We sent you a verification email. "
                "Please verify before logging in."
            )
            return

        self.banner_style = "success"
        self.error_message = "Congratulations! You have successfully signed up. Please log in."

    def on_cancel(self) -> None:
        """
        Cancels the sign-up popup and resets everything.
        """
        self.is_email_valid = True
        self.passwords_valid = True
        self.email = ""
        self.password = ""
        self.confirm_password = ""
        self.referral_code = ""
        self.error_message = ""

        # Return to the login form
        if self.on_toggle_form:
            self.on_toggle_form("login")

    def on_back_to_login_pressed(self):
        """
        Goes back to the login form.
        """
        if self.on_toggle_form:
            self.on_toggle_form("login")

    def on_google_login_pressed(self) -> None:
        _navigate_to_google_oauth(self.session)

    def validate_email(self, email: str):
        """
        FRONTEND VALIDATION: Validate email format in real-time as user types.
        Respects the global config setting for email validation.
        """
        try:
            if email:
                # Use config setting for validation
                SecuritySanitizer.validate_email_format(email, require_valid=config.REQUIRE_VALID_EMAIL)
                self.is_email_valid = True
            else:
                self.is_email_valid = False
        except Exception:
            self.banner_style = "danger"
            self.is_email_valid = False

    async def update_email(self, event: rio.TextInputChangeEvent):
        self.email = event.text
        self.validate_email(self.email)
        self.force_refresh()

    async def update_password(self, event: rio.TextInputChangeEvent):
        self.password = event.text
        self.password_strength = get_password_strength(self.password)
        self.do_passwords_match = self.password == self.confirm_password
        self.acknowledge_weak_password = False
        self.force_refresh()

    async def update_confirm_password(self, event: rio.TextInputChangeEvent):
        self.confirm_password = event.text
        self.do_passwords_match = self.password == self.confirm_password
        self.force_refresh()

    async def update_referral_code(self, event: rio.TextInputChangeEvent):
        self.referral_code = event.text
        self.force_refresh()

    def password_strength_progress(self) -> rio.Component:
        return rio.ProgressBar(
            progress=max(0, min(self.password_strength / 100, 1)),
            color=get_password_strength_color(self.password_strength),
        )

    def build(self) -> rio.Component:
        social_signup_components: list[rio.Component] = []
        if config.ENABLE_GOOGLE_LOGIN:
            social_signup_components.extend(
                [
                    rio.Separator(),
                    rio.Button(
                        "Sign up with Google",
                        on_press=self.on_google_login_pressed,
                        style="minor",
                        shape="rounded",
                        grow_x=True,
                    ),
                ]
            )

        return rio.Card(
            rio.Column(
                rio.Text("Create account", style="heading1", justify="center"),
                # Display an error, if any
                rio.Banner(
                    text=self.error_message,
                    style=self.banner_style,
                    margin_top=1,
                ),
                rio.TextInput(
                    text=self.email,
                    label="Email",
                    on_change=self.update_email,
                    is_sensitive=True,
                    on_confirm=self.on_sign_up_pressed
                ),
                rio.TextInput(
                    text=self.password,
                    label="Password",
                    on_change=self.update_password,
                    is_secret=True,
                    on_confirm=self.on_sign_up_pressed
                ),
                rio.TextInput(
                    text=self.confirm_password,
                    label="Confirm Password",
                    on_change=self.update_confirm_password,
                    is_sensitive=True,
                    is_secret=True,
                    on_confirm=self.on_sign_up_pressed
                ),
                rio.TextInput(
                    text=self.referral_code,
                    label="Referral Code (Optional)",
                    on_change=self.update_referral_code,
                    on_confirm=self.on_sign_up_pressed
                ),
                rio.Text(
                    f'Email is valid: {self.is_email_valid}',
                    style=rio.TextStyle(
                        fill=rio.Color.from_rgb(0, 1, 0, srgb=True)
                        if self.is_email_valid else rio.Color.from_rgb(1, 0, 0, srgb=True)
                    )
                ),
                rio.Text(
                    f'Passwords match: {self.do_passwords_match}',
                    style=rio.TextStyle(
                        fill=rio.Color.from_rgb(0, 1, 0, srgb=True)
                        if self.do_passwords_match else rio.Color.from_rgb(1, 0, 0, srgb=True)
                    ),
                ),
                rio.Text(
                    f'Password strength: {self.password_strength}, '
                    f'{get_password_strength_status(self.password_strength)}',
                    style=rio.TextStyle(fill=get_password_strength_color(self.password_strength))
                ),
                self.password_strength_progress(),
                *(
                    [
                        rio.Row(
                            rio.Switch(
                                is_on=self.bind().acknowledge_weak_password,
                            ),
                            rio.Text(
                                "I acknowledge my password is weak",
                                style=rio.TextStyle(
                                    fill=rio.Color.from_rgb(1, 0.6, 0, srgb=True),
                                ),
                            ),
                            spacing=1,
                            align_x=0,
                        ),
                    ]
                    if config.ALLOW_WEAK_PASSWORDS and self.password and self.password_strength < config.MIN_PASSWORD_STRENGTH
                    else []
                ),
                rio.FlowContainer(
                    rio.Button(
                        "Sign up",
                        on_press=self.on_sign_up_pressed,
                        shape='rounded'
                    ),
                    rio.Button(
                        "Back to Login",
                        on_press=self.on_back_to_login_pressed,
                        shape='rounded'
                    ),
                    row_spacing=1,
                    column_spacing=1,
                ),
                *social_signup_components,
                spacing=1,
                margin=2,
            ),
            align_y=0,
        )


class SocialMFAForm(rio.Component):
    """
    Completes an OAuth login for users who have app-level 2FA enabled.
    """

    pending_user_id: str = ""
    verification_code: str = ""
    error_message: str = ""
    banner_style: str = "success"
    _is_processing: bool = False
    on_toggle_form: t.Callable[[str], None] | None = None

    async def complete_login(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if self._is_processing:
            return

        self._is_processing = True
        self.force_refresh()
        try:
            pers = self.session[Persistence]
            try:
                user_id = uuid.UUID(self.pending_user_id)
                user_info = await pers.get_user_by_id(user_id)
            except (ValueError, KeyError):
                self.banner_style = "danger"
                self.error_message = "Google sign-in expired. Please try again."
                return

            if not user_info.is_active:
                self.banner_style = "danger"
                self.error_message = "This account is inactive. Contact an administrator."
                return

            if not user_info.two_factor_enabled:
                session_created = await _complete_login_session(
                    self.session,
                    pers,
                    user_info,
                )
                if not session_created:
                    self.banner_style = "danger"
                    self.error_message = _account_changed_during_login_message()
                return

            mfa_key = rate_limit_key("user", user_info.id)
            blocked = _consume_rate_limits(
                pers,
                ((login_mfa_policy(), mfa_key),),
            )
            if blocked:
                self.banner_style = "danger"
                self.error_message = rate_limited_message(
                    "Too many two-factor attempts.",
                    blocked.retry_after_seconds,
                )
                return

            result = pers.verify_two_factor_challenge(user_info.id, self.verification_code)
            if not result.ok:
                self.banner_style = "danger"
                self.error_message = result.get_error_message()
                return

            pers.clear_rate_limit(scope=login_mfa_policy().scope, key=mfa_key)
            session_created = await _complete_login_session(
                self.session,
                pers,
                user_info,
                recovery_code_used=result.used_recovery_code,
            )
            if not session_created:
                self.banner_style = "danger"
                self.error_message = _account_changed_during_login_message()
        finally:
            self._is_processing = False
            self.force_refresh()

    def on_cancel(self) -> None:
        self.verification_code = ""
        self.error_message = ""
        if self.on_toggle_form:
            self.on_toggle_form("login")

    def build(self) -> rio.Component:
        return rio.Card(
            rio.Column(
                rio.Text("Complete sign in", style="heading1", justify="center"),
                rio.Banner(
                    text=self.error_message or "Google verified. Enter your app 2FA code.",
                    style=self.banner_style,
                    margin_top=1,
                ),
                rio.TextInput(
                    text=self.bind().verification_code,
                    label="2FA or recovery code",
                    on_confirm=self.complete_login,
                ),
                rio.FlowContainer(
                    rio.Button(
                        "Verify",
                        on_press=self.complete_login,
                        is_loading=self._is_processing,
                        shape="rounded",
                    ),
                    rio.Button(
                        "Back to Login",
                        on_press=self.on_cancel,
                        shape="rounded",
                    ),
                    row_spacing=1,
                    column_spacing=1,
                ),
                spacing=1,
                margin=2,
            ),
            align_y=0,
        )


class ResetPasswordForm(rio.Component):
    """
    Provides an interface for resetting the user's password with a one-time token.
    """

    email: str = ""
    reset_token: str = ""
    new_password: str = ""
    confirm_password: str = ""
    verification_code: str = ""
    error_message: str = ""
    banner_style: str = "danger"
    code_sent: bool = False
    require_two_factor: bool = False
    _is_processing: bool = False
    password_strength: int = 0
    do_passwords_match: bool = False
    acknowledge_weak_password: bool = False
    prefilled_email: str = ""
    prefilled_reset_token: str = ""
    prefilled_message: str = ""
    prefilled_message_style: str = "success"
    prefilled_require_two_factor: bool = False

    # We'll expose an event so that the parent page can toggle forms
    on_toggle_form: t.Callable[[str], None] | None = None

    @rio.event.on_populate
    def on_populate(self) -> None:
        if self.prefilled_email and not self.email:
            self.email = self.prefilled_email

        if self.prefilled_reset_token:
            self.code_sent = True
            self.reset_token = self.prefilled_reset_token
            self.require_two_factor = self.prefilled_require_two_factor

        if self.prefilled_message:
            self.banner_style = self.prefilled_message_style
            self.error_message = self.prefilled_message

    def _set_banner(self, style: str, message: str) -> None:
        self.banner_style = style
        self.error_message = message

    def _show_reset_token_entry(self, sanitized_email: str) -> None:
        self.email = sanitized_email
        self.require_two_factor = False
        self.code_sent = True
        self.reset_token = ""
        self.new_password = ""
        self.confirm_password = ""
        self.verification_code = ""
        self._set_banner("success", _generic_reset_message())

    async def on_primary_action(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Handle the primary button or enter key presses.
        """
        if self._is_processing:
            return

        self._is_processing = True
        self.force_refresh()

        try:
            if self.code_sent:
                await self._update_password()
            else:
                await self._send_reset_token()
        finally:
            self._is_processing = False
            self.force_refresh()

    async def on_resend_code(self, _=None) -> None:
        """
        Allow the user to regenerate a reset token if the previous one expired.
        """
        if self._is_processing:
            return

        self._is_processing = True
        self.force_refresh()

        try:
            await self._send_reset_token()
        finally:
            self._is_processing = False
            self.force_refresh()

    async def _send_reset_token(self) -> None:
        """
        Generate a reset token, persist it, and send it via email.
        """
        try:
            sanitized_email = SecuritySanitizer.validate_email_format(self.email)
        except HTTPException as exc:
            detail = getattr(exc, "detail", "Please provide a valid email address.")
            self._set_banner("danger", str(detail))
            return

        pers = self.session[Persistence]
        request_context = context_from_rio_session(
            self.session,
            identifier=sanitized_email,
        )
        blocked = _consume_rate_limits(
            pers,
            (
                (password_reset_email_policy(), rate_limit_key("identifier", sanitized_email)),
                (password_reset_ip_policy(), rate_limit_key("ip", request_context.client_ip)),
            ),
        )
        if blocked:
            self._set_banner(
                "danger",
                rate_limited_message(
                    "Too many password reset requests.",
                    blocked.retry_after_seconds,
                ),
            )
            return

        try:
            user_info = await pers.get_user_by_identity(identifier=sanitized_email)
        except KeyError:
            # Don't reveal whether the account exists
            self._show_reset_token_entry(sanitized_email)
            return

        if user_info.auth_provider != "password":
            # Don't reveal auth provider details
            self._show_reset_token_entry(sanitized_email)
            return

        try:
            reset_token = await pers.create_reset_token(user_info.id)
        except Exception:
            self._show_reset_token_entry(sanitized_email)
            return

        try:
            send_password_reset_email(
                recipient=sanitized_email,
                token=reset_token.token,
                valid_until=reset_token.valid_until,
            )
        except HTTPException:
            self._show_reset_token_entry(sanitized_email)
            return
        except Exception:
            self._show_reset_token_entry(sanitized_email)
            return

        self._show_reset_token_entry(sanitized_email)

    async def _update_password(self) -> None:
        """
        Validate the reset token and update the user's password.
        """
        try:
            sanitized_email = SecuritySanitizer.validate_email_format(self.email)
        except HTTPException as exc:
            detail = getattr(exc, "detail", "Please provide a valid email address.")
            self._set_banner("danger", str(detail))
            return

        try:
            sanitized_token = SecuritySanitizer.sanitize_auth_code(self.reset_token, max_length=96)
        except HTTPException as exc:
            detail = getattr(exc, "detail", "Invalid reset token.")
            self._set_banner("danger", str(detail))
            return

        if not sanitized_token:
            self._set_banner("danger", "Please enter the reset token that was emailed to you.")
            return

        if not self.new_password:
            self._set_banner("danger", "Please enter a new password.")
            return

        if self.new_password != self.confirm_password:
            self._set_banner("danger", "Passwords do not match.")
            return

        password_policy = evaluate_new_password(
            self.new_password,
            acknowledged_weak=self.acknowledge_weak_password,
        )
        if not password_policy.ok:
            self._set_banner(
                "danger",
                password_policy.message or "Password is not allowed.",
            )
            return

        pers = self.session[Persistence]
        request_context = context_from_rio_session(
            self.session,
            identifier=sanitized_email,
        )
        blocked = _consume_rate_limits(
            pers,
            (
                (password_reset_completion_ip_policy(), rate_limit_key("ip", request_context.client_ip)),
                # This caps retries of the same submitted token. Blind guessing is
                # primarily bounded by the IP bucket above and reset-token entropy.
                (password_reset_token_policy(), token_rate_limit_key(sanitized_token)),
            ),
        )
        if blocked:
            self._set_banner(
                "danger",
                rate_limited_message(
                    "Too many password reset attempts.",
                    blocked.retry_after_seconds,
                ),
            )
            return

        try:
            user = await pers.get_user_by_reset_token(sanitized_token)
        except KeyError:
            self._set_banner("danger", "Invalid or expired reset token. Please request a new one.")
            return

        if user.email.lower() != sanitized_email:
            self._set_banner("danger", "Invalid or expired reset token. Please request a new one.")
            return

        self.require_two_factor = bool(user.two_factor_secret)

        if user.two_factor_secret:
            mfa_key = rate_limit_key("user", user.id)
            blocked = _consume_rate_limits(
                pers,
                ((password_reset_mfa_policy(), mfa_key),),
            )
            if blocked:
                self._set_banner(
                    "danger",
                    rate_limited_message(
                        "Too many two-factor attempts.",
                        blocked.retry_after_seconds,
                    ),
                )
                return

            result = pers.verify_two_factor_challenge(user.id, self.verification_code)
            if not result.ok:
                self._set_banner("danger", result.get_error_message())
                return
            pers.clear_rate_limit(scope=password_reset_mfa_policy().scope, key=mfa_key)

        try:
            consumed = await pers.consume_reset_token_and_update_password(
                sanitized_token,
                user.id,
                self.new_password,
                acknowledged_weak=self.acknowledge_weak_password,
            )
        except Exception:
            self._set_banner("danger", "Failed to update password. Please request a new token and try again.")
            return

        if not consumed:
            self._set_banner("danger", "Reset token has already been used. Please request a new one.")
            return

        self._set_banner(
            "success",
            "Your password has been updated. You can now log in with your new credentials.",
        )
        self.code_sent = False
        self.require_two_factor = False
        self.reset_token = ""
        self.new_password = ""
        self.confirm_password = ""
        self.verification_code = ""

    def on_back_to_login_pressed(self):
        """
        Goes back to the login form.
        """
        if self.on_toggle_form:
            self.on_toggle_form("login")

    async def update_new_password(self, event: rio.TextInputChangeEvent):
        self.new_password = event.text
        self.password_strength = get_password_strength(self.new_password)
        self.do_passwords_match = self.new_password == self.confirm_password
        self.acknowledge_weak_password = False
        self.force_refresh()

    async def update_confirm_password(self, event: rio.TextInputChangeEvent):
        self.confirm_password = event.text
        self.do_passwords_match = self.new_password == self.confirm_password
        self.force_refresh()

    def password_strength_progress(self) -> rio.Component:
        return rio.ProgressBar(
            progress=max(0, min(self.password_strength / 100, 1)),
            color=get_password_strength_color(self.password_strength),
        )

    def build(self) -> rio.Component:
        primary_label = "Update Password" if self.code_sent else "Send Reset Link"

        additional_inputs: list[rio.Component] = []
        if self.code_sent:
            additional_inputs.extend(
                [
                    rio.TextInput(
                        text=self.new_password,
                        label="New password",
                        is_secret=True,
                        on_change=self.update_new_password,
                        on_confirm=self.on_primary_action,
                    ),
                    rio.TextInput(
                        text=self.confirm_password,
                        label="Confirm new password",
                        is_secret=True,
                        is_sensitive=True,
                        on_change=self.update_confirm_password,
                        on_confirm=self.on_primary_action,
                    ),
                    rio.TextInput(
                        text=self.bind().reset_token,
                        label="Email reset token",
                        on_confirm=self.on_primary_action,
                    ),
                ]
            )
            if self.require_two_factor:
                additional_inputs.append(
                    rio.TextInput(
                        text=self.bind().verification_code,
                        label="2FA or recovery code (if enabled)",
                        on_confirm=self.on_primary_action,
                    )
                )

            # Always show password strength indicators when in password reset mode
            additional_inputs.extend(
                [
                    rio.Text(
                        f'Passwords match: {self.do_passwords_match}',
                        style=rio.TextStyle(
                            fill=rio.Color.from_rgb(0, 1, 0, srgb=True)
                            if self.do_passwords_match else rio.Color.from_rgb(1, 0, 0, srgb=True)
                        ),
                    ),
                    rio.Text(
                        f'Password strength: {self.password_strength}, '
                        f'{get_password_strength_status(self.password_strength)}',
                        style=rio.TextStyle(fill=get_password_strength_color(self.password_strength))
                    ),
                    self.password_strength_progress(),
                ]
            )
            if (
                config.ALLOW_WEAK_PASSWORDS
                and self.new_password
                and self.password_strength < config.MIN_PASSWORD_STRENGTH
            ):
                additional_inputs.append(
                    rio.Row(
                        rio.Switch(
                            is_on=self.bind().acknowledge_weak_password,
                        ),
                        rio.Text(
                            "I acknowledge my password is weak",
                            style=rio.TextStyle(
                                fill=rio.Color.from_rgb(1, 0.6, 0, srgb=True),
                            ),
                        ),
                        spacing=1,
                        align_x=0,
                    )
                )

        buttons: list[rio.Component] = [
            rio.Button(
                primary_label,
                on_press=self.on_primary_action,
                is_loading=self._is_processing,
                shape='rounded',
            ),
        ]

        if self.code_sent:
            buttons.append(
                rio.Button(
                    "Resend Link",
                    on_press=self.on_resend_code,
                    is_loading=self._is_processing,
                    shape='rounded',
                )
            )

        buttons.append(
            rio.Button(
                "Back to Login",
                on_press=self.on_back_to_login_pressed,
                shape='rounded',
            )
        )

        return rio.Card(
            rio.Column(
                rio.Text("Reset Password", style="heading1", justify="center"),
                rio.Banner(
                    text=self.error_message,
                    style=self.banner_style,
                    margin_top=1,
                ),
                rio.TextInput(
                    text=self.bind().email,
                    label="Email",
                    on_confirm=self.on_primary_action,
                    is_sensitive=True,
                ),
                *additional_inputs,
                rio.FlowContainer(
                    *buttons,
                    row_spacing=1,
                    column_spacing=1,
                ),
                spacing=1,
                margin=2
            ),
            align_y=0,
        )

################################################################################
# Main LoginPage which toggles between the three forms
################################################################################

@rio.page(
    name="Login",
    url_segment="login",
    guard=guard,
)
class LoginPage(rio.Component):
    """
    The LoginPage decides which form (LoginForm, SignUpForm, or ResetPasswordForm)
    to show based on current_form. It uses a CenterComponent with a single
    child component that is dynamically swapped.
    """

    current_form: str = "login"  # Could be 'login', 'signup', 'reset', or 'social_mfa'
    page_message: str = ""
    page_message_style: str = "success"
    reset_prefilled_email: str = ""
    reset_prefilled_token: str = ""
    reset_prefilled_message: str = ""
    reset_prefilled_message_style: str = "success"
    reset_prefilled_require_two_factor: bool = False
    pending_social_user_id: str = ""

    def _set_page_message(self, style: str, message: str) -> None:
        self.page_message_style = style
        self.page_message = message

    @rio.event.on_populate
    async def on_populate(self) -> None:
        query = self.session.active_page_url.query

        social_token_raw = str(query.get("social_login_token", "")).strip()
        oauth_error = str(query.get("oauth_error", "")).strip()
        verify_token_raw = str(query.get("verify_token", "")).strip()
        reset_token_raw = str(query.get("reset_token", "")).strip()
        if social_token_raw:
            try:
                social_token = SecuritySanitizer.sanitize_auth_code(
                    social_token_raw,
                    max_length=128,
                )
            except HTTPException:
                social_token = None

            if not social_token:
                self.current_form = "login"
                self._set_page_message("danger", "Google sign-in link is invalid.")
                self.force_refresh()
                return

            persistence = self.session[Persistence]
            try:
                user_info = await persistence.consume_oauth_handoff(social_token)
            except KeyError:
                self.current_form = "login"
                self._set_page_message(
                    "danger",
                    "Google sign-in link is invalid or expired. Please try again.",
                )
                self.force_refresh()
                return

            if user_info.two_factor_enabled:
                self.current_form = "social_mfa"
                self.pending_social_user_id = str(user_info.id)
                self._set_page_message("", "")
                self.force_refresh()
                return

            session_created = await _complete_login_session(
                self.session,
                persistence,
                user_info,
            )
            if not session_created:
                self.current_form = "login"
                self._set_page_message(
                    "danger",
                    _account_changed_during_login_message(),
                )
                self.force_refresh()
            return

        if oauth_error:
            self.current_form = "login"
            self._set_page_message("danger", _oauth_error_message(oauth_error))
            self.force_refresh()
            return

        if verify_token_raw:
            try:
                verify_token = SecuritySanitizer.sanitize_auth_code(verify_token_raw, max_length=96)
            except HTTPException:
                verify_token = None

            if not verify_token:
                self.current_form = "login"
                self._set_page_message("danger", "Verification link is invalid. Please request a new email.")
                self.force_refresh()
                return

            persistence = self.session[Persistence]
            try:
                await persistence.consume_email_verification_token(verify_token)
            except KeyError:
                self.current_form = "login"
                self._set_page_message(
                    "danger",
                    "Verification link is invalid or expired. Use 'Resend Verification Email' on login.",
                )
                self.force_refresh()
                return

            self.current_form = "login"
            self._set_page_message("success", "Email verified successfully. You can now log in.")
            self.force_refresh()
            return

        if reset_token_raw:
            persistence = self.session[Persistence]
            try:
                reset_token = SecuritySanitizer.sanitize_auth_code(reset_token_raw, max_length=96)
            except HTTPException:
                reset_token = None

            if not reset_token:
                self.current_form = "reset"
                self._set_page_message("danger", "Reset link is invalid. Request a new password reset email.")
                self.force_refresh()
                return

            self.current_form = "reset"
            self.reset_prefilled_token = ""
            self.reset_prefilled_email = ""
            self.reset_prefilled_message = (
                "Reset link is invalid or expired. Request a new password reset email."
            )
            self.reset_prefilled_message_style = "danger"
            self.reset_prefilled_require_two_factor = False
            try:
                user = await persistence.get_user_by_reset_token(reset_token)
            except KeyError:
                pass
            else:
                self.reset_prefilled_token = reset_token
                self.reset_prefilled_email = user.email
                self.reset_prefilled_message = "Reset link received. Enter your new password below."
                self.reset_prefilled_message_style = "success"
                self.reset_prefilled_require_two_factor = bool(user.two_factor_secret)
            self._set_page_message("", "")
            self.force_refresh()
            return

    def set_form(self, form_name: str):
        """
        Called by child forms to switch between login / signup / reset forms.
        """
        self.current_form = form_name
        if form_name != "reset":
            self.reset_prefilled_email = ""
            self.reset_prefilled_token = ""
            self.reset_prefilled_message = ""
            self.reset_prefilled_message_style = "success"
            self.reset_prefilled_require_two_factor = False
        if form_name != "social_mfa":
            self.pending_social_user_id = ""
        self.force_refresh()

    def build(self) -> rio.Component:
        # Decide which form to show
        if self.current_form == "login":
            form_to_show = LoginForm(on_toggle_form=self.set_form)
        elif self.current_form == "signup":
            form_to_show = SignUpForm(on_toggle_form=self.set_form)
        elif self.current_form == "reset":
            form_to_show = ResetPasswordForm(
                on_toggle_form=self.set_form,
                prefilled_email=self.reset_prefilled_email,
                prefilled_reset_token=self.reset_prefilled_token,
                prefilled_message=self.reset_prefilled_message,
                prefilled_message_style=self.reset_prefilled_message_style,
                prefilled_require_two_factor=self.reset_prefilled_require_two_factor,
            )
        elif self.current_form == "social_mfa":
            form_to_show = SocialMFAForm(
                on_toggle_form=self.set_form,
                pending_user_id=self.pending_social_user_id,
            )
        else:
            # Fallback to login if something weird happens
            form_to_show = LoginForm(on_toggle_form=self.set_form)

        content_children: list[rio.Component] = []
        if self.page_message:
            content_children.append(
                rio.Banner(
                    text=self.page_message,
                    style=self.page_message_style,
                )
            )
        content_children.append(form_to_show)

        return CenterComponent(
            rio.Column(
                *content_children,
                spacing=1,
            ),
            width_percent=WIDTH_NARROW,
            margin_top=10
        )
