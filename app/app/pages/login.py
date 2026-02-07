from __future__ import annotations

import typing as t

import rio
from fastapi import HTTPException

from app.persistence import Persistence, TwoFactorFailure
from app.data_models import AppUser, UserSettings, RecoveryCodeUsage
from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_NARROW
from app.scripts.utils import (
    get_password_strength,
    get_password_strength_color,
    get_password_strength_status,
)
from app.scripts.message_utils import send_email
from app.validation import SecuritySanitizer
from app.config import config


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

    _currently_logging_in: bool = False

    # We'll expose an event so that the parent page can toggle forms
    on_toggle_form: t.Callable[[str], None] | None = None

    async def login(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Attempt to log in the user, checking 2FA if necessary.
        """
        try:
            self._currently_logging_in = True
            self.force_refresh()

            pers = self.session[Persistence]

            #  Try to find a user with this identifier (email first, username fallback)
            try:
                user_info = await pers.get_user_by_identity(identifier=self.identifier)
            except KeyError:
                self.error_message = "Invalid email. Please try again or create a new account."
                return

            if user_info.auth_provider != "password":
                provider_name = user_info.auth_provider.title()
                self.error_message = (
                    f"This account is configured for {provider_name} sign-in. Please continue with that provider."
                )
                return

            # Make sure their password matches
            if not user_info.verify_password(self.password):
                self.error_message = "Invalid password. Please try again or create a new account."
                return

            # Check if 2FA is enabled for this user
            recovery_code_used = False
            if user_info.two_factor_enabled:
                result = pers.verify_two_factor_challenge(user_info.id, self.verification_code)
                if not result.ok:
                    if result.failure == TwoFactorFailure.INVALID_FORMAT:
                        self.error_message = result.failure_detail or "Invalid authentication code."
                        return
                    if result.failure == TwoFactorFailure.MISSING_CODE:
                        self.error_message = (
                            "2FA is enabled for this account. Please enter your verification or recovery code."
                        )
                        return
                    self.error_message = "Invalid verification or recovery code. Please try again."
                    return
                recovery_code_used = result.used_recovery_code

            # The login was successful
            self.error_message = ""

            # Create and store a session
            user_session = await pers.create_session(user_id=user_info.id)
            self.session.attach(user_session)
            self.session.attach(user_info)

            settings = self.session[UserSettings]
            settings.auth_token = user_session.id
            self.session.attach(settings)

            if recovery_code_used:
                try:
                    usage = self.session[RecoveryCodeUsage]
                except KeyError:
                    usage = RecoveryCodeUsage()
                    self.session.attach(usage)
                usage.used_at_login = True

            self.session.navigate_to("/app/dashboard")

        finally:
            self._currently_logging_in = False

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

    def build(self) -> rio.Component:
        return rio.Card(
            rio.Column(
                rio.Text("Login", style="heading1", justify="center"),
                rio.Banner(
                    text=self.error_message,
                    style="danger",
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
                    row_spacing=1,
                    column_spacing=1,
                ),
                spacing=1,
                margin=2,
            ),
            align_y=0,
        )

class SignUpForm(rio.Component):
    """
    Provides interface for users to sign up for a new account.

    Email addresses are treated as the primary identifier. Usernames can be
    layered on in future use-cases without rewriting this form because the
    backend exposes both email and username lookups.
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

        # BACKEND VALIDATION: Enforce email validation if configured
        if config.REQUIRE_VALID_EMAIL:
            try:
                SecuritySanitizer.validate_email_format(self.email, require_valid=True)
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

        # Check password strength — allow weak passwords only if acknowledged
        strength = get_password_strength(self.password)
        if strength < config.MIN_PASSWORD_STRENGTH and not self.acknowledge_weak_password:
            self.banner_style = "danger"
            self.error_message = "Your password is weak. Please acknowledge this below or choose a stronger password."
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
            # Good news, we can create the user
            self.banner_style = "success"
            self.error_message = "Congratulations! You have successfully signed up. Please log in."
            pass

        # Create a new user
        user_info = AppUser.create_new_user_with_default_settings(
            email=self.email,
            password=self.password,
            referral_code=self.referral_code,
        )

        # Store the user in the database
        await pers.create_user(user_info)

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
                        fill=rio.Color.from_rgb(0, 1, 0)
                        if self.is_email_valid else rio.Color.from_rgb(1, 0, 0)
                    )
                ),
                rio.Text(
                    f'Passwords match: {self.do_passwords_match}',
                    style=rio.TextStyle(
                        fill=rio.Color.from_rgb(0, 1, 0)
                        if self.do_passwords_match else rio.Color.from_rgb(1, 0, 0)
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
                                    fill=rio.Color.from_rgb(1, 0.6, 0),
                                ),
                            ),
                            spacing=1,
                            align_x=0,
                        ),
                    ]
                    if self.password and self.password_strength < config.MIN_PASSWORD_STRENGTH
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
                spacing=1,
                margin=2,
            ),
            align_y=0,
        )

class ResetPasswordForm(rio.Component):
    """
    Provides an interface for resetting the user's password with a one-time code.
    """

    email: str = ""
    reset_code: str = ""
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

    # We'll expose an event so that the parent page can toggle forms
    on_toggle_form: t.Callable[[str], None] | None = None

    def _set_banner(self, style: str, message: str) -> None:
        self.banner_style = style
        self.error_message = message

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
                await self._send_reset_code()
        finally:
            self._is_processing = False
            self.force_refresh()

    async def on_resend_code(self, _=None) -> None:
        """
        Allow the user to regenerate a reset code if the previous one expired.
        """
        if self._is_processing:
            return

        self._is_processing = True
        self.force_refresh()

        try:
            await self._send_reset_code()
        finally:
            self._is_processing = False
            self.force_refresh()

    async def _send_reset_code(self) -> None:
        """
        Generate a reset code, persist it, and send it via email.
        """
        try:
            sanitized_email = SecuritySanitizer.validate_email_format(self.email)
        except HTTPException as exc:
            detail = getattr(exc, "detail", "Please provide a valid email address.")
            self._set_banner("danger", str(detail))
            return

        pers = self.session[Persistence]

        try:
            user_info = await pers.get_user_by_identity(identifier=sanitized_email)
        except KeyError:
            self._set_banner("danger", "No account found with that email address. Please try again.")
            return

        if user_info.auth_provider != "password":
            provider_name = user_info.auth_provider.title()
            self._set_banner(
                "danger",
                f"This account is configured for {provider_name} sign-in. Please continue with that provider.",
            )
            return

        try:
            reset_code = await pers.create_reset_code(user_info.id)
        except Exception:
            self._set_banner("danger", "We were unable to create a reset code. Please try again.")
            return

        email_body = (
            "Hi,\n\n"
            f"Your password reset code is {reset_code.code}. Enter this code in the Rio app to choose a new password.\n\n"
            f"This code expires on {reset_code.valid_until.strftime('%Y-%m-%d %H:%M %Z')}.\n\n"
            "If you did not request this code, you can ignore this email."
        )

        try:
            send_email(
                recipient=sanitized_email,
                subject="Your Rio password reset code",
                body=email_body,
            )
        except HTTPException as exc:
            detail = getattr(exc, "detail", "Failed to send reset email.")
            self._set_banner("danger", str(detail))
            return
        except Exception:
            self._set_banner("danger", "Failed to send reset email. Please try again.")
            return

        self.email = sanitized_email
        self.require_two_factor = bool(user_info.two_factor_secret)
        self.code_sent = True
        self.reset_code = ""
        self.new_password = ""
        self.confirm_password = ""
        self.verification_code = ""
        self._set_banner(
            "success",
            "We've emailed a reset code. Enter it below along with your new password.",
        )

    async def _update_password(self) -> None:
        """
        Validate the reset code and update the user's password.
        """
        try:
            sanitized_email = SecuritySanitizer.validate_email_format(self.email)
        except HTTPException as exc:
            detail = getattr(exc, "detail", "Please provide a valid email address.")
            self._set_banner("danger", str(detail))
            return

        try:
            sanitized_code = SecuritySanitizer.sanitize_auth_code(self.reset_code, max_length=12)
        except HTTPException as exc:
            detail = getattr(exc, "detail", "Invalid reset code.")
            self._set_banner("danger", str(detail))
            return

        if not sanitized_code:
            self._set_banner("danger", "Please enter the reset code that was emailed to you.")
            return

        if not self.new_password:
            self._set_banner("danger", "Please enter a new password.")
            return

        if self.new_password != self.confirm_password:
            self._set_banner("danger", "Passwords do not match.")
            return

        strength = get_password_strength(self.new_password)
        if strength < config.MIN_PASSWORD_STRENGTH and not self.acknowledge_weak_password:
            self._set_banner(
                "danger",
                "Your password is weak. Please acknowledge this below or choose a stronger password.",
            )
            return

        pers = self.session[Persistence]

        try:
            user = await pers.get_user_by_reset_code(sanitized_code)
        except KeyError:
            self._set_banner("danger", "Invalid or expired reset code. Please request a new one.")
            return

        if user.email.lower() != sanitized_email:
            self._set_banner("danger", "Reset code does not match this email address.")
            return

        self.require_two_factor = bool(user.two_factor_secret)

        if user.two_factor_secret:
            result = pers.verify_two_factor_challenge(user.id, self.verification_code)
            if not result.ok:
                if result.failure == TwoFactorFailure.INVALID_FORMAT:
                    self._set_banner(
                        "danger",
                        result.failure_detail or "Invalid verification code.",
                    )
                    return
                if result.failure == TwoFactorFailure.MISSING_CODE:
                    self._set_banner(
                        "danger",
                        "2FA is enabled for this account. Please enter your verification or recovery code.",
                    )
                    return
                self._set_banner(
                    "danger",
                    "Invalid verification or recovery code.",
                )
                return

        consumed = await pers.consume_reset_code(sanitized_code, user.id)
        if not consumed:
            self._set_banner("danger", "Reset code has already been used. Please request a new one.")
            return

        try:
            await pers.update_password(user.id, self.new_password)
        except Exception:
            self._set_banner("danger", "Failed to update password. Please request a new code and try again.")
            return

        self._set_banner(
            "success",
            "Your password has been updated. You can now log in with your new credentials.",
        )
        self.code_sent = False
        self.require_two_factor = False
        self.reset_code = ""
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
        primary_label = "Update Password" if self.code_sent else "Send Reset Code"
        strength = get_password_strength(self.new_password) if self.code_sent else 0

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
                        text=self.bind().reset_code,
                        label="Email reset code",
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
                            fill=rio.Color.from_rgb(0, 1, 0)
                            if self.do_passwords_match else rio.Color.from_rgb(1, 0, 0)
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
            if self.new_password and self.password_strength < config.MIN_PASSWORD_STRENGTH:
                additional_inputs.append(
                    rio.Row(
                        rio.Switch(
                            is_on=self.bind().acknowledge_weak_password,
                        ),
                        rio.Text(
                            "I acknowledge my password is weak",
                            style=rio.TextStyle(
                                fill=rio.Color.from_rgb(1, 0.6, 0),
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
                    "Resend Code",
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

    current_form: str = "login"  # Could be 'login', 'signup', or 'reset'

    def set_form(self, form_name: str):
        """
        Called by child forms to switch between login / signup / reset forms.
        """
        self.current_form = form_name
        self.force_refresh()

    def build(self) -> rio.Component:
        # Decide which form to show
        if self.current_form == "login":
            form_to_show = LoginForm(on_toggle_form=self.set_form)
        elif self.current_form == "signup":
            form_to_show = SignUpForm(on_toggle_form=self.set_form)
        elif self.current_form == "reset":
            form_to_show = ResetPasswordForm(on_toggle_form=self.set_form)
        else:
            # Fallback to login if something weird happens
            form_to_show = LoginForm(on_toggle_form=self.set_form)

        return CenterComponent(
            # Show the chosen form
            form_to_show,
            width_percent=WIDTH_NARROW,
            # height_percent=40,
            margin_top=10
        )
