from __future__ import annotations

import typing as t
from dataclasses import KW_ONLY, field

import re
import pyotp

import rio

from app.persistence import Persistence
from app.data_models import AppUser, UserSettings
from app.components.center_component import CenterComponent
from app.scripts.utils import (
    get_password_strength,
    get_password_strength_color,
    get_password_strength_status,
)


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

    return "/home"


################################################################################
# Segmented Forms
################################################################################

class LoginForm(rio.Component):
    """
    This Component handles the login flow, including 2FA verification if needed.
    """

    username: str = ""
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

            #  Try to find a user with this name
            try:
                user_info = await pers.get_user_by_username(username=self.username)
            except KeyError:
                self.error_message = "Invalid username. Please try again or create a new account."
                return

            # Make sure their password matches
            if not user_info.verify_password(self.password):
                self.error_message = "Invalid password. Please try again or create a new account."
                return

            # Check if 2FA is enabled for this user
            if user_info.two_factor_secret:
                if not self.verification_code:
                    self.error_message = "2FA is enabled for this account. Please enter your verification code."
                    return

                # Verify the TOTP code
                totp = pyotp.TOTP(user_info.two_factor_secret)
                if not totp.verify(self.verification_code):
                    self.error_message = "Invalid verification code. Please try again."
                    return

            # The login was successful
            self.error_message = ""

            # Create and store a session
            user_session = await pers.create_session(user_id=user_info.id)
            self.session.attach(user_session)
            self.session.attach(user_info)

            settings = self.session[UserSettings]
            settings.auth_token = user_session.id
            self.session.attach(settings)

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
                    text=self.bind().username,
                    label="Email/Username",
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
                    label="2FA Code (if applicable)",
                    on_confirm=self.login,
                ),
                rio.Row(
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
                        "Forgot Password?",
                        on_press=self.on_reset_password_button_pressed,
                        shape='rounded',
                    ),
                    spacing=2
                ),
                spacing=1,
                margin=2,
            ),
            align_y=0,
        )

class SignUpForm(rio.Component):
    """
    Provides interface for users to sign up for a new account.

    It includes fields for username and password, handles user creation, and
    displays error messages if the sign-up process fails.
    """

    # Fields
    email: str = ""
    password: str = ""
    confirm_password: str = ""
    error_message: str = ""
    banner_style: str = "danger"
    is_email_valid: bool = False
    passwords_valid: bool = False
    password_strength: int = 0
    do_passwords_match: bool = False

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
            self.error_message = "Please fill in all fields"
            self.passwords_valid = False
            self.is_email_valid = False
            return

        # Check if the passwords match
        if self.password != self.confirm_password:
            self.error_message = "Passwords do not match"
            self.passwords_valid = False
            self.is_email_valid = True
            return

        # Check if the user already exists
        try:
            await pers.get_user_by_username(username=self.email)
            self.error_message = "This username is already taken"
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
            username=self.email,
            password=self.password,
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
        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        self.is_email_valid = bool(email and re.match(email_regex, email))

    async def update_email(self, event: rio.TextInputChangeEvent):
        self.email = event.text
        self.validate_email(self.email)
        self.force_refresh()

    async def update_password(self, event: rio.TextInputChangeEvent):
        self.password = event.text
        self.password_strength = get_password_strength(self.password)
        self.do_passwords_match = self.password == self.confirm_password
        self.force_refresh()

    async def update_confirm_password(self, event: rio.TextInputChangeEvent):
        self.confirm_password = event.text
        self.do_passwords_match = self.password == self.confirm_password
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
                rio.Row(
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
                    spacing=2
                ),
                spacing=1,
                margin=2,
            ),
            align_y=0,
        )

class ResetPasswordForm(rio.Component):
    """
    Provides an interface for resetting the user’s password.
    User enters their email/username, then clicks reset.
    """

    username_or_email: str = ""
    error_message: str = ""
    banner_style: str = "danger"

    # We'll expose an event so that the parent page can toggle forms
    on_toggle_form: t.Callable[[str], None] | None = None

    async def on_reset_password_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Handles sending a password reset request to the user’s email.
        You’d typically generate a token, email the user, etc.
        """
        if not self.username_or_email:
            self.error_message = "Please enter your username or email."
            return

        # Here you can do your typical "get user by email" logic
        pers = self.session[Persistence]
        try:
            user_info = await pers.get_user_by_username(username=self.username_or_email)
            # If user is found, you'd trigger an email or some method of resetting password
            # For now, let’s just simulate success.
            self.banner_style = "success"
            self.error_message = (
                "A password reset link has been sent to your email (simulated)."
            )
        except KeyError:
            banner_style = "danger"
            self.error_message = (
                "No account found with that username or email. Please try again."
            )

    def on_back_to_login_pressed(self):
        """
        Goes back to the login form.
        """
        if self.on_toggle_form:
            self.on_toggle_form("login")

    def build(self) -> rio.Component:
        return rio.Card(
            rio.Column(
                rio.Text("Reset Password", style="heading1", justify="center"),
                rio.Banner(
                    text=self.error_message,
                    style=self.banner_style,
                    margin_top=1,
                ),
                rio.TextInput(
                    text=self.bind().username_or_email,
                    label="Username / Email",
                    on_confirm=self.on_reset_password_pressed,
                ),
                rio.Row(
                    rio.Button(
                        "Reset Password",
                        on_press=self.on_reset_password_pressed,
                        shape='rounded',
                    ),
                    rio.Button(
                        "Back to Login",
                        on_press=self.on_back_to_login_pressed,
                        shape='rounded',
                    ),
                    spacing=2
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
            width_percent=30,
            # height_percent=40,
            margin_top=10
        )
