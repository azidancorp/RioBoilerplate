from __future__ import annotations

import typing as t
import rio
import re

from app.persistence import Persistence
from app.data_models import AppUser
from app.components.center_component import CenterComponent
from app.scripts.utils import (
    get_password_strength,
    get_password_strength_color,
    get_password_strength_status,
)
from app.validation import SecuritySanitizer

@rio.page(
    name="Reset Password",
    url_segment="reset-password",
)
class ResetPasswordPage(rio.Component):
    """
    This Page allows a user to reset their password using a temporary code
    (sent via email or some other method). The user inputs the temporary code,
    then enters a new password and confirms it. We display the password strength
    just like in the Sign Up form, following the same style.
    """

    # Fields
    reset_code: str = ""
    new_password: str = ""
    confirm_password: str = ""
    error_message: str = ""
    password_strength: int = 0
    do_passwords_match: bool = False

    async def on_reset_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Verifies the reset code, checks if the new password/confirm password
        match, and if so, updates the user's password in the database.
        """
        if not self.reset_code or not self.new_password or not self.confirm_password:
            self.error_message = "Please fill out all fields."
            return

        # Validate and sanitize reset code
        try:
            sanitized_reset_code = SecuritySanitizer.sanitize_string(self.reset_code, 100)
            if not sanitized_reset_code:
                self.error_message = "Invalid reset code format."
                return
            
            # Update the reset code with sanitized value
            self.reset_code = sanitized_reset_code
            
        except Exception:
            self.error_message = "Invalid reset code format."
            return

        # Check if the passwords match
        if self.new_password != self.confirm_password:
            self.error_message = "New password and confirmation do not match."
            return

        # Get the persistence instance from the session
        pers = self.session[Persistence]

        try:
            # Attempt to find a user by their reset code
            # Note: get_user_by_reset_code needs to be implemented in persistence.py
            user_info = await pers.get_user_by_reset_code(code=self.reset_code)
            
            # Update the password using our new function
            await pers.update_password(user_info.id, self.new_password)
            
            # Clear the reset code
            # Note: clear_reset_code needs to be implemented in persistence.py
            await pers.clear_reset_code(user_info.id)
            
            # Clear form and redirect to login
            self.reset_code = ""
            self.new_password = ""
            self.confirm_password = ""
            self.error_message = ""
            self.session.navigate_to("/app/login")
            
        except KeyError:
            self.error_message = "Invalid or expired reset code."
        except Exception as e:
            self.error_message = f"Failed to reset password: {str(e)}"

    async def update_new_password(self, event: rio.TextInputChangeEvent):
        """
        Called whenever the 'new password' field changes.
        We recalculate password strength, check if the two passwords match, etc.
        """
        self.new_password = event.text
        self.password_strength = get_password_strength(self.new_password)
        self.do_passwords_match = (self.new_password == self.confirm_password)
        self.force_refresh()

    async def update_confirm_password(self, event: rio.TextInputChangeEvent):
        """
        Called whenever the 'confirm password' field changes.
        We check if the two passwords match, etc.
        """
        self.confirm_password = event.text
        self.do_passwords_match = (self.new_password == self.confirm_password)
        self.force_refresh()

    def password_strength_progress(self) -> rio.Component:
        """
        Renders the progress bar that indicates the strength of the password.
        Same approach as used in SignUpForm from login.py.
        """
        return rio.ProgressBar(
            progress=max(0, min(self.password_strength / 100, 1)),
            color=get_password_strength_color(self.password_strength),
        )

    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Card(
                rio.Column(
                    rio.Text("Reset Your Password", style="heading1", justify="center"),
                    # Display an error, if any
                    rio.Banner(
                        text=self.error_message,
                        style="danger" if self.error_message else "info",
                        margin_top=1,
                    ),
                    rio.TextInput(
                        text=self.bind().reset_code,
                        label="Temporary Code",
                        on_confirm=self.on_reset_pressed,
                        is_secret=False,
                    ),
                    rio.TextInput(
                        text=self.new_password,
                        label="New Password",
                        on_change=self.update_new_password,
                        is_secret=True,
                        on_confirm=self.on_reset_pressed,
                    ),
                    rio.TextInput(
                        text=self.confirm_password,
                        label="Confirm New Password",
                        on_change=self.update_confirm_password,
                        is_secret=True,
                        on_confirm=self.on_reset_pressed,
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
                            "Reset Password",
                            on_press=self.on_reset_pressed,
                            shape='rounded',
                        ),
                        spacing=2,
                    ),
                    spacing=1,
                    margin=2,
                ),
                align_y=0,
            ),
            width_percent=30,
            margin_top=10,
        )
