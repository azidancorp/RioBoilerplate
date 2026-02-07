from __future__ import annotations

import rio

from app.data_models import UserSession
from app.persistence import Persistence, TwoFactorFailure
from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_COMFORTABLE


@rio.page(
    name="Disable Two-Factor Authentication",
    url_segment="disable-mfa",
)
class DisableMFA(rio.Component):
    """Two-factor authentication disable page."""

    password: str = ""
    two_factor_enabled: bool = False
    verification_code: str = ""
    error_message: str = ""

    @rio.event.on_populate
    async def on_populate(self):
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        user = await persistence.get_user_by_id(user_session.user_id)
        self.two_factor_enabled = user.two_factor_enabled

        # If the user does not have a secret, redirect them
        if not self.two_factor_enabled:
            self.session.navigate_to("/app/settings")

    async def _on_totp_entered(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Verify password and 2FA or recovery code before disabling 2FA.
        """
        # Validate password first
        if not self.password:
            self.error_message = "Please enter your password to disable 2FA."
            self.force_refresh()
            return

        # Get user and verify password
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        user = await persistence.get_user_by_id(user_session.user_id)

        if not user.verify_password(self.password):
            self.error_message = "Invalid password. Please try again."
            self.force_refresh()
            return

        result = persistence.verify_two_factor_challenge(
            user_session.user_id,
            self.verification_code,
        )
        if not result.ok:
            if result.failure == TwoFactorFailure.INVALID_FORMAT:
                self.error_message = result.failure_detail or "Invalid 2FA or recovery code format."
            elif result.failure == TwoFactorFailure.MISSING_CODE:
                self.error_message = "Please enter a 2FA code or recovery code."
            else:
                self.error_message = "Invalid verification or recovery code. Please try again."
            self.force_refresh()
            return

        self.disable_2fa()

    def disable_2fa(self):
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        persistence.set_2fa_secret(user_session.user_id, None)
        self.session.navigate_to("/app/settings")

    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Card(
                rio.Column(
                    rio.Text("Disable Two-Factor Authentication", style="heading1", justify="center"),
                    rio.Banner(text=self.error_message, style="danger", margin_top=1),
                    rio.Text("Two-factor authentication is currently enabled."),
                    rio.Text("To disable 2FA, please enter your password and 2FA code:"),
                    rio.TextInput(
                        text=self.bind().password,
                        label="Enter your password",
                        is_secret=True,
                        on_confirm=self._on_totp_entered,
                    ),
                    rio.TextInput(
                        text=self.bind().verification_code,
                        label="Enter your 2FA or recovery code",
                        on_confirm=self._on_totp_entered,
                    ),
                    rio.Row(
                        rio.Button(
                            "Verify and Disable 2FA",
                            on_press=self._on_totp_entered,
                            shape='rounded'
                        ),
                        spacing=2
                    ),
                    spacing=1,
                    margin=2,
                ),
                align_y=0,
            ),
            width_percent=WIDTH_COMFORTABLE,
            height_percent=50,
        )
