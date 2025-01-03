from __future__ import annotations

import pyotp
import rio

from app.data_models import UserSession
from app.persistence import Persistence
from app.components.center_component import CenterComponent


@rio.page(
    name="Disable Two-Factor Authentication",
    url_segment="disable-mfa",
)
class DisableMFA(rio.Component):
    """Two-factor authentication disable page."""

    two_factor_secret: str | None = None
    verification_code: str = ""
    error_message: str = ""

    @rio.event.on_populate
    async def on_populate(self):
        user_session = self.session[UserSession]
        persistence = Persistence()
        user = await persistence.get_user_by_id(user_session.user_id)
        self.two_factor_secret = user.two_factor_secret

        # If the user does not have a secret, redirect them
        if not self.two_factor_secret:
            self.session.navigate_to("/app/settings")

    def verify_totp(self) -> bool:
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(self.verification_code)

    def _on_totp_entered(self):
        is_code_matching = self.verify_totp()
        if is_code_matching:
            self.disable_2fa()
        else:
            self.error_message = "Invalid verification code. Please try again."
            self.force_refresh()

    def disable_2fa(self):
        user_session = self.session[UserSession]
        persistence = Persistence()
        persistence.set_2fa_secret(user_session.user_id, None)
        self.session.navigate_to("/app/settings")

    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Card(
                rio.Column(
                    rio.Text("Disable Two-Factor Authentication", style="heading1", justify="center"),
                    rio.Banner(text=self.error_message, style="danger", margin_top=1),
                    rio.Text("Two-factor authentication is currently enabled."),
                    rio.Text("To disable 2FA, please enter your 6-digit verification code:"),
                    rio.TextInput(
                        text=self.bind().verification_code,
                        label="Enter your 2FA code",
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
            width_percent=50,
            height_percent=50,
        )
