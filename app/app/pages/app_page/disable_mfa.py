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

    @rio.event.on_populate
    async def on_populate(self):
        user_session = self.session[UserSession]
        persistence = Persistence()
        user = await persistence.get_user_by_id(user_session.user_id)
        self.two_factor_secret = user.two_factor_secret
        
        if not self.two_factor_secret:
            # User doesn't have 2FA enabled, redirect to settings
            self.session.navigate_to("/app/settings")

            return

    def verify_totp(self):
        totp = pyotp.TOTP(self.two_factor_secret)
        print(f"verifying secret {self.two_factor_secret} with code {self.verification_code}")
        return totp.verify(self.verification_code)

    def _on_totp_entered(self):
        is_code_matching = self.verify_totp()
        print("is_code_matching:", is_code_matching)
        if is_code_matching:
            self.disable_2fa()

    def disable_2fa(self):
        user_session = self.session[UserSession]
        persistence = Persistence()
        print("disable 2fa for", user_session.user_id)
        persistence.set_2fa_secret(user_session.user_id, None)
        self.session.navigate_to("/app/settings")

    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Column(
                rio.Text(
                    "Disable Two-Factor Authentication",
                ),
                rio.Text("Two-factor authentication is currently enabled."),
                rio.Text("To disable 2FA, please enter your 6-digit verification code:"),
                rio.TextInput(
                    text=self.bind().verification_code,
                    label="Enter your 2FA code",
                ),
                rio.Button(
                    "Verify and Disable 2FA",
                    on_press=self._on_totp_entered,
                ),
            ),
            width_percent=50,
            height_percent=50,
        )
