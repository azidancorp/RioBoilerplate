from __future__ import annotations

import io
import base64
from dataclasses import KW_ONLY
import qrcode
import pyotp
import rio
from rio.component_meta import C

from app.data_models import UserSession
from app.persistence import Persistence
from app.components.center_component import CenterComponent


@rio.page(
    name="Enable Two-Factor Authentication",
    url_segment="enable-mfa",
)
class EnableMFA(rio.Component):
    """Two-factor authentication setup page."""

    temporary_two_factor_secret: str = ""
    verification_code: str = ""
    qr_code_image_bytes: bytes | None = None
    secret: str | None = None
    error_message: str = ""

    # Cleanup method removed as QR codes are now generated in memory

    @rio.event.on_populate
    async def on_populate(self):
        user_session = self.session[UserSession]
        persistence = Persistence()
        user = await persistence.get_user_by_id(user_session.user_id)

        # If the user already has a 2FA secret, redirect them
        if user.two_factor_secret:
            self.session.navigate_to("/app/settings")
        
        # create a new 2FA secret
        self.temporary_two_factor_secret = pyotp.random_base32()

        # Generate a QR code for the secret
        totp_uri = pyotp.TOTP(self.temporary_two_factor_secret).provisioning_uri(
            name=f"{user.username}:{user.id}",
            issuer_name="RioBase"
        )

        # Generate QR in memory
        img = qrcode.make(totp_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        self.qr_code_image_bytes = buffer.getvalue()

    def verify_totp(self) -> bool:
        totp = pyotp.TOTP(self.temporary_two_factor_secret)
        return totp.verify(self.verification_code)

    def _on_totp_entered(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Called when user presses "Verify" button.
        """
        is_code_matching = self.verify_totp()
        if is_code_matching:
            self.set_totp_secret_in_db()
        else:
            self.error_message = "Invalid verification code. Please try again."
            self.force_refresh()

    def set_totp_secret_in_db(self, _=None):
        """
        Persists the user's TOTP secret.
        """
        secret = self.temporary_two_factor_secret
        user_session = self.session[UserSession]
        persistence = Persistence()
        persistence.set_2fa_secret(user_session.user_id, secret)
        
        self.session.navigate_to("/app/settings")

    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Card(
                rio.Column(
                    rio.Text("Enable Two-Factor Authentication", style="heading1", justify="center"),
                    rio.Banner(text=self.error_message, style="danger", margin_top=1),
                    rio.Text("To enable 2FA, please scan the QR code below."),
                    *(
                        [rio.Image(
                            self.qr_code_image_bytes,
                            fill_mode="fit",
                            min_width=20,
                            min_height=20,
                            corner_radius=2,
                        )] if self.qr_code_image_bytes else [rio.Text("Generating QR code...")]
                    ),
                    rio.Text("Or enter the 2FA secret manually:"),
                    rio.Text(self.temporary_two_factor_secret),
                    rio.TextInput(
                        text=self.bind().verification_code,
                        label="Enter your 2FA code",
                        on_confirm=self._on_totp_entered,
                    ),
                    rio.Row(
                        rio.Button(
                            "Verify",
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
        )
