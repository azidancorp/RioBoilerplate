from __future__ import annotations

import io
import base64
from dataclasses import KW_ONLY
import qrcode
import pyotp
import rio
from pathlib import Path
from rio.component_meta import C
from datetime import datetime

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
    qr_code_path: Path | None = None
    secret: str | None = None

    @rio.event.on_populate
    async def on_populate(self):
        user_session = self.session[UserSession]
        persistence = Persistence()
        user = await persistence.get_user_by_id(user_session.user_id)
        if user.two_factor_secret:
            # User already has 2FA enabled, redirect to settings
            self.session.navigate_to("/app/settings")

        
        # create a new 2FA secret
        self.temporary_two_factor_secret = pyotp.random_base32()
        
        # generate a QR code for the secret
        totp_uri = pyotp.TOTP(self.temporary_two_factor_secret).provisioning_uri(
            name=f"{user.username}:{user.id}",
            issuer_name="RioBase"
        )
        
        
        # Store the base64 image data
        print(totp_uri)
        img = qrcode.make(totp_uri)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%SZ")  # Current timestamp
        filename = f"{timestamp}_{self.temporary_two_factor_secret}.png"
        filepath = f"app/assets/mfa_qr_codes/{filename}"  # Relative path from app root
        
        img.save(filepath)
        self.qr_code_path = Path(self.session.assets / "mfa_qr_codes" / filename)
        
        print(f"QR code saved to: {filepath}")
        
        # self.force_refresh()






    def verify_totp(self):
        totp = pyotp.TOTP(self.temporary_two_factor_secret)
        print(f"verifying secret {self.temporary_two_factor_secret} with code {self.verification_code}")
        return totp.verify(self.verification_code)
    
    def _on_totp_entered(self):
        is_code_matching = self.verify_totp()
        print("is_code_matching:", is_code_matching)
        if is_code_matching:
            self.set_totp_secret_in_db()
            

    def set_totp_secret_in_db(self, _=None):
        secret = self.temporary_two_factor_secret
        user_session = self.session[UserSession]
        persistence = Persistence()
        persistence.set_2fa_secret(user_session.user_id, secret)
        print("new secret:", secret)
        self.session.navigate_to("/app/settings")


    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Column(
                rio.Text(
                    "Enable Two-Factor Authentication",
                ),
                rio.Text("To enable 2FA, please scan the QR code below."),
                *(
                    [rio.Image(
                        self.qr_code_path,
                        fill_mode="fit",
                        min_width=20,
                        min_height=20,
                        corner_radius=2,
                    )] if self.qr_code_path else [rio.Text("Generating QR code...")]
                ),
                rio.Text("Or enter the 2FA secret manually:"),
                rio.Text(self.temporary_two_factor_secret),
                rio.TextInput(
                    text=self.bind().verification_code,
                    label="Enter your 2FA code",
                ),
                rio.Button(
                    "Verify",
                    on_press=self._on_totp_entered,
                ),
            ),
            width_percent=50,
            height_percent=50,
        )
