from __future__ import annotations

import io
import qrcode
import pyotp
import rio

from app.persistence import Persistence
from app.request_context import context_from_rio_session
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import require_fresh_user_session
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_COMFORTABLE
from app.validation import SecuritySanitizer


@rio.page(
    name="Enable Two-Factor Authentication",
    url_segment="enable-mfa",
)
class EnableMFA(ResponsiveComponent):
    """Two-factor authentication setup page."""

    password: str = ""
    temporary_two_factor_secret: str = ""
    verification_code: str = ""
    qr_code_image_bytes: bytes | None = None
    secret: str | None = None
    error_message: str = ""
    recovery_codes: tuple[str, ...] = ()
    show_recovery_codes: bool = False

    # Cleanup method removed as QR codes are now generated in memory

    @rio.event.on_populate
    async def on_populate(self):
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        _, user = fresh_session

        # If the user already has a 2FA secret, redirect them
        if user.two_factor_secret:
            self.session.navigate_to("/app/settings")

        # create a new 2FA secret
        self.temporary_two_factor_secret = pyotp.random_base32()
        self.recovery_codes = ()
        self.show_recovery_codes = False

        # Generate a QR code for the secret
        totp_uri = pyotp.TOTP(self.temporary_two_factor_secret).provisioning_uri(
            name=f"{(user.username or user.email)}:{user.id}",
            issuer_name="RioBase"
        )

        # Generate QR in memory
        img = qrcode.make(totp_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        self.qr_code_image_bytes = buffer.getvalue()

    def verify_totp(self) -> bool:
        candidate = self.verification_code.replace("-", "")
        totp = pyotp.TOTP(self.temporary_two_factor_secret)
        return candidate.isdigit() and totp.verify(candidate)

    async def _on_totp_entered(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Called when user presses "Verify" button.
        Requires password verification before enabling 2FA.
        """
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        persistence = self.session[Persistence]

        # Validate password first
        if not self.password:
            self.error_message = "Please enter your password to enable 2FA."
            self.force_refresh()
            return

        context = context_from_rio_session(self.session, user_id=user_session.user_id)
        limit_key = rate_limit_key("mfa_enable", context.user_id or context.session_id or context.client_ip)
        decision = persistence.check_rate_limit(
            policy=sensitive_action_policy("mfa_enable"),
            key=limit_key,
        )
        if not decision.allowed:
            self.error_message = rate_limited_message(
                "Too many two-factor setup attempts.",
                decision.retry_after_seconds,
            )
            self.force_refresh()
            return

        if not user.verify_password(self.password):
            self.error_message = "Invalid password. Please try again."
            self.force_refresh()
            return

        try:
            sanitized_code = SecuritySanitizer.sanitize_auth_code(self.verification_code)
        except Exception:
            self.error_message = "Invalid verification code format."
            self.force_refresh()
            return

        if not sanitized_code:
            self.error_message = "Please enter your 2FA verification code."
            self.force_refresh()
            return

        self.verification_code = sanitized_code

        # Verify TOTP code
        is_code_matching = self.verify_totp()
        if is_code_matching:
            persistence.clear_rate_limit(
                scope=sensitive_action_policy("mfa_enable").scope,
                key=limit_key,
            )
            self.set_totp_secret_in_db()
        else:
            self.error_message = "Invalid verification code. Please try again."
            self.force_refresh()

    def set_totp_secret_in_db(self, _=None) -> None:
        """
        Persists the user's TOTP secret.
        """
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, _ = fresh_session
        secret = self.temporary_two_factor_secret
        persistence = self.session[Persistence]
        persistence.set_2fa_secret(user_session.user_id, secret)

        recovery_codes = persistence.generate_recovery_codes(user_session.user_id)
        self.recovery_codes = tuple(recovery_codes)
        self.show_recovery_codes = True
        self.error_message = ""
        self.password = ""
        self.verification_code = ""
        self.force_refresh()

    def _on_acknowledge_recovery_codes(self, _event=None) -> None:
        """Navigate back to settings after the user confirms they've stored the codes."""
        self.session.navigate_to("/app/settings")

    def build(self) -> rio.Component:
        if self.show_recovery_codes:
            return CenterComponent(
                rio.Card(
                    rio.Column(
                        rio.Text("Recovery Codes", style="heading1", justify="center"),
                        rio.Text(
                            "Two-factor authentication is now enabled. Store these recovery codes somewhere safe. "
                            "Each code can be used once if you lose access to your authenticator app.",
                            margin_bottom=1,
                        ),
                        rio.Column(
                            *(rio.Text(code) for code in self.recovery_codes),
                            spacing=0.5,
                            margin_bottom=1.5,
                        ),
                        rio.Text(
                            "You will not be able to see these codes again once you leave this page.",
                            margin_bottom=1,
                        ),
                        rio.Button(
                            "I have saved my recovery codes",
                            on_press=self._on_acknowledge_recovery_codes,
                            shape="rounded",
                        ),
                        spacing=1.5,
                        margin=2,
                    ),
                    align_y=0,
                ),
                width_percent=WIDTH_COMFORTABLE,
            )

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
                            min_height=20,
                            corner_radius=2,
                        )] if self.qr_code_image_bytes else [rio.Text("Generating QR code...")]
                    ),
                    rio.Text("Or enter the 2FA secret manually:"),
                    rio.Text(self.temporary_two_factor_secret),
                    rio.TextInput(
                        text=self.bind().password,
                        label="Enter your password",
                        is_secret=True,
                        on_confirm=self._on_totp_entered,
                    ),
                    rio.TextInput(
                        text=self.bind().verification_code,
                        label="Enter your 2FA code",
                        on_confirm=self._on_totp_entered,
                    ),
                    rio.Row(
                        rio.Button(
                            "Verify and Enable 2FA",
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
        )
