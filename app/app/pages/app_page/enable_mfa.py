from __future__ import annotations

import io
import logging
import qrcode
import pyotp
import rio

from app.config import config
from app.persistence import Persistence
from app.persistence_auth import (
    TwoFactorEmailUnverifiedError,
    TwoFactorFailure,
    TwoFactorStateConflict,
    verify_two_factor_candidate,
)
from app.persistence_social import OAUTH_MFA_ENABLE_PURPOSE
from app.request_context import context_from_rio_session
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import reject_stale_user_session, require_fresh_user_session
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_COMFORTABLE
from app.mfa_oauth import (
    navigate_to_google_mfa_reauth,
    read_oauth_mfa_callback,
)


logger = logging.getLogger(__name__)


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
    email_unverified: bool = False
    auth_provider: str = "password"
    oauth_approval_token: str = ""
    oauth_status: str = ""

    def _scrub_setup_state(self) -> None:
        self.password = ""
        self.temporary_two_factor_secret = ""
        self.verification_code = ""
        self.qr_code_image_bytes = None
        self.secret = None
        self.recovery_codes = ()
        self.show_recovery_codes = False

    @rio.event.on_populate
    def on_populate(self):
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        persistence = self.session[Persistence]
        self.auth_provider = user.auth_provider

        # If the user already has a 2FA secret, redirect them
        if user.two_factor_secret:
            self._scrub_setup_state()
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.session.navigate_to("/app/settings", replace=True)
            return

        # Capture and scrub callback values before any other gate so an
        # approval token never stays in the URL. An error callback must not
        # erase an approval that is already held. Rio does not re-run a
        # synchronous population after same-route replace navigation, so this
        # pass must fall through and finish initialization itself.
        if user.auth_provider == "google":
            callback = read_oauth_mfa_callback(
                self.session,
                purpose=OAUTH_MFA_ENABLE_PURPOSE,
                token_parameter="enable_mfa_oauth_token",
                error_parameter="enable_mfa_oauth_error",
            )
            if callback.should_scrub_url:
                self.session.navigate_to("/app/enable-mfa", replace=True)
                if callback.token:
                    try:
                        persistence.validate_oauth_reauth_approval(
                            approval_token=callback.token,
                            user_id=user.id,
                            provider=user.auth_provider,
                            purpose=OAUTH_MFA_ENABLE_PURPOSE,
                            auth_token=user_session.id,
                        )
                    except (KeyError, ValueError):
                        if not self.oauth_approval_token:
                            self._scrub_setup_state()
                            self.oauth_status = ""
                        self.error_message = (
                            "Google verification expired or your session changed. "
                            "Verify with Google again."
                        )
                    else:
                        self._scrub_setup_state()
                        self.oauth_approval_token = callback.token
                        self.oauth_status = (
                            "Google identity confirmed. This approval expires in "
                            f"{config.MFA_LIFECYCLE_APPROVAL_TTL_MINUTES} minutes."
                        )
                        self.error_message = ""
                else:
                    self.error_message = callback.error_message
        else:
            self.oauth_approval_token = ""
            self.oauth_status = ""

        # Unverified accounts must not arm TOTP; persistence enforces the same
        # rule, this just explains it before showing a QR code.
        if not user.is_verified:
            self._scrub_setup_state()
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.email_unverified = True
            return
        self.email_unverified = False

        if user.auth_provider == "google" and not self.oauth_approval_token:
            self._scrub_setup_state()
            return

        if self.temporary_two_factor_secret:
            return

        # Create a new 2FA secret only after Google reauthentication, when used.
        self._scrub_setup_state()
        self.temporary_two_factor_secret = pyotp.random_base32()
        self.error_message = ""

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

    async def _on_verify_google_pressed(self) -> None:
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        if user.auth_provider != "google":
            self.error_message = "This account does not use Google sign-in."
            return

        persistence = self.session[Persistence]
        context = context_from_rio_session(
            self.session,
            user_id=user_session.user_id,
        )
        limit_key = rate_limit_key(
            "mfa_enable",
            context.user_id or context.session_id or context.client_ip,
        )
        decision = persistence.check_rate_limit(
            policy=sensitive_action_policy("mfa_enable"),
            key=limit_key,
        )
        if not decision.allowed:
            self.error_message = rate_limited_message(
                "Too many two-factor setup attempts.",
                decision.retry_after_seconds,
            )
            return

        try:
            challenge = await persistence.create_oauth_reauth_challenge(
                user_id=user.id,
                provider=user.auth_provider,
                purpose=OAUTH_MFA_ENABLE_PURPOSE,
                auth_token=user_session.id,
            )
        except KeyError:
            reject_stale_user_session(self.session)
            return
        except ValueError:
            self.error_message = "Google verification is unavailable."
            return

        self._scrub_setup_state()
        self.oauth_approval_token = ""
        self.oauth_status = ""
        self.error_message = ""
        navigate_to_google_mfa_reauth(
            self.session,
            purpose=OAUTH_MFA_ENABLE_PURPOSE,
            challenge=challenge,
        )

    async def _on_totp_entered(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Called when user presses "Verify" button.
        Requires password verification before enabling 2FA.
        """
        # A rapid double-submit can queue a second event before the successful
        # recovery-code view reaches the client. Keep that one-time display intact.
        if self.show_recovery_codes:
            return

        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        persistence = self.session[Persistence]

        if user.two_factor_secret:
            self._scrub_setup_state()
            self.error_message = "Two-factor authentication is already enabled."
            self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return

        if not self.temporary_two_factor_secret:
            self._scrub_setup_state()
            if user.auth_provider == "google":
                self.oauth_approval_token = ""
                self.oauth_status = ""
                self.error_message = (
                    "Two-factor setup expired. Verify with Google again."
                )
            else:
                self.error_message = "Two-factor setup has expired. Please start again."
                self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return

        if user.auth_provider == "password":
            if not self.password:
                self.error_message = "Please enter your password to enable 2FA."
                self.force_refresh()
                return
        elif user.auth_provider == "google":
            if not self.oauth_approval_token:
                self._scrub_setup_state()
                self.error_message = "Verify with Google before enabling 2FA."
                self.force_refresh()
                return
        else:
            self._scrub_setup_state()
            self.error_message = "This account's sign-in provider is not supported."
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

        if user.auth_provider == "password" and not user.verify_password(self.password):
            self.error_message = "Invalid password. Please try again."
            self.force_refresh()
            return

        try:
            if user.auth_provider == "google":
                recovery_codes = persistence.enroll_two_factor_after_oauth_approval(
                    user_id=user_session.user_id,
                    auth_token=user_session.id,
                    oauth_approval_token=self.oauth_approval_token,
                    candidate_secret=self.temporary_two_factor_secret,
                    verification_code=self.verification_code,
                )
            else:
                candidate_result = verify_two_factor_candidate(
                    self.temporary_two_factor_secret,
                    self.verification_code,
                )
                if not candidate_result.ok:
                    if candidate_result.failure == TwoFactorFailure.INVALID_FORMAT:
                        self.error_message = "Invalid verification code format."
                    elif candidate_result.failure == TwoFactorFailure.MISSING_CODE:
                        self.error_message = "Please enter your 2FA verification code."
                    else:
                        self.error_message = (
                            "Invalid verification code. Please try again."
                        )
                    self.force_refresh()
                    return
                recovery_codes = persistence.enroll_two_factor(
                    user_session.user_id,
                    self.temporary_two_factor_secret,
                )
        except KeyError:
            self._scrub_setup_state()
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.error_message = (
                "Google verification expired or your session changed. "
                "Verify with Google again."
            )
            self.force_refresh()
            return
        except ValueError as exc:
            self.error_message = str(exc) or "Invalid verification code."
            self.force_refresh()
            return
        except TwoFactorStateConflict:
            self._scrub_setup_state()
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.error_message = "Two-factor authentication is already enabled."
            self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return
        except TwoFactorEmailUnverifiedError:
            self._scrub_setup_state()
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.email_unverified = True
            self.force_refresh()
            return

        self.recovery_codes = tuple(recovery_codes)
        self.show_recovery_codes = True
        self.error_message = ""
        self.password = ""
        self.oauth_approval_token = ""
        self.oauth_status = ""
        self.temporary_two_factor_secret = ""
        self.verification_code = ""
        self.qr_code_image_bytes = None
        self.secret = None
        try:
            persistence.clear_rate_limit(
                scope=sensitive_action_policy("mfa_enable").scope,
                key=limit_key,
            )
        except Exception:
            logger.exception(
                "MFA enrollment committed but its rate-limit bucket could not be cleared."
            )
        self.force_refresh()

    def _on_acknowledge_recovery_codes(self, _event=None) -> None:
        """Navigate back to settings after the user confirms they've stored the codes."""
        self.session.navigate_to("/app/settings")

    def _on_back_to_settings(self, _event=None) -> None:
        self.session.navigate_to("/app/settings")

    def build(self) -> rio.Component:
        if self.email_unverified:
            return CenterComponent(
                rio.Card(
                    rio.Column(
                        rio.Text(
                            "Verify Your Email First",
                            style="heading1",
                            justify="center",
                        ),
                        rio.Text(
                            "Two-factor authentication requires a verified email "
                            "address, because account recovery depends on "
                            "reaching you at it.",
                            margin_bottom=1,
                        ),
                        rio.Text(
                            "Verify your email and return to this page. If you "
                            "never received a verification email, contact an "
                            "administrator.",
                            margin_bottom=1,
                        ),
                        rio.Button(
                            "Back to Settings",
                            on_press=self._on_back_to_settings,
                            shape="rounded",
                        ),
                        spacing=1.5,
                        margin=2,
                    ),
                    align_y=0,
                ),
                width_percent=WIDTH_COMFORTABLE,
            )

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

        if self.auth_provider == "google" and not self.oauth_approval_token:
            return CenterComponent(
                rio.Card(
                    rio.Column(
                        rio.Text(
                            "Enable Two-Factor Authentication",
                            style="heading1",
                            justify="center",
                        ),
                        *(
                            [
                                rio.Banner(
                                    text=self.error_message,
                                    style="danger",
                                    margin_top=1,
                                )
                            ]
                            if self.error_message
                            else []
                        ),
                        rio.Text(
                            "Verify your identity with Google before creating "
                            "a new authenticator secret. No app password is required."
                        ),
                        rio.Button(
                            "Verify with Google",
                            on_press=self._on_verify_google_pressed,
                            shape="rounded",
                        ),
                        rio.Button(
                            "Back to Settings",
                            on_press=self._on_back_to_settings,
                            shape="rounded",
                        ),
                        spacing=1,
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
                    *(
                        [
                            rio.Banner(
                                text=self.error_message,
                                style="danger",
                                margin_top=1,
                            )
                        ]
                        if self.error_message
                        else []
                    ),
                    *(
                        [rio.Banner(text=self.oauth_status, style="success")]
                        if self.oauth_status
                        else []
                    ),
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
                    *(
                        [
                            rio.TextInput(
                                text=self.bind().password,
                                label="Enter your password",
                                is_secret=True,
                                on_confirm=self._on_totp_entered,
                            )
                        ]
                        if self.auth_provider == "password"
                        else []
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
