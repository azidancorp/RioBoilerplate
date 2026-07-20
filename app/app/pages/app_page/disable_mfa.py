from __future__ import annotations

import logging
import rio

from app.config import config
from app.persistence import Persistence
from app.persistence_auth import (
    TwoFactorFailure,
    TwoFactorMethod,
    TwoFactorStateConflict,
)
from app.persistence_social import OAUTH_MFA_DISABLE_PURPOSE
from app.request_context import context_from_rio_session
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import reject_stale_user_session, require_fresh_user_session
from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_COMFORTABLE
from app.mfa_oauth import (
    navigate_to_google_mfa_reauth,
    read_oauth_mfa_callback,
)


logger = logging.getLogger(__name__)


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
    auth_provider: str = "password"
    oauth_approval_token: str = ""
    oauth_status: str = ""

    @rio.event.on_populate
    def on_populate(self):
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        persistence = self.session[Persistence]
        self.auth_provider = user.auth_provider
        self.two_factor_enabled = user.two_factor_enabled

        # If the user does not have a secret, redirect them
        if not self.two_factor_enabled:
            self.password = ""
            self.verification_code = ""
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.session.navigate_to("/app/settings", replace=True)
            return

        if user.auth_provider == "google":
            callback = read_oauth_mfa_callback(
                self.session,
                purpose=OAUTH_MFA_DISABLE_PURPOSE,
                token_parameter="disable_mfa_oauth_token",
                error_parameter="disable_mfa_oauth_error",
            )
            if callback.should_scrub_url:
                # An error callback must not erase an approval already held.
                # Rio does not re-run a synchronous population after the
                # same-route replace navigation, so do not return early.
                self.session.navigate_to("/app/disable-mfa", replace=True)
                if callback.token:
                    try:
                        persistence.validate_oauth_reauth_approval(
                            approval_token=callback.token,
                            user_id=user.id,
                            provider=user.auth_provider,
                            purpose=OAUTH_MFA_DISABLE_PURPOSE,
                            auth_token=user_session.id,
                        )
                    except (KeyError, ValueError):
                        if not self.oauth_approval_token:
                            self.password = ""
                            self.verification_code = ""
                            self.oauth_status = ""
                        self.error_message = (
                            "Google verification expired or your session changed. "
                            "Verify with Google again."
                        )
                    else:
                        self.password = ""
                        self.verification_code = ""
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
            "mfa_disable",
            context.user_id or context.session_id or context.client_ip,
        )
        decision = persistence.check_rate_limit(
            policy=sensitive_action_policy("mfa_disable"),
            key=limit_key,
        )
        if not decision.allowed:
            self.error_message = rate_limited_message(
                "Too many two-factor disable attempts.",
                decision.retry_after_seconds,
            )
            return

        try:
            challenge = await persistence.create_oauth_reauth_challenge(
                user_id=user.id,
                provider=user.auth_provider,
                purpose=OAUTH_MFA_DISABLE_PURPOSE,
                auth_token=user_session.id,
            )
        except KeyError:
            reject_stale_user_session(self.session)
            return
        except ValueError:
            self.error_message = "Google verification is unavailable."
            return

        self.password = ""
        self.verification_code = ""
        self.oauth_approval_token = ""
        self.oauth_status = ""
        self.error_message = ""
        navigate_to_google_mfa_reauth(
            self.session,
            purpose=OAUTH_MFA_DISABLE_PURPOSE,
            challenge=challenge,
        )

    async def _on_totp_entered(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Verify password and 2FA or recovery code before disabling 2FA.
        """
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        persistence = self.session[Persistence]
        expected_secret = user.two_factor_secret

        if not expected_secret:
            self.two_factor_enabled = False
            self.password = ""
            self.verification_code = ""
            self.error_message = "Two-factor authentication is already disabled."
            self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return

        if user.auth_provider == "password":
            if not self.password:
                self.error_message = "Please enter your password to disable 2FA."
                self.force_refresh()
                return
        elif user.auth_provider == "google":
            if not self.oauth_approval_token:
                self.error_message = "Verify with Google before disabling 2FA."
                self.force_refresh()
                return
        else:
            self.error_message = "This account's sign-in provider is not supported."
            self.force_refresh()
            return

        context = context_from_rio_session(self.session, user_id=user_session.user_id)
        limit_key = rate_limit_key("mfa_disable", context.user_id or context.session_id or context.client_ip)
        decision = persistence.check_rate_limit(
            policy=sensitive_action_policy("mfa_disable"),
            key=limit_key,
        )
        if not decision.allowed:
            self.error_message = rate_limited_message(
                "Too many two-factor disable attempts.",
                decision.retry_after_seconds,
            )
            self.force_refresh()
            return

        if user.auth_provider == "password" and not user.verify_password(self.password):
            self.error_message = "Invalid password. Please try again."
            self.force_refresh()
            return

        if user.auth_provider == "google":
            try:
                disabled = persistence.disable_two_factor_after_oauth_approval(
                    user_id=user_session.user_id,
                    auth_token=user_session.id,
                    oauth_approval_token=self.oauth_approval_token,
                    two_factor_code=self.verification_code,
                    expected_secret=expected_secret,
                )
            except KeyError:
                self.password = ""
                self.verification_code = ""
                self.oauth_approval_token = ""
                self.oauth_status = ""
                self.error_message = (
                    "Google verification expired or your session changed. "
                    "Verify with Google again."
                )
                self.force_refresh()
                return
            except ValueError as exc:
                self.error_message = str(exc) or "Invalid 2FA or recovery code."
                self.force_refresh()
                return
            except TwoFactorStateConflict:
                disabled = False
        else:
            result = persistence.verify_two_factor_challenge(
                user_session.user_id,
                self.verification_code,
            )
            if result.method == TwoFactorMethod.NOT_REQUIRED:
                self.two_factor_enabled = False
                self.password = ""
                self.verification_code = ""
                self.error_message = "Two-factor authentication is already disabled."
                self.session.navigate_to("/app/settings", replace=True)
                self.force_refresh()
                return

            if not result.ok:
                if result.failure == TwoFactorFailure.INVALID_FORMAT:
                    self.error_message = (
                        result.failure_detail
                        or "Invalid 2FA or recovery code format."
                    )
                elif result.failure == TwoFactorFailure.MISSING_CODE:
                    self.error_message = "Please enter a 2FA code or recovery code."
                else:
                    self.error_message = (
                        "Invalid verification or recovery code. Please try again."
                    )
                self.force_refresh()
                return

            disabled = persistence.disable_two_factor(
                user_session.user_id,
                expected_secret=expected_secret,
            )

        if not disabled:
            self.password = ""
            self.verification_code = ""
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.error_message = "Two-factor authentication changed. Please try again."
            self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return

        self.two_factor_enabled = False
        self.password = ""
        self.verification_code = ""
        self.oauth_approval_token = ""
        self.oauth_status = ""
        try:
            persistence.clear_rate_limit(
                scope=sensitive_action_policy("mfa_disable").scope,
                key=limit_key,
            )
        except Exception:
            logger.exception(
                "MFA disable committed but its rate-limit bucket could not be cleared."
            )
        self.session.navigate_to("/app/settings", replace=True)

    def build(self) -> rio.Component:
        if self.auth_provider == "google" and not self.oauth_approval_token:
            return CenterComponent(
                rio.Card(
                    rio.Column(
                        rio.Text(
                            "Disable Two-Factor Authentication",
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
                            "Verify your identity with Google before disabling "
                            "application two-factor authentication."
                        ),
                        rio.Button(
                            "Verify with Google",
                            on_press=self._on_verify_google_pressed,
                            shape="rounded",
                        ),
                        spacing=1,
                        margin=2,
                    ),
                    align_y=0,
                ),
                width_percent=WIDTH_COMFORTABLE,
                height_percent=50,
            )

        return CenterComponent(
            rio.Card(
                rio.Column(
                    rio.Text("Disable Two-Factor Authentication", style="heading1", justify="center"),
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
                    rio.Text("Two-factor authentication is currently enabled."),
                    rio.Text(
                        "Enter your 2FA or recovery code to disable two-factor "
                        "authentication."
                    ),
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
