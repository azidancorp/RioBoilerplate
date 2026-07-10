from __future__ import annotations

import logging
import rio

from app.persistence import Persistence
from app.persistence_auth import TwoFactorFailure, TwoFactorMethod
from app.request_context import context_from_rio_session
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import require_fresh_user_session
from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_COMFORTABLE


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

    @rio.event.on_populate
    async def on_populate(self):
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        _, user = fresh_session
        self.two_factor_enabled = user.two_factor_enabled

        # If the user does not have a secret, redirect them
        if not self.two_factor_enabled:
            self.password = ""
            self.verification_code = ""
            self.session.navigate_to("/app/settings", replace=True)
            return

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

        # Validate password first
        if not self.password:
            self.error_message = "Please enter your password to disable 2FA."
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

        if not user.verify_password(self.password):
            self.error_message = "Invalid password. Please try again."
            self.force_refresh()
            return

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
                self.error_message = result.failure_detail or "Invalid 2FA or recovery code format."
            elif result.failure == TwoFactorFailure.MISSING_CODE:
                self.error_message = "Please enter a 2FA code or recovery code."
            else:
                self.error_message = "Invalid verification or recovery code. Please try again."
            self.force_refresh()
            return

        if not persistence.disable_two_factor(
            user_session.user_id,
            expected_secret=expected_secret,
        ):
            self.password = ""
            self.verification_code = ""
            self.error_message = "Two-factor authentication changed. Please try again."
            self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return

        self.two_factor_enabled = False
        self.password = ""
        self.verification_code = ""
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
