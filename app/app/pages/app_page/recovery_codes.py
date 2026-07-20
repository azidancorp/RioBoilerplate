from __future__ import annotations

from datetime import timezone
import logging
import rio

from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_COMFORTABLE
from app.config import config
from app.mfa_oauth import (
    navigate_to_google_mfa_reauth,
    read_oauth_mfa_callback,
)
from app.persistence import Persistence
from app.persistence_auth import (
    TwoFactorFailure,
    TwoFactorMethod,
    TwoFactorStateConflict,
)
from app.persistence_social import OAUTH_RECOVERY_CODES_PURPOSE
from app.request_context import context_from_rio_session
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import reject_stale_user_session, require_fresh_user_session


logger = logging.getLogger(__name__)


@rio.page(
    name="Manage Recovery Codes",
    url_segment="recovery-codes",
)
class ManageRecoveryCodes(rio.Component):
    """Allows users to regenerate two-factor recovery codes."""

    password: str = ""
    verification_code: str = ""
    error_message: str = ""
    success_message: str = ""
    recovery_codes: tuple[str, ...] = ()
    show_recovery_codes: bool = False
    auth_provider: str = "password"
    oauth_approval_token: str = ""
    oauth_status: str = ""

    recovery_codes_total: int = 0
    recovery_codes_remaining: int = 0
    last_generated_label: str = "Never generated"

    @rio.event.on_populate
    def on_populate(self) -> None:
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        persistence = self.session[Persistence]
        self.auth_provider = user.auth_provider

        if not user.two_factor_secret:
            # Recovery codes are only relevant when 2FA is enabled.
            self.password = ""
            self.verification_code = ""
            self.recovery_codes = ()
            self.show_recovery_codes = False
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.session.navigate_to("/app/settings", replace=True)
            return

        if user.auth_provider == "google":
            callback = read_oauth_mfa_callback(
                self.session,
                purpose=OAUTH_RECOVERY_CODES_PURPOSE,
                token_parameter="recovery_codes_oauth_token",
                error_parameter="recovery_codes_oauth_error",
            )
            if callback.should_scrub_url:
                # An error callback must not erase an approval already held.
                # Rio does not re-run a synchronous population after the
                # same-route replace navigation, so fall through to the
                # summary refresh below instead of returning early.
                self.session.navigate_to("/app/recovery-codes", replace=True)
                if callback.token:
                    try:
                        persistence.validate_oauth_reauth_approval(
                            approval_token=callback.token,
                            user_id=user.id,
                            provider=user.auth_provider,
                            purpose=OAUTH_RECOVERY_CODES_PURPOSE,
                            auth_token=user_session.id,
                        )
                    except (KeyError, ValueError):
                        if not self.oauth_approval_token:
                            self.password = ""
                            self.verification_code = ""
                            self.recovery_codes = ()
                            self.show_recovery_codes = False
                            self.oauth_status = ""
                        self.error_message = (
                            "Google verification expired or your session changed. "
                            "Verify with Google again."
                        )
                    else:
                        self.password = ""
                        self.verification_code = ""
                        self.recovery_codes = ()
                        self.show_recovery_codes = False
                        self.oauth_approval_token = callback.token
                        self.oauth_status = (
                            "Google identity confirmed. This approval expires in "
                            f"{config.MFA_LIFECYCLE_APPROVAL_TTL_MINUTES} minutes."
                        )
                        self.error_message = ""
                        self.success_message = ""
                else:
                    self.error_message = callback.error_message
        else:
            self.oauth_approval_token = ""
            self.oauth_status = ""

        self._refresh_summary(persistence, user_session.user_id)
        self.recovery_codes = ()
        self.show_recovery_codes = False
        self.success_message = ""

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
            "recovery_codes_regenerate",
            context.user_id or context.session_id or context.client_ip,
        )
        decision = persistence.check_rate_limit(
            policy=sensitive_action_policy("recovery_codes_regenerate"),
            key=limit_key,
        )
        if not decision.allowed:
            self.error_message = rate_limited_message(
                "Too many recovery-code attempts.",
                decision.retry_after_seconds,
            )
            return

        try:
            challenge = await persistence.create_oauth_reauth_challenge(
                user_id=user.id,
                provider=user.auth_provider,
                purpose=OAUTH_RECOVERY_CODES_PURPOSE,
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
            purpose=OAUTH_RECOVERY_CODES_PURPOSE,
            challenge=challenge,
        )

    def _refresh_summary(self, persistence: Persistence, user_id) -> None:
        summary = persistence.get_recovery_codes_summary(user_id)
        self.recovery_codes_total = summary["total"]
        self.recovery_codes_remaining = summary["remaining"]
        last_generated = summary["last_generated"]
        if last_generated:
            self.last_generated_label = last_generated.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        else:
            self.last_generated_label = "Never generated"

    async def _on_generate_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        fresh_session = require_fresh_user_session(self.session)
        if fresh_session is None:
            return
        user_session, user = fresh_session
        persistence = self.session[Persistence]
        expected_secret = user.two_factor_secret

        if not expected_secret:
            self.password = ""
            self.verification_code = ""
            self.recovery_codes = ()
            self.show_recovery_codes = False
            self.error_message = "Two-factor authentication is no longer enabled."
            self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return

        if user.auth_provider == "password":
            if not self.password:
                self.error_message = "Please enter your account password."
                self.force_refresh()
                return
        elif user.auth_provider == "google":
            if not self.oauth_approval_token:
                self.error_message = (
                    "Verify with Google before generating recovery codes."
                )
                self.force_refresh()
                return
        else:
            self.error_message = "This account's sign-in provider is not supported."
            self.force_refresh()
            return

        context = context_from_rio_session(self.session, user_id=user_session.user_id)
        limit_key = rate_limit_key("recovery_codes_regenerate", context.user_id or context.session_id or context.client_ip)
        decision = persistence.check_rate_limit(
            policy=sensitive_action_policy("recovery_codes_regenerate"),
            key=limit_key,
        )
        if not decision.allowed:
            self.error_message = rate_limited_message(
                "Too many recovery-code attempts.",
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
                codes = persistence.generate_recovery_codes_after_oauth_approval(
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
                codes = None
        else:
            result = persistence.verify_two_factor_challenge(
                user_session.user_id,
                self.verification_code,
            )
            if result.method == TwoFactorMethod.NOT_REQUIRED:
                self.password = ""
                self.verification_code = ""
                self.recovery_codes = ()
                self.show_recovery_codes = False
                self.error_message = "Two-factor authentication is no longer enabled."
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
                    self.error_message = "2FA or recovery code is required."
                else:
                    self.error_message = "Invalid 2FA or recovery code."
                self.force_refresh()
                return

            try:
                codes = persistence.generate_recovery_codes(
                    user_session.user_id,
                    expected_secret=expected_secret,
                )
            except TwoFactorStateConflict:
                codes = None

        if codes is None:
            self.password = ""
            self.verification_code = ""
            self.recovery_codes = ()
            self.show_recovery_codes = False
            self.oauth_approval_token = ""
            self.oauth_status = ""
            self.error_message = "Two-factor authentication changed. Please try again."
            self.session.navigate_to("/app/settings", replace=True)
            self.force_refresh()
            return

        self.recovery_codes = tuple(codes)
        self.show_recovery_codes = True
        self.error_message = ""
        self.success_message = ""
        self.password = ""
        self.verification_code = ""
        self.oauth_approval_token = ""
        self.oauth_status = ""
        try:
            persistence.clear_rate_limit(
                scope=sensitive_action_policy("recovery_codes_regenerate").scope,
                key=limit_key,
            )
        except Exception:
            logger.exception(
                "Recovery codes committed but their rate-limit bucket could not be cleared."
            )
        try:
            self._refresh_summary(persistence, user_session.user_id)
        except Exception:
            logger.exception(
                "Recovery codes committed but their summary could not be refreshed."
            )
        self.force_refresh()

    def _on_acknowledge_recovery_codes(self, _event=None) -> None:
        self.session.navigate_to("/app/settings")

    def _summary_text(self) -> str:
        if not self.recovery_codes_total:
            return "You have not generated any recovery codes yet."
        return (
            f"Recovery codes remaining: {self.recovery_codes_remaining} "
            f"of {self.recovery_codes_total}."
        )

    def build(self) -> rio.Component:
        if self.show_recovery_codes:
            return CenterComponent(
                rio.Card(
                    rio.Column(
                        rio.Text("New Recovery Codes", style="heading1", justify="center"),
                        rio.Text(
                            "Store these recovery codes in a secure location. "
                            "Each code can only be used once.",
                            margin_bottom=1,
                        ),
                        rio.Column(
                            *(rio.Text(code) for code in self.recovery_codes),
                            spacing=0.5,
                            margin_bottom=1.5,
                        ),
                        rio.Text(
                            "You will not be able to view these codes again after leaving this page.",
                            margin_bottom=1,
                        ),
                        rio.Button(
                            "Return to Settings",
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
                            "Manage Recovery Codes",
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
                        rio.Text(self._summary_text()),
                        rio.Text(f"Last generated: {self.last_generated_label}"),
                        rio.Text(
                            "Verify your identity with Google before replacing "
                            "your application recovery codes."
                        ),
                        rio.Button(
                            "Verify with Google",
                            on_press=self._on_verify_google_pressed,
                            shape="rounded",
                        ),
                        rio.Button(
                            "Back to Settings",
                            on_press=self._on_acknowledge_recovery_codes,
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
                    rio.Text("Manage Recovery Codes", style="heading1", justify="center"),
                    rio.Banner(
                        text=self.error_message,
                        style="danger",
                        margin_top=1,
                    ) if self.error_message else rio.Spacer(min_height=0, grow_x=False, grow_y=False),
                    rio.Banner(
                        text=self.success_message,
                        style="success",
                        margin_top=1,
                    ) if self.success_message else rio.Spacer(min_height=0, grow_x=False, grow_y=False),
                    *(
                        [rio.Banner(text=self.oauth_status, style="success")]
                        if self.oauth_status
                        else []
                    ),
                    rio.Text(self._summary_text()),
                    rio.Text(f"Last generated: {self.last_generated_label}"),
                    rio.Text(
                        "Generating a new set invalidates all existing recovery codes.",
                        margin_top=1,
                    ),
                    *(
                        [
                            rio.TextInput(
                                label="Password",
                                text=self.bind().password,
                                is_secret=True,
                            )
                        ]
                        if self.auth_provider == "password"
                        else []
                    ),
                    rio.TextInput(
                        label="2FA / Recovery Code",
                        text=self.bind().verification_code,
                        on_confirm=self._on_generate_pressed,
                    ),
                    rio.Button(
                        "Generate New Recovery Codes",
                        on_press=self._on_generate_pressed,
                        shape="rounded",
                    ),
                    rio.Button(
                        "Back to Settings",
                        on_press=self._on_acknowledge_recovery_codes,
                        shape="rounded",
                        margin_top=0.5,
                    ),
                    spacing=1,
                    margin=2,
                ),
                align_y=0,
            ),
            width_percent=WIDTH_COMFORTABLE,
        )
