from __future__ import annotations

from datetime import timezone
import rio

from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_COMFORTABLE
from app.data_models import UserSession
from app.persistence import Persistence, TwoFactorFailure


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

    recovery_codes_total: int = 0
    recovery_codes_remaining: int = 0
    last_generated_label: str = "Never generated"

    @rio.event.on_populate
    async def on_populate(self) -> None:
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        user = await persistence.get_user_by_id(user_session.user_id)

        if not user.two_factor_secret:
            # Recovery codes are only relevant when 2FA is enabled.
            self.session.navigate_to("/app/settings")
            return

        self._refresh_summary(persistence, user_session.user_id)
        self.recovery_codes = ()
        self.show_recovery_codes = False
        self.error_message = ""
        self.success_message = ""

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
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        user = await persistence.get_user_by_id(user_session.user_id)

        if not self.password:
            self.error_message = "Please enter your account password."
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
        if not result.ok:
            if result.failure == TwoFactorFailure.INVALID_FORMAT:
                self.error_message = result.failure_detail or "Invalid 2FA or recovery code format."
            elif result.failure == TwoFactorFailure.MISSING_CODE:
                self.error_message = "2FA or recovery code is required."
            else:
                self.error_message = "Invalid 2FA or recovery code."
            self.force_refresh()
            return

        codes = persistence.generate_recovery_codes(user_session.user_id)
        self.recovery_codes = tuple(codes)
        self.show_recovery_codes = True
        self.error_message = ""
        self.success_message = ""
        self.password = ""
        self.verification_code = ""
        self._refresh_summary(persistence, user_session.user_id)
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
                    rio.Text(self._summary_text()),
                    rio.Text(f"Last generated: {self.last_generated_label}"),
                    rio.Text(
                        "Generating a new set invalidates all existing recovery codes.",
                        margin_top=1,
                    ),
                    rio.TextInput(
                        label="Password",
                        text=self.bind().password,
                        is_secret=True,
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
