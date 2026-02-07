from __future__ import annotations

import typing as t
from dataclasses import KW_ONLY, field
from datetime import datetime, timezone

import rio
from app.persistence import Persistence, TwoFactorFailure
from app.data_models import AppUser, UserSession, RecoveryCodeUsage
from app.components.center_component import CenterComponent
from app.components.currency_summary import CurrencySummary, CurrencyOverview as CurrencySnapshot
from app.scripts.utils import (
    get_password_strength,
    get_password_strength_color,
    get_password_strength_status,
)
from app.validation import SecuritySanitizer


@rio.page(
    name="Settings",
    url_segment="settings",
)
class Settings(rio.Component):
    """
    Settings page containing various user configuration options.
    """

    # Notification preferences (loaded from database)
    email_notifications_enabled: bool = True
    sms_notifications_enabled: bool = False
    two_factor_enabled: bool = False

    # Profile fields (loaded from database)
    profile_display_name: str = ""
    profile_bio: str = ""
    account_email: str = ""

    # Password change fields
    change_password_current_password: str = ""
    change_password_new_password: str = ""
    change_password_confirm_password: str = ""
    change_password_2fa: str = ""

    # Tracking password strength in real time
    change_password_new_password_strength: int = 0
    change_password_passwords_match: bool = False

    # Account deletion fields
    delete_account_password: str = ""
    delete_account_2fa: str = ""
    delete_account_confirmation: str = ""
    delete_account_error: str = ""

    # Error/success messages
    error_message: str = ""
    profile_success_message: str = ""
    recovery_code_notice: str = ""

    # Recovery code metadata
    recovery_codes_total: int = 0
    recovery_codes_remaining: int = 0
    recovery_codes_last_generated: str = "Never generated"

    # Currency overview
    currency_overview: CurrencySnapshot | None = None

    @rio.event.on_populate
    async def on_populate(self):
        """Load user data from database when page loads."""
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]

        # Load user data
        user = await persistence.get_user_by_id(user_session.user_id)
        self.two_factor_enabled = bool(user.two_factor_secret)
        self.email_notifications_enabled = user.email_notifications_enabled
        self.sms_notifications_enabled = user.sms_notifications_enabled
        self.account_email = user.email
        self.currency_overview = CurrencySnapshot(
            balance_minor=user.primary_currency_balance,
            updated_at=user.primary_currency_updated_at,
        )

        # Load profile data
        profile = await persistence.get_profile_by_user_id(str(user_session.user_id))
        if profile:
            self.profile_display_name = profile.get("full_name") or ""
            self.profile_bio = profile.get("bio") or ""

        # Load recovery code summary
        summary = persistence.get_recovery_codes_summary(user_session.user_id)
        self.recovery_codes_total = summary["total"]
        self.recovery_codes_remaining = summary["remaining"]
        last_generated = summary["last_generated"]
        if last_generated:
            # Present timestamps in UTC to avoid timezone confusion in dashboard context.
            self.recovery_codes_last_generated = last_generated.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        else:
            self.recovery_codes_last_generated = "Never generated"

        try:
            usage = self.session[RecoveryCodeUsage]
        except KeyError:
            usage = None

        if usage and (usage.used_at_login or usage.used_in_settings):
            self.recovery_code_notice = (
                "A recovery code was recently used. Generate a new set so you retain backups."
            )
            usage.used_at_login = False
            usage.used_in_settings = False
        else:
            self.recovery_code_notice = ""

    async def _on_email_notifications_switch_pressed(self, event: rio.SwitchChangeEvent):
        """Handle email notification toggle and save to database."""
        self.email_notifications_enabled = event.is_on
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        await persistence.update_notification_preferences(
            user_session.user_id,
            email_notifications_enabled=event.is_on
        )

    async def _on_sms_notifications_switch_pressed(self, event: rio.SwitchChangeEvent):
        """Handle SMS notification toggle and save to database."""
        self.sms_notifications_enabled = event.is_on
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        await persistence.update_notification_preferences(
            user_session.user_id,
            sms_notifications_enabled=event.is_on
        )

    async def on_change_new_password(self, event: rio.TextInputChangeEvent):
        self.change_password_new_password = event.text
        self.change_password_new_password_strength = get_password_strength(self.change_password_new_password)
        self.change_password_passwords_match = (
            self.change_password_new_password == self.change_password_confirm_password
        )
        self.force_refresh()

    async def on_change_confirm_password(self, event: rio.TextInputChangeEvent):
        self.change_password_confirm_password = event.text
        self.change_password_passwords_match = (
            self.change_password_new_password == self.change_password_confirm_password
        )
        self.force_refresh()

    def new_password_strength_progress(self) -> rio.Component:
        return rio.ProgressBar(
            progress=max(0, min(self.change_password_new_password_strength / 100, 1)),
            color=get_password_strength_color(self.change_password_new_password_strength),
        )

    def recovery_codes_summary_text(self) -> str:
        if not self.recovery_codes_total:
            return "Recovery codes have not been generated yet."
        return (
            f"Recovery codes remaining: {self.recovery_codes_remaining} "
            f"of {self.recovery_codes_total}"
        )

    async def _on_confirm_password_change_pressed(self) -> None:
        """Handle the password change process."""
        # Get required instances
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]
        
        try:
            # Get current user
            user = await persistence.get_user_by_id(user_session.user_id)
            
            # Validate inputs
            if not (self.change_password_current_password and 
                   self.change_password_new_password and 
                   self.change_password_confirm_password):
                self.error_message = "Please fill in all password fields"
                return
                
            # Verify passwords match
            if self.change_password_new_password != self.change_password_confirm_password:
                self.error_message = "New passwords do not match"
                return
                
            # Verify current password
            if not user.verify_password(self.change_password_current_password):
                self.error_message = "Current password is incorrect"
                return
                
            # Validate and sanitize 2FA code if provided
            if user.two_factor_enabled:
                result = persistence.verify_two_factor_challenge(
                    user_session.user_id,
                    self.change_password_2fa,
                )
                if not result.ok:
                    if result.failure == TwoFactorFailure.MISSING_CODE:
                        self.error_message = "2FA code is required"
                        return
                    self.error_message = "Invalid 2FA or recovery code."
                    return

                if result.used_recovery_code:
                    try:
                        usage = self.session[RecoveryCodeUsage]
                    except KeyError:
                        usage = RecoveryCodeUsage()
                        self.session.attach(usage)
                    usage.used_in_settings = True
                    self.recovery_code_notice = "A recovery code was used. Generate a new set to stay protected."

                self.change_password_2fa = ""
            
            # Update the password
            await persistence.update_password(user_session.user_id, self.change_password_new_password)
            
            # Clear the form
            self.change_password_current_password = ""
            self.change_password_new_password = ""
            self.change_password_confirm_password = ""
            self.change_password_2fa = ""
            self.change_password_new_password_strength = 0
            self.change_password_passwords_match = False
            self.error_message = ""
            
            # Force refresh to update UI
            self.force_refresh()
            
        except Exception as e:
            self.error_message = f"Failed to update password: {str(e)}"

    async def _on_save_profile_pressed(self) -> None:
        """Handle saving profile information to the database."""
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]

        try:
            # Validate and sanitize inputs
            sanitized_display_name = None
            sanitized_bio = None

            if self.profile_display_name:
                sanitized_display_name = SecuritySanitizer.sanitize_string(
                    self.profile_display_name, 100
                )

            if self.profile_bio:
                sanitized_bio = SecuritySanitizer.sanitize_string(
                    self.profile_bio, 2000
                )

            # Update profile in database
            updated_profile = await persistence.update_profile(
                user_id=str(user_session.user_id),
                full_name=sanitized_display_name,
                bio=sanitized_bio
            )

            if updated_profile:
                self.profile_success_message = "Profile updated successfully!"
                self.error_message = ""
            else:
                self.error_message = "Failed to update profile. Profile not found."
                self.profile_success_message = ""

        except Exception as e:
            self.error_message = f"Failed to update profile: {str(e)}"
            self.profile_success_message = ""

    async def _on_delete_account_pressed(self) -> None:
        """Handle the account deletion process."""
        # Validate confirmation text
        try:
            sanitized_confirmation = SecuritySanitizer.sanitize_string(self.delete_account_confirmation, 50)
            if sanitized_confirmation != "DELETE MY ACCOUNT":
                self.delete_account_error = "Please type 'DELETE MY ACCOUNT' exactly to confirm deletion"
                return
        except Exception:
            self.delete_account_error = "Invalid confirmation text"
            return

        # Validate 2FA code if provided
        if self.two_factor_enabled and self.delete_account_2fa:
            try:
                sanitized_2fa = SecuritySanitizer.sanitize_auth_code(self.delete_account_2fa)
            except Exception:
                self.delete_account_error = "Invalid 2FA or recovery code format"
                return

            if not sanitized_2fa:
                self.delete_account_error = "Invalid 2FA or recovery code format"
                return

            self.delete_account_2fa = sanitized_2fa

        user_session = self.session[UserSession]
        persistence = self.session[Persistence]

        success = await persistence.delete_user(
            user_id=user_session.user_id,
            password=self.delete_account_password,
            two_factor_code=self.delete_account_2fa if self.two_factor_enabled else None
        )

        if success:
            print("Account deleted successfully")
            # Redirect to login page
            self.session.navigate_to("/")
        else:
            self.delete_account_error = "Failed to delete account. Please check your password and 2FA code."

    async def _on_logout_all_devices_pressed(self) -> None:
        """Handle the logout all devices button click."""
        user_session = self.session[UserSession]
        persistence = self.session[Persistence]

        # Invalidate all sessions for this user
        await persistence.invalidate_all_sessions(user_session.user_id)

        # Detach everything from the current session
        self.session.detach(AppUser)
        self.session.detach(UserSession)

        # Navigate to the login page
        self.session.navigate_to("/")

    def build(self) -> rio.Component:

        return CenterComponent(
            rio.Column(
                rio.Text(
                    "Settings",
                    style="heading1",
                    margin_bottom=2,
                ),

                self.currency_overview and CurrencySummary(
                    overview=self.currency_overview,
                    title="Your Balance",
                ) or rio.Card(
                    rio.Text("Balance information unavailable", style="dim"),
                    color="hud",
                ),

                # Profile Section
                rio.Text(
                    "Profile Settings",
                    style="heading2",
                    margin_top=2,
                    margin_bottom=1,
                ),

                rio.Column(
                    rio.Banner(
                        text=self.profile_success_message,
                        style="success",
                        margin_bottom=1,
                    ) if self.profile_success_message else rio.Spacer(min_height=0),
                    rio.TextInput(
                        label="Display Name",
                        text=self.bind().profile_display_name,
                        margin_bottom=1,
                    ),
                    rio.Text(
                        f"Account Email: {self.account_email}",
                        margin_bottom=1,
                    ),
                    rio.MultiLineTextInput(
                        label="Bio",
                        text=self.bind().profile_bio,
                        min_height=4,
                        margin_bottom=1,
                    ),
                    rio.Button(
                        "Save Profile",
                        on_press=self._on_save_profile_pressed,
                        shape="rounded",
                    ),
                    spacing=1,
                ),

                # Notifications Section
                rio.Text(
                    "Notifications",
                    style="heading2",
                    margin_top=2,
                    margin_bottom=1,
                ),

                rio.Column(
                    rio.Row(
                        rio.Text("Email Notifications"),
                        rio.Switch(
                            is_on=self.email_notifications_enabled,
                            on_change=self._on_email_notifications_switch_pressed,
                        ),
                        spacing=1,
                    ),
                    rio.Row(
                        rio.Text("SMS Notifications"),
                        rio.Switch(
                            is_on=self.sms_notifications_enabled,
                            on_change=self._on_sms_notifications_switch_pressed,
                        ),
                        spacing=1,
                    ),
                ),

                # Security Section
                rio.Text(
                    "Security Settings",
                    style="heading2",
                    margin_top=2,
                    margin_bottom=1,
                ),
                rio.Card(
                    rio.Column(
                        rio.Text(
                            "Change Password",
                            style="heading3",
                        ),
                        rio.Banner(
                            text=self.error_message,
                            style="danger",
                            margin_top=1,
                        ),
                        rio.Row(
                            rio.TextInput(
                                label="Current Password",
                                text=self.bind().change_password_current_password,
                                is_secret=True,
                            ),
                            rio.TextInput(
                                label="New Password",
                                text=self.bind().change_password_new_password,
                                is_secret=True,
                                on_change=self.on_change_new_password,
                            ),
                            rio.TextInput(
                                label="Confirm Password",
                                text=self.bind().change_password_confirm_password,
                                is_secret=True,
                                on_change=self.on_change_confirm_password,
                            ),
                            rio.TextInput(
                                label="2FA / Recovery Code",
                                text=self.bind().change_password_2fa,
                            ),
                            rio.Button(
                                "Confirm Password Change",
                                on_press=self._on_confirm_password_change_pressed,
                                shape="rounded",
                            ),
                            spacing=1,
                        ),
                        # Password strength visuals
                        rio.Text(
                            f"Passwords match: {self.change_password_passwords_match}",
                            style=rio.TextStyle(
                                fill=rio.Color.from_rgb(0, 1, 0)
                                if self.change_password_passwords_match else rio.Color.from_rgb(1, 0, 0)
                            )
                        ),
                        rio.Text(
                            f"Password strength: {self.change_password_new_password_strength}, "
                            f"{get_password_strength_status(self.change_password_new_password_strength)}",
                            style=rio.TextStyle(
                                fill=get_password_strength_color(self.change_password_new_password_strength)
                            )
                        ),
                        self.new_password_strength_progress(),

                        rio.Link(
                            rio.Button(
                                "Disable Two-Factor Authentication" if self.two_factor_enabled else "Enable Two-Factor Authentication",
                                shape="rounded",
                            ),
                            target_url="/app/disable-mfa" if self.two_factor_enabled else "/app/enable-mfa",
                        ),
                        rio.Column(
                            rio.Text(
                                "Recovery Codes",
                                style="heading3",
                                margin_top=2,
                            ),
                            rio.Banner(
                                text=self.recovery_code_notice,
                                style="warning",
                                margin_top=1,
                            ) if self.recovery_code_notice else rio.Spacer(min_height=0),
                            rio.Text(self.recovery_codes_summary_text()),
                            rio.Text(f"Last generated: {self.recovery_codes_last_generated}"),
                            *(
                                [
                                    rio.Link(
                                        rio.Button(
                                            "Manage Recovery Codes",
                                            shape="rounded",
                                        ),
                                        target_url="/app/recovery-codes",
                                    )
                                ]
                                if self.two_factor_enabled
                                else [
                                    rio.Text(
                                        "Enable two-factor authentication to generate recovery codes.",
                                        margin_top=0.5,
                                    )
                                ]
                            ),
                            spacing=1,
                        ),

                        rio.Button(
                            "Logout from All Devices",
                            on_press=self._on_logout_all_devices_pressed,
                            shape="rounded",
                        ),

                        rio.Text(
                            "Delete Account",
                            style="heading3",
                            margin_top=2,
                            margin_bottom=1,
                        ),

                        rio.Row(
                            rio.TextInput(
                                label="Password",
                                text=self.bind().delete_account_password,
                                is_secret=True,
                            ),
                            rio.TextInput(
                                label="2FA / Recovery Code",
                                text=self.bind().delete_account_2fa,
                            ),
                            rio.TextInput(
                                label='Type "DELETE MY ACCOUNT" to confirm',
                                text=self.bind().delete_account_confirmation,
                            ),
                            rio.Button(
                                "Delete Account",
                                on_press=self._on_delete_account_pressed,
                                shape="rounded",
                            ),
                            spacing=1,
                        ),

                        rio.Banner(
                            text=self.delete_account_error,
                            style="danger",
                            margin_top=1,
                            # visible=bool(self.delete_account_error),
                        ),

                        spacing=2,
                    ),

                ),
                spacing=1,
                margin=2,
            ),
            width_percent=70
        )
