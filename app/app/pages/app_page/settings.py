from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t

from paramiko import ssh_exception
import rio
from app.persistence import Persistence
from app.data_models import AppUser, UserSession
from app.components.center_component import CenterComponent


@rio.page(
    name="Settings",
    url_segment="settings",
)
class Settings(rio.Component):
    """
    Settings page containing various user configuration options.
    """
    
    email_notifications_enabled: bool = True
    sms_notifications_enabled: bool = False
    two_factor_enabled: bool = False
    
    change_password_current_password: str = ""
    change_password_new_password: str = ""
    change_password_confirm_password: str = ""
    change_password_2fa: str = ""
    
    delete_account_password: str = ""
    delete_account_2fa: str = ""
    delete_account_confirmation: str = ""
    delete_account_error: str = ""
    
    @rio.event.on_populate
    async def on_populate(self):
        user_session = self.session[UserSession]
        persistence = Persistence()
        user = await persistence.get_user_by_id(user_session.user_id)
        self.two_factor_enabled = bool(user.two_factor_secret)
        # print(f"2FA is {'enabled' if self.two_factor_enabled else 'disabled'}")
    

    def _on_email_notifications_switch_pressed(self, event: rio.SwitchChangeEvent):
        self.email_notifications_enabled = event.is_on
        # print(f"Email notifications are now {'enabled' if self.email_notifications_enabled else 'disabled'}")
        
    def _on_sms_notifications_switch_pressed(self, event: rio.SwitchChangeEvent):
        self.sms_notifications_enabled = event.is_on
        # print(f"SMS notifications are now {'enabled' if self.sms_notifications_enabled else 'disabled'}")
    
    
    async def _on_confirm_password_change_pressed(self) -> None:
        user_session = self.session[UserSession]
        persistence = Persistence()
        # # print("change password for", user_session.user_id)
        # await persistence.change_password(user_session.user_id, self.session[UserSession].password)
    
    async def _on_delete_account_pressed(self) -> None:
        """Handle the account deletion process."""
        if self.delete_account_confirmation != "DELETE MY ACCOUNT":
            self.delete_account_error = "Please type 'DELETE MY ACCOUNT' exactly to confirm deletion"
            return
        
        user_session = self.session[UserSession]
        persistence = Persistence()
        
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
                
                # Profile Section
                rio.Text(
                    "Profile Settings",
                    style="heading2",
                    margin_top=2,
                    margin_bottom=1,
                ),
                
                rio.Column(
                    rio.TextInput(
                        label="Display Name",
                        margin_bottom=1,
                    ),
                    rio.TextInput(
                        label="Email",
                        margin_bottom=1,
                    ),
                    rio.MultiLineTextInput(
                        label="Bio",
                        min_height=4,
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
                            ),
                            rio.TextInput(
                                label="Confirm Password",
                                text=self.bind().change_password_confirm_password,
                                is_secret=True,
                            ),
                            rio.TextInput(
                                label="2FA Code",
                                text=self.bind().change_password_2fa,
                            ),
                            rio.Button(
                                "Confirm Password Change",
                                on_press=self._on_confirm_password_change_pressed,
                                shape="rounded",
                            ),
                            spacing=1,
                        ),
                        
                        rio.Link(
                            rio.Button(
                                "Disable Two-Factor Authentication" if self.two_factor_enabled else "Enable Two-Factor Authentication",
                                shape="rounded",
                            ),
                            target_url="/app/disable-mfa" if self.two_factor_enabled else "/app/enable-mfa",
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
                                label="2FA Code",
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