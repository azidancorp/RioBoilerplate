from __future__ import annotations

from dataclasses import field
from decimal import Decimal, InvalidOperation
import uuid
import os
import typing as t
import pandas as pd

import rio
from app.persistence import Persistence
from app.data_models import AppUser, UserSession
from app.permissions import can_manage_role, get_manageable_roles, get_default_role
from app.currency import major_to_minor, format_minor_amount, attach_currency_name
from app.validation import SecuritySanitizer

@rio.page(
    name="AdminPage",
    url_segment="admin",
)
class AdminPage(rio.Component):
    """
    Admin page for managing users and their roles.
    Only accessible to users with admin or root roles.
    """
    
    # Keep track of users and their current roles
    users: t.List[AppUser] = field(default_factory=list)
    selected_role: t.Dict[str, str] = field(default_factory=dict)
    current_user: AppUser | None = None
    df: pd.DataFrame | None = None
    
    # User change role fields
    change_role_identifier: str = ""
    change_role_new_role: str = field(default_factory=get_default_role)
    change_role_error: str = ""
    
    
    # User deletion fields
    delete_user_identifier: str = ""
    delete_user_confirmation: str = ""
    delete_user_password: str = ""
    delete_user_error: str = ""
    delete_user_success: str = ""

    # Currency management fields
    currency_user_identifier: str = ""
    currency_amount: str = ""
    currency_reason: str = ""
    currency_mode_is_set: bool = False  # False -> adjust delta, True -> set absolute
    currency_error: str = ""
    currency_success: str = ""
    
    @rio.event.on_populate
    async def on_populate(self):
        """Load all users when the page is populated."""
        await self._load_user_data()

    async def _load_user_data(self) -> None:
        """Populate component state with the latest user data."""
        persistence = self.session[Persistence]
        user_session = self.session[UserSession]

        try:
            self.current_user = await persistence.get_user_by_id(user_session.user_id)
        except KeyError:
            self.current_user = None
            self.users = []
            self.selected_role = {}
            self.df = pd.DataFrame([])
            return

        self.users = await persistence.list_users()
        self.selected_role = {str(user.id): user.role for user in self.users}

        data = []
        for user in self.users:
            data.append({
                "Email": user.email,
                "Username": user.username or "",
                "Created At": user.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Role": user.role,
                "Verified": "✓" if user.is_verified else "✗",
                "Balance": attach_currency_name(
                    format_minor_amount(user.primary_currency_balance),
                    quantity_minor_units=user.primary_currency_balance,
                ),
                "ID": str(user.id),
            })

        self.df = pd.DataFrame(data)

    async def _on_change_role_pressed(self) -> None:
        identifier = (self.change_role_identifier or "").strip()
        new_role = (self.change_role_new_role or "").strip()

        if not identifier:
            self.change_role_error = "Please enter an email or username"
            self.force_refresh()
            return
            
        if not new_role:
            self.change_role_error = "Please enter a new role"
            self.force_refresh()
            return

        updated = await self._update_role(identifier, new_role)
        if updated:
            self.change_role_identifier = ""
            self.change_role_new_role = get_default_role()
            await self._load_user_data()

        self.force_refresh()

    async def _update_role(self, identifier: str, new_role: str) -> bool:
        """Update a user's role."""
        if not self.current_user:
            self.change_role_error = "You must be logged in to perform this action"
            return False

        persistence = self.session[Persistence]
        try:
            target_user = await persistence.get_user_by_email_or_username(identifier)
        except KeyError:
            self.change_role_error = f"User {identifier} not found"
            return False

        current_role = target_user.role

        try:
            can_manage_target = can_manage_role(self.current_user.role, current_role)
            can_manage_new = can_manage_role(self.current_user.role, new_role)
        except ValueError:
            self.change_role_error = f"Unknown role: {new_role}"
            return False

        # Check if the current user can manage both the user's current and new roles
        if not (can_manage_target and can_manage_new):
            self.change_role_error = (
                f"You do not have permission to change role from {current_role} to "
                f"{new_role} because your role is {self.current_user.role}"
            )
            return False

        try:
            self.change_role_error = ""
            await persistence.update_user_role(target_user.id, new_role)
            return True
        except Exception as exc:
            self.change_role_error = f"Error updating role: {str(exc)}"
            return False
        
    async def _on_delete_user_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """Handle the user deletion process from admin panel."""
        if not self.current_user:
            self.delete_user_error = "You must be logged in to perform this action"
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        if not self.delete_user_identifier or self.delete_user_identifier == "":
            self.delete_user_error = "Please enter an email or username to delete"
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        if self.delete_user_confirmation != f"DELETE USER {self.delete_user_identifier}":
            self.delete_user_error = f'Please type "DELETE USER {self.delete_user_identifier}" exactly to confirm deletion'
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        persistence = self.session[Persistence]

        try:
            target_user = await persistence.get_user_by_email_or_username(self.delete_user_identifier)
        except KeyError:
            self.delete_user_error = f"User not found: {self.delete_user_identifier}"
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        target_role = target_user.role
        
        # Check if current user has permission to delete this user
        if not can_manage_role(self.current_user.role, target_role):
            self.delete_user_error = f"You do not have permission to delete users with role: {target_role} because your role is {self.current_user.role}"
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        # Validate admin deletion password
        if not self.delete_user_password or self.delete_user_password == "":
            self.delete_user_error = "Please enter the admin deletion password"
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        # Check admin deletion password against environment variable
        ADMIN_DELETION_PASSWORD = os.getenv('ADMIN_DELETION_PASSWORD')
        if ADMIN_DELETION_PASSWORD is None:
            self.delete_user_error = "ADMIN_DELETION_PASSWORD environment variable is not set. Please configure your environment variables."
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        if self.delete_user_password != ADMIN_DELETION_PASSWORD:
            self.delete_user_error = "Incorrect admin deletion password"
            self.delete_user_success = ""
            self.force_refresh()
            return
            
        # Store username for success message
        identifier_to_delete = self.delete_user_identifier

        # Delete the user
        try:
            success = await persistence.delete_user(
                user_id=target_user.id,
                password=self.delete_user_password,  # Use entered admin deletion password
                two_factor_code=None  # No 2FA needed for admin deletion
            )
            if success:
                # Set success message
                self.delete_user_success = f"User '{identifier_to_delete}' has been successfully deleted"
                # Clear the fields
                self.delete_user_identifier = ""
                self.delete_user_confirmation = ""
                self.delete_user_password = ""
                self.delete_user_error = ""
                # Refresh the page to show updated user list
                await self._load_user_data()
                self.force_refresh()
            else:
                self.delete_user_error = "Failed to delete user"
                self.delete_user_success = ""
                self.force_refresh()
        except Exception as e:
            self.delete_user_error = f"Error deleting user: {str(e)}"
            self.delete_user_success = ""
            self.force_refresh()

    async def _on_currency_submit(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """Handle currency adjustments or absolute updates."""
        if not self.current_user:
            self.currency_error = "You must be logged in to perform this action"
            self.currency_success = ""
            self.force_refresh()
            return

        identifier = (self.currency_user_identifier or "").strip()
        if not identifier:
            self.currency_error = "Please provide a user email, username, or ID"
            self.currency_success = ""
            self.force_refresh()
            return

        try:
            amount_decimal = Decimal((self.currency_amount or "").strip())
        except (InvalidOperation, AttributeError):
            self.currency_error = "Enter a valid numeric amount"
            self.currency_success = ""
            self.force_refresh()
            return

        persistence = self.session[Persistence]

        target_user: AppUser | None = None
        try:
            target_user = await persistence.get_user_by_id(uuid.UUID(identifier))
        except (ValueError, KeyError):
            try:
                target_user = await persistence.get_user_by_email_or_username(identifier)
            except KeyError:
                target_user = None

        if not target_user:
            self.currency_error = f"User not found: {identifier}"
            self.currency_success = ""
            self.force_refresh()
            return

        # Ensure the admin has permission to manage this user when roles differ.
        if (
            self.current_user.id != target_user.id
            and not can_manage_role(self.current_user.role, target_user.role)
        ):
            self.currency_error = (
                f"You do not have permission to update balances for users with role {target_user.role}."
            )
            self.currency_success = ""
            self.force_refresh()
            return

        reason = None
        if self.currency_reason:
            try:
                sanitized_reason = SecuritySanitizer.sanitize_string(self.currency_reason, 200)
            except Exception:
                sanitized_reason = None
            reason = sanitized_reason

        try:
            minor_amount = major_to_minor(amount_decimal)
        except ValueError:
            self.currency_error = "Amount must be a valid number"
            self.currency_success = ""
            self.force_refresh()
            return

        try:
            if self.currency_mode_is_set:
                entry = await persistence.set_currency_balance(
                    target_user.id,
                    new_balance_minor=minor_amount,
                    reason=reason,
                    metadata=None,
                    actor_user_id=self.current_user.id,
                )
                action_word = "Set"
            else:
                entry = await persistence.adjust_currency_balance(
                    target_user.id,
                    delta_minor=minor_amount,
                    reason=reason,
                    metadata=None,
                    actor_user_id=self.current_user.id,
                )
                action_word = "Adjusted"
        except ValueError as exc:
            self.currency_error = str(exc)
            self.currency_success = ""
            self.force_refresh()
            return

        delta_text = attach_currency_name(
            format_minor_amount(entry.delta), quantity_minor_units=entry.delta
        )
        balance_text = attach_currency_name(
            format_minor_amount(entry.balance_after), quantity_minor_units=entry.balance_after
        )

        self.currency_success = (
            f"{action_word} {target_user.email or target_user.username}'s balance. "
            f"Delta: {delta_text}. New balance: {balance_text}."
        )
        self.currency_error = ""
        self.currency_amount = ""
        await self._load_user_data()
        self.force_refresh()

    def _on_currency_mode_toggle(self, event: rio.SwitchChangeEvent) -> None:
        """Toggle between adjust and set modes."""
        self.currency_mode_is_set = event.is_on
        self.force_refresh()

    def build(self) -> rio.Component:
        if not self.current_user or self.df is None:
            return rio.Text("Error: Could not load user information")
            
        return rio.Column(
            rio.Text(
                "User Management",
                style="heading1",
                margin_bottom=2,
            ),
            
            # Users table
            rio.Card(
                rio.Column(
                    rio.Text(
                        "All Users",
                        style="heading2",
                        margin_bottom=1,
                    ),
                    
                    rio.Table(
                        data=self.df,
                        show_row_numbers=False
                    ),
                    
                    margin=2,
                ),
            ),
            
            # User Management
            rio.Text(
                "User Management",
                style="heading2",
                margin_top=2,
                margin_bottom=1,
            ),
            
            rio.Text(
                "Change Role",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),


            rio.Row(
                rio.TextInput(
                    label="Email or Username to Change Role",
                    text=self.bind().change_role_identifier,
                ),
                rio.Dropdown(
                    label="New Role",
                    options={role: role for role in get_manageable_roles(self.current_user.role)},
                    selected_value=self.bind().change_role_new_role,
                ),
                rio.Button(
                    "Change Role",
                    on_press=self._on_change_role_pressed,
                    shape="rounded",
                ),
                spacing=1,
                proportions=[1, 1, 1],
            ),

            rio.Text(
                f"about to change {self.change_role_identifier}'s role to {self.change_role_new_role}",
                margin_top=1,
            ),
            
            rio.Banner(
                text=self.change_role_error,
                style="danger",
                margin_top=1,
            ),


            rio.Text(
                "Currency Management",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            rio.Row(
                rio.TextInput(
                    label="User Email / Username / ID",
                    text=self.bind().currency_user_identifier,
                ),
                rio.TextInput(
                    label="Amount",
                    text=self.bind().currency_amount,
                    on_confirm=self._on_currency_submit,
                ),
                rio.TextInput(
                    label="Reason (optional)",
                    text=self.bind().currency_reason,
                    on_confirm=self._on_currency_submit,
                ),
                spacing=1,
                proportions=[1, 1, 1],
            ),

            rio.Row(
                rio.Text("Set absolute balance"),
                rio.Switch(
                    is_on=self.currency_mode_is_set,
                    on_change=self._on_currency_mode_toggle,
                ),
                rio.Button(
                    "Apply",
                    on_press=self._on_currency_submit,
                    shape="rounded",
                ),
                spacing=1,
            ),

            rio.Banner(
                text=self.currency_success,
                style="success",
                margin_top=1,
            ) if self.currency_success else rio.Spacer(),

            rio.Banner(
                text=self.currency_error,
                style="danger",
                margin_top=1,
            ) if self.currency_error else rio.Spacer(),

            
            rio.Text(
                "Delete User",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),
            
            rio.Row(
                rio.TextInput(
                    label="Email or Username to Delete",
                    text=self.bind().delete_user_identifier,
                    on_confirm=self._on_delete_user_pressed
                ),
                rio.TextInput(
                    label='Type "DELETE USER identifier" to confirm',
                    text=self.bind().delete_user_confirmation,
                    on_confirm=self._on_delete_user_pressed
                ),
                rio.TextInput(
                    label="Admin Deletion Password",
                    text=self.bind().delete_user_password,
                    is_secret=True,
                    on_confirm=self._on_delete_user_pressed
                ),
                rio.Button(
                    "Delete User",
                    on_press=self._on_delete_user_pressed,
                    shape="rounded",
                ),
                spacing=1,
                proportions=[1, 1, 1, 1],
            ),
            
            rio.Banner(
                text=self.delete_user_success,
                style="success",
                margin_top=1,
            ) if self.delete_user_success else rio.Spacer(),
            
            rio.Banner(
                text=self.delete_user_error,
                style="danger",
                margin_top=1,
            ) if self.delete_user_error else rio.Spacer(),
            
            align_x=0.5,
            min_width=80,
        )
