from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t
from datetime import datetime, timezone
import uuid
import pandas as pd

import rio
from app.persistence import Persistence
from app.data_models import AppUser, UserSession
from app.components.center_component import CenterComponent
from app.permissions import get_manageable_roles, can_manage_role

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
    change_role_username: str = ""
    change_role_new_role: str = "user"
    change_role_error: str = ""
    
    
    # User deletion fields
    delete_user_username: str = ""
    delete_user_confirmation: str = ""
    delete_user_error: str = ""
    
    @rio.event.on_populate
    def on_populate(self):
        """Load all users when the page is populated"""
        persistence = self.session[Persistence]
        cursor = persistence.conn.cursor()
        
        # Get current user
        user_session = self.session[UserSession]
        cursor.execute("SELECT id, username, created_at, role, is_verified FROM users WHERE id = ?", (str(user_session.user_id),))
        user_row = cursor.fetchone()
        if user_row:
            self.current_user = AppUser(
                id=uuid.UUID(user_row[0]),
                username=user_row[1],
                created_at=datetime.fromtimestamp(user_row[2], tz=timezone.utc),
                password_hash=b"",
                password_salt=b"",
                role=user_row[3],
                is_verified=bool(user_row[4])
            )
        
        # Get all users from the database
        cursor.execute("SELECT id, username, created_at, role, is_verified FROM users")
        rows = cursor.fetchall()
        
        # Convert rows to AppUser objects and DataFrame
        self.users = []
        self.selected_role = {}
        
        data = []
        for row in rows:
            user_id = uuid.UUID(row[0])
            username = row[1]
            created_at = datetime.fromtimestamp(row[2], tz=timezone.utc)
            role = row[3]
            is_verified = bool(row[4])
            
            user = AppUser(
                id=user_id,
                username=username,
                created_at=created_at,
                password_hash=b"",
                password_salt=b"",
                role=role,
                is_verified=is_verified
            )
            self.users.append(user)
            self.selected_role[str(user_id)] = role
            
            # Add to DataFrame data
            data.append({
                'Username': username,
                'Created At': created_at.strftime("%Y-%m-%d %H:%M:%S"),
                'Role': role,
                'Verified': '✓' if is_verified else '✗',
                'ID': str(user_id)
            })
        
        # Create DataFrame
        self.df = pd.DataFrame(data)
    

    def _on_change_role_pressed(self) -> None:
        if not self.change_role_username or self.change_role_username == "":
            self.change_role_error = "Please enter a username"
            return
            
        if not self.change_role_new_role or self.change_role_new_role == "":
            self.change_role_error = "Please enter a new role"
            return
            
        self._update_role(self.change_role_username, self.change_role_new_role)
        self.change_role_username = ""
        self.change_role_new_role = ""
        
        self.force_refresh()

    def _update_role(self, username: str, new_role: str) -> None:
        """Update a user's role"""
        if not self.current_user:
            self.change_role_error = "You must be logged in to perform this action"
            return
            
        persistence = self.session[Persistence]
        cursor = persistence.conn.cursor()
        
        # Get the target user's current role
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            self.change_role_error = f"User {username} not found"
            return
            
        current_role = result[0]
        
        # Check if the current user can manage both the user's current and new roles
        if not (can_manage_role(self.current_user.role, current_role) and 
                can_manage_role(self.current_user.role, new_role)):
            self.change_role_error = f"You do not have permission to change role from {current_role} to {new_role} because your role is {self.current_user.role}"
            return
            
        try:
            cursor.execute(
                "UPDATE users SET role = ? WHERE username = ?",
                (new_role, username)
            )
            persistence.conn.commit()
            
            # Clear error on success
            self.change_role_error = ""
            
            # Refresh the page to show updated roles
            self.on_populate()
        except Exception as e:
            self.change_role_error = f"Error updating role: {str(e)}"
        
    def _on_delete_user_pressed(self) -> None:
        """Handle the user deletion process from admin panel."""
        if not self.current_user:
            self.delete_user_error = "You must be logged in to perform this action"
            return
            
        if not self.delete_user_username or self.delete_user_username == "":
            self.delete_user_error = "Please enter a username to delete"
            return
            
        if self.delete_user_confirmation != f"DELETE USER {self.delete_user_username}":
            self.delete_user_error = f'Please type "DELETE USER {self.delete_user_username}" exactly to confirm deletion'
            return
            
        persistence = self.session[Persistence]
        cursor = persistence.conn.cursor()
        
        # Get the target user's information
        cursor.execute("SELECT id, role FROM users WHERE username = ?", (self.delete_user_username,))
        result = cursor.fetchone()
        if not result:
            self.delete_user_error = f"User not found: {self.delete_user_username}"
            return
            
        target_user_id = uuid.UUID(result[0])
        target_role = result[1]
        
        # Check if current user has permission to delete this user
        if not can_manage_role(self.current_user.role, target_role):
            self.delete_user_error = f"You do not have permission to delete users with role: {target_role} because your role is {self.current_user.role}"
            return
            
        # Admin deletion password with special characters, numbers, and mixed case
        ADMIN_DELETION_PASSWORD = "UserD3l3t!0n@AdminP4n3l"
            
        # Delete the user
        try:
            success = persistence.delete_user(
                user_id=target_user_id,
                password=ADMIN_DELETION_PASSWORD,  # Use secure admin deletion password
                two_factor_code=None  # No 2FA needed for admin deletion
            )
            if success:
                # Clear the fields
                self.delete_user_username = ""
                self.delete_user_confirmation = ""
                self.delete_user_error = ""
                # Refresh the page to show updated user list
                self.on_populate()
            else:
                self.delete_user_error = "Failed to delete user"
        except Exception as e:
            self.delete_user_error = f"Error deleting user: {str(e)}"
    
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
                    label="Username to Change Role",
                    text=self.bind().change_role_username,
                ),
                rio.Dropdown(
                    label="New Role",
                    # options=get_manageable_roles(self.current_user.role),
                    options={
                        "admin": "admin",
                        "user": "user",
                        "root": "root"
                    },
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
                f"about to change {self.change_role_username}'s role to {self.change_role_new_role}",
                margin_top=1,
            ),
            
            rio.Banner(
                text=self.change_role_error,
                style="danger",
                margin_top=1,
            ),

            
            rio.Text(
                "Delete User",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),
            
            rio.Row(
                rio.TextInput(
                    label="Username to Delete",
                    text=self.bind().delete_user_username,
                ),
                rio.TextInput(
                    label='Type "DELETE USER username" to confirm',
                    text=self.bind().delete_user_confirmation,
                ),
                rio.Button(
                    "Delete User",
                    on_press=self._on_delete_user_pressed,
                    shape="rounded",
                ),
                spacing=1,
                proportions=[1, 1, 1],
            ),
            
            rio.Banner(
                text=self.delete_user_error,
                style="danger",
                margin_top=1,
            ),
            
            align_x=0.5,
            min_width=80,
        )
