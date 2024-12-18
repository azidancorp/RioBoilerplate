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
    
    @rio.event.on_populate
    async def on_populate(self):
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
    
    async def on_role_changed(self, user_id: str, event: rio.SelectChangeEvent):
        """Handle role change for a user"""
        if not self.current_user:
            return
            
        # Get the target user
        target_user = next((u for u in self.users if str(u.id) == user_id), None)
        if not target_user:
            return
            
        # Check if current user can manage the target user's role
        if not can_manage_role(self.current_user.role, target_user.role):
            return
            
        persistence = self.session[Persistence]
        cursor = persistence.conn.cursor()
        
        # Update the role in the database
        cursor.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (event.value, user_id)
        )
        persistence.conn.commit()
        
        # Update the selected role in our state
        self.selected_role[user_id] = event.value
        
        # Update DataFrame
        if self.df is not None:
            self.df.loc[self.df['ID'] == user_id, 'Role'] = event.value
        
        # Force a refresh to update the UI
        self.force_refresh()

    def build(self) -> rio.Component:
        if not self.current_user or self.df is None:
            return rio.Text("Error: Could not load user information")
            
        return rio.Column(
            rio.Text(
                "User Management",
                style=rio.TextStyle(font_size=2.0, font_weight="bold"),
                margin_bottom=2,
            ),
            
            # Users table
            rio.Card(
                rio.Column(
                    rio.Text(
                        "All Users",
                        style=rio.TextStyle(font_size=1.5, font_weight="bold"),
                        margin_bottom=1,
                    ),
                    
                    rio.Table(
                        data=self.df,
                        show_row_numbers=False
                    ),
                    
                    margin=2,
                ),
                margin=2,
            ),
            
            align_x=0.5,
            min_width=80,
        )
