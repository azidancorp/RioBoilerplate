from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t
from datetime import datetime, timezone
import uuid

import rio
from app.persistence import Persistence
from app.data_models import AppUser, UserSession
from app.components.center_component import CenterComponent

@rio.page(
    name="AdminPage",
    url_segment="admin",
)
class AdminPage(rio.Component):
    """
    Admin page for managing users and their roles.
    Only accessible to users with the admin role.
    """
    
    # Keep track of users and their current roles
    users: t.List[AppUser] = field(default_factory=list)
    selected_role: t.Dict[str, str] = field(default_factory=dict)
    
    @rio.event.on_populate
    async def on_populate(self):
        """Load all users when the page is populated"""
        persistence = self.session[Persistence]
        cursor = persistence.conn.cursor()
        
        # Get all users from the database
        cursor.execute("SELECT id, username, created_at, role, is_verified FROM users")
        rows = cursor.fetchall()
        
        # Convert rows to AppUser objects
        self.users = []
        self.selected_role = {}
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
                password_hash=b"",  # We don't need the password info
                password_salt=b"",
                role=role,
                is_verified=is_verified
            )
            self.users.append(user)
            self.selected_role[str(user_id)] = role
    
    async def on_role_changed(self, user_id: str, event: rio.SelectChangeEvent):
        """Handle role change for a user"""
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
        
        # Force a refresh to update the UI
        self.force_refresh()

    def build(self) -> rio.Component:
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
                    
                    # Table header
                    rio.Grid(
                        [
                            rio.Text("Username", style=rio.TextStyle(font_weight="bold")),
                            rio.Text("Created At", style=rio.TextStyle(font_weight="bold")),
                            rio.Text("Role", style=rio.TextStyle(font_weight="bold")),
                            rio.Text("Verified", style=rio.TextStyle(font_weight="bold")),
                        ],
                        column_spacing=2,
                        margin_bottom=1,
                    ),
                    
                    # Table rows
                    *[
                        rio.Grid(
                            [
                                rio.Text(user.username),
                                rio.Text(user.created_at.strftime("%Y-%m-%d %H:%M:%S")),
                                # rio.Select(
                                #     options=[
                                #         rio.SelectOption("user", "User"),
                                #         rio.SelectOption("admin", "Admin"),
                                #     ],
                                #     value=self.selected_role[str(user.id)],
                                #     on_change=lambda e, uid=str(user.id): self.on_role_changed(uid, e),
                                # ),
                                # rio.Icon(
                                #     "check" if user.is_verified else "close",
                                #     fill="green" if user.is_verified else "red",
                                # ),
                            ],
                            column_spacing=2,
                            margin_bottom=0.5,
                        )
                        for user in self.users
                    ],
                    
                    margin=2,
                ),
                margin=2,
            ),
            
            align_x=0.5,
            min_width=80,
        )
