from __future__ import annotations

from dataclasses import KW_ONLY, field
import re
import warnings

import rio
import app.theme as theme
from app.data_models import AppUser
from app.permissions import PAGE_ROLE_MAPPING, get_highest_privilege_role


# Define all possible sidebar links with their paths and icons
# This is the single source of truth for sidebar navigation
ALL_SIDEBAR_LINKS = [
    ("Dashboard", "/app/dashboard", "dashboard"),
    ("Admin", "/app/admin", "admin-panel-settings"),
    ("Test", "/app/test", "science"),
    ("News", "/app/news", "newspaper"),
    ("Notifications", "/app/notifications", "notifications"),
    ("Settings", "/app/settings", "settings"),
]

EXCLUDED_FROM_SIDEBAR = {
    "/app/enable-mfa",
    "/app/disable-mfa",
    "/app/recovery-codes",
}


def _validate_sidebar_configuration() -> None:
    """
    Validate that sidebar URLs and PAGE_ROLE_MAPPING are in sync.

    This function runs once at module import time to catch configuration
    mismatches during development rather than at runtime.
    """
    sidebar_urls = {url for _, url, _ in ALL_SIDEBAR_LINKS}

    # Check if all sidebar URLs are defined in PAGE_ROLE_MAPPING
    for _, url, _ in ALL_SIDEBAR_LINKS:
        if url not in PAGE_ROLE_MAPPING:
            warnings.warn(
                f"Sidebar URL '{url}' is not defined in PAGE_ROLE_MAPPING",
                RuntimeWarning,
                stacklevel=2
            )

    # Check if all app URLs in PAGE_ROLE_MAPPING are defined in sidebar
    # (excluding special pages like MFA setup that shouldn't be in sidebar)
    for url in PAGE_ROLE_MAPPING:
        if url.startswith("/app/") and url not in sidebar_urls and url not in EXCLUDED_FROM_SIDEBAR:
            warnings.warn(
                f"PAGE_ROLE_MAPPING URL '{url}' is not defined in sidebar links",
                RuntimeWarning,
                stacklevel=2
            )


# Run validation once at module import time
_validate_sidebar_configuration()


class SideBarLink(rio.Component):
    title: str
    url: str
    icon: str
    
    @rio.event.on_page_change
    def on_page_change(self) -> None:
        self.force_refresh()

    def build(self) -> rio.Component:
        # Get the URL segment of the active page for comparison.
        try:
            active_page_url_segment = self.session.active_page_instances[1].url_segment
        except IndexError:
            active_page_url_segment = None

        # Default styles for inactive menu items.
        bg_color = theme.shade_color(theme.BACKGROUND_COLOR, 0.9)
        icon_bg_color = theme.shade_color(theme.SECONDARY_COLOR, 0.4)
        text_color = theme.PRIMARY_COLOR

        # Apply styles for the active menu item.
        if self.url == f'/app/{active_page_url_segment}':
            bg_color = theme.shade_color(theme.PRIMARY_COLOR, 0.9)
            icon_bg_color = theme.shade_color(theme.SECONDARY_COLOR, 0.9)
            text_color = theme.shade_color(theme.SECONDARY_COLOR, 0.3)
        
        return rio.Card(
        
            rio.Link(
                
                rio.Container(
        
                    rio.Row(
                        
                        rio.Card(
                            rio.Icon(
                                icon=self.icon,
                                fill=theme.PRIMARY_COLOR,
                                margin=0.5,
                            ),
                            color=icon_bg_color, 
                            corner_radius=0.2,
                            colorize_on_hover=True,
                        ),
                        
                        rio.Text(
                            self.title,
                            align_x=0,
                            style=rio.TextStyle(
                                fill=text_color,
                            ),
                        ),
                        
                        spacing=1,
                        align_x=0,
                        margin=0.5,
                        grow_x=True
                    ),
                    
                ),
                
                target_url=self.url,
                align_x=0,
                grow_x=True,
            ),
        
            color=bg_color,
            corner_radius=0.2,
            colorize_on_hover=True,
            grow_x=True,
        )
    



class Sidebar(rio.Component):
    """
    A sidebar with a fixed position and fixed width.
    """
    
    @rio.event.on_page_change
    async def on_page_change(self) -> None:
        self.force_refresh()

    def build(self) -> rio.Component:
        """
        Build the sidebar component.

        If the user is logged in, the sidebar will contain links based on the user's role.
        Only links that the user has permission to access will be shown.
        The sidebar will be empty and have a width of 0 if the user is not logged in.

        The height of the sidebar is fixed at 100% of the parent component's
        height. The width is fixed at 200px. The left, top, and right margins are
        set to 1.5, 2, and 2, respectively.

        The links in the sidebar are wrapped in a rio.Column component. The
        column's `align_x` and `align_y` properties are set to 0, and its
        `grow_x` and `grow_y` properties are set to False.
        """
        
        try:
            user = self.session[AppUser]
            user_is_logged_in = True
            user_role = user.role
        except KeyError:
            user_is_logged_in = False
            user_role = None
            
        if not user_is_logged_in:
            return rio.Column(
                min_width=0,  # Shrink the sidebar when no links are shown
            )

        # Show all links if user has highest privilege, otherwise filter based on role
        visible_links = [
            SideBarLink(title, url, icon)
            for title, url, icon in ALL_SIDEBAR_LINKS
        ] if user_role == get_highest_privilege_role() else [
            SideBarLink(title, url, icon)
            for title, url, icon in ALL_SIDEBAR_LINKS
            if url in PAGE_ROLE_MAPPING and user_role in PAGE_ROLE_MAPPING[url]
        ]
        
        return rio.Column(
            *visible_links,
            align_x=0,
            align_y=0,
            grow_y=False,
            margin_left=1.5,
            margin_top=2,
            margin_right=2,
        )
