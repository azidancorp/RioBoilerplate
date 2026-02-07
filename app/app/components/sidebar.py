from __future__ import annotations

import rio
import app.theme as theme
from app.data_models import AppUser
from app.navigation import get_sidebar_links
from app.permissions import check_access, get_highest_privilege_role


ALL_SIDEBAR_LINKS = get_sidebar_links()


class SideBarLink(rio.Component):
    title: str
    url: str
    icon: str
    
    @rio.event.on_page_change
    def on_page_change(self) -> None:
        self.force_refresh()

    def build(self) -> rio.Component:
        # Get the URL segment of the active page for comparison.
        # NOTE: Using active_page_instances[1] assumes a two-level route like '/app/<subpage>'.
        # This is brittle for top-level routes (no index 1) and deeper nesting.
        # If you extend routing, consider instead:
        #   - active_page_instances[-1].url_segment  # always deepest page
        #   - Or build the current path: 
        #       "/" + "/".join(p.url_segment for p in self.session.active_page_instances if p.url_segment)
        #     then compare equality or use startswith(self.url + "/") to highlight parents on deeper routes.
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
        
        user: AppUser | None = None
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

        header_components: list[rio.Component] = []
        if user_role is not None and user is not None:
            header_components.append(
                rio.Card(
                    rio.Column(
                        rio.Text(
                            "Balance",
                            style="dim",
                            align_x=0,
                        ),
                        rio.Text(
                            user.primary_currency_formatted_with_label,
                            style=rio.TextStyle(font_size=1.5),
                            align_x=0,
                        ),
                        spacing=0.5,
                    ),
                    margin=0.5,
                    color="hud",
                )
            )

        # Show all links if user has highest privilege, otherwise filter based on role
        visible_links = [
            SideBarLink(title, url, icon)
            for title, url, icon in ALL_SIDEBAR_LINKS
        ] if user_role == get_highest_privilege_role() else [
            SideBarLink(title, url, icon)
            for title, url, icon in ALL_SIDEBAR_LINKS
            if check_access(url, user_role)
        ]
        
        return rio.Column(
            *header_components,
            *visible_links,
            align_x=0,
            align_y=0,
            grow_y=False,
            margin_left=1.5,
            margin_top=2,
            margin_right=2,
        )
