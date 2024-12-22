from __future__ import annotations

from dataclasses import KW_ONLY, field
import re
from typing import *  # type: ignore

import rio
import app.theme as theme


class SideBarLink(rio.Component):
    title: str
    url: str
    icon: str
    
    @rio.event.on_page_change
    def on_page_change(self) -> None:
        self.force_refresh()

    def build(self) -> rio.Component:
        # Get the URL segment of the active page for comparison.
        # print("active page instances", self.session.active_page_instances)
        # print("active page 0", self.session.active_page_instances[0])
        # print("active page url segment", self.session.active_page_instances[1].url_segment)
        try:
            active_page_url_segment = self.session.active_page_instances[1].url_segment
            print("active page url segment", active_page_url_segment)
        except IndexError:
            active_page_url_segment = None

        # Default styles for inactive menu items.
        bg_color = theme.shade_color(theme.BACKGROUND_COLOR, 0.9)
        icon_bg_color = theme.shade_color(theme.SECONDARY_COLOR, 0.4)
        text_color = theme.PRIMARY_COLOR

        # Apply styles for the active menu item.
        if self.url == f'/app/{active_page_url_segment}':
            print("self.url", self.url)
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

        If the user is logged in, the sidebar will contain links to the home page,
        test page, news page, about page, and contact page. If the user is not
        logged in, the sidebar will be empty and have a width of 0, effectively
        hiding it.

        The height of the sidebar is fixed at 100% of the parent component's
        height. The width is fixed at 200px. The left, top, and right margins are
        set to 1.5, 2, and 2, respectively.

        The links in the sidebar are wrapped in a rio.Column component. The
        column's `align_x` and `align_y` properties are set to 0, and its
        `grow_x` and `grow_y` properties are set to False.
        """

            
        # On non-app pages, no sidebar
        # if len(self.session.active_page_instances) <= 1:
        #     return rio.Column(
        #         margin_left=1.5,
        #         margin_top=2,
        #         margin_right=2,
        #         min_width=0,  # Shrink the sidebar when no links are shown
        #     )
            
        return rio.Column(
            
            SideBarLink("Dashboard", "/app/dashboard", "dashboard"),
            SideBarLink("Admin", "/app/admin", "admin-panel-settings"), 
            SideBarLink("Test", "/app/test", "science"),
            SideBarLink("News", "/app/news", "newspaper"),
            
            align_x=0,
            align_y=0,
            grow_y=False,
            margin_left=1.5,
            margin_top=2,
            margin_right=2,
        )
