from __future__ import annotations

import rio

from app.components.navbar import Navbar
from app.components.sidebar import Sidebar
from app.components.footer import Footer
from app.components.responsive import ResponsiveComponent
from app.components.public_nav import PublicNav
from app.data_models import AppUser


class RootComponent(ResponsiveComponent):
    """
    This component will be used as the root for the app. This means that it will
    always be visible, regardless of which page is currently active.

    This makes it the perfect place to put components that should be visible on
    all pages, such as a navbar or a footer.

    Additionally, the root will contain a `rio.PageView`. Page views don't have
    any appearance of their own, but they are used to display the content of the
    currently active page. Thus, we'll always see the navbar and footer, with
    the content of the current page sandwiched in between.
    """

    drawer_open: bool = False

    def _toggle_drawer(self) -> None:
        """Toggle the mobile navigation drawer."""
        self.drawer_open = not self.drawer_open

    def _close_drawer(self) -> None:
        """Close the mobile navigation drawer."""
        self.drawer_open = False

    def _on_drawer_change(self, event: rio.DrawerOpenOrCloseEvent) -> None:
        """Handle drawer open/close events."""
        self.drawer_open = event.is_open

    @rio.event.on_page_change
    def on_page_change(self) -> None:
        """Close drawer when navigating to a new page."""
        self._close_drawer()

    def build(self) -> rio.Component:
        try:
            self.session[AppUser]
            user_is_logged_in = True
        except KeyError:
            user_is_logged_in = False

        mobile = self.is_mobile

        # Main content area with navbar, page view, and footer
        main_content = rio.Column(
            Navbar(
                show_hamburger=mobile,
                on_hamburger_press=self._toggle_drawer,
            ),
            rio.Separator(),
            rio.Row(
                # Sidebar only shown inline on desktop when logged in
                Sidebar() if (user_is_logged_in and not mobile) else rio.Spacer(min_width=0, min_height=0, grow_x=False, grow_y=False),
                rio.Column(
                    rio.PageView(
                        grow_y=True,
                    ),
                    align_y=0,
                    grow_x=True,
                ),
                align_y=0,
                grow_x=True,
                grow_y=True,
            ),
            Footer(),
        )

        if mobile:
            drawer_body: rio.Component
            if user_is_logged_in:
                drawer_body = Sidebar()
            else:
                drawer_body = PublicNav()

            return rio.Drawer(
                anchor=main_content,
                content=rio.Column(
                    rio.Row(
                        rio.Text("Menu", style=rio.TextStyle(font_size=1.5, font_weight="bold")),
                        rio.Spacer(),
                        rio.IconButton(
                            icon="material/close",
                            on_press=self._close_drawer,
                        ),
                        margin=1,
                    ),
                    rio.Separator(),
                    drawer_body,
                    align_y=0,
                    grow_y=True,
                ),
                side="left",
                is_open=self.drawer_open,
                on_open_or_close=self._on_drawer_change,
                is_modal=True,
            )
        else:
            return main_content
