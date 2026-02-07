from __future__ import annotations

import typing as t
from datetime import datetime, timezone

import rio
from app.persistence import Persistence
from app.data_models import AppUser, UserSession
from app.components.responsive import ResponsiveComponent
from app.navigation import get_public_desktop_links, get_public_login_link


class NavBarLink(rio.Component):
    title: str
    url: str

    def build(self) -> rio.Component:
        return rio.Link(
            rio.Button(
                self.title,
                shape='rounded',
            ),
            self.url,
        )


class Navbar(ResponsiveComponent):
    """
    A navbar with a fixed position and responsive width.
    """

    show_hamburger: bool = False
    on_hamburger_press: t.Callable[[], None] | None = None

    # Make sure the navbar will be rebuilt when the app navigates to a different
    # page. While Rio automatically detects state changes and rebuilds
    # components as needed, navigating to other pages is not considered a state
    # change, since it's not stored in the component.
    #
    # Instead, we can use Rio's `on_page_change` event to trigger a rebuild of
    # the navbar when the page changes.
    @rio.event.on_page_change
    async def on_page_change(self) -> None:
        # Rio comes with a function specifically for this. Whenever Rio is
        # unable to detect a change automatically, use this function to force a
        # refresh.
        self.force_refresh()

    async def on_logout(self) -> None:
        user_session = self.session[UserSession]

        # Expire the session
        pers = self.session[Persistence]

        await pers.update_session_duration(
            user_session,
            new_valid_until=datetime.now(tz=timezone.utc),
        )

        # Detach everything from the session. This informs all components that
        # nobody is logged in.
        self.session.detach(AppUser)
        self.session.detach(UserSession)

        # Navigate to the login page to prevent the user being on a page that is
        # prohibited without being logged in.
        self.session.navigate_to("/")

    def build(self) -> rio.Component:
        # Check if the user is logged in and display the appropriate buttons
        # based on the user's status
        try:
            current_user = self.session[AppUser]
            user_is_logged_in = True
        except KeyError:
            current_user = None
            user_is_logged_in = False

        mobile = self.is_mobile

        # Create the content of the navbar. First, create a row with a certain
        # spacing and margin. Use the `.add()` method to add components
        # conditionally to the row.
        navbar_content = rio.Row(spacing=self.flow_spacing, margin=self.flow_spacing)

        # Add hamburger menu button for mobile if enabled
        if self.show_hamburger and self.on_hamburger_press is not None:
            navbar_content.add(
                rio.IconButton(
                    icon="material/menu",
                    on_press=self.on_hamburger_press,
                )
            )

        # Links can be used to navigate to other pages and
        # external URLs. You can pass either a simple string or
        # another component as their content.
        navbar_content.add(
            rio.Link(
                rio.Text(
                    "HOME",
                    style="heading1",
                ),
                "/",
            )
        )

        # This spacer will take up any superfluous space,
        # effectively pushing the subsequent buttons to the
        # right.
        navbar_content.add(rio.Spacer())

        # On mobile, hide most nav links (they'll be in the drawer)
        # Only show essential actions here.
        if not mobile:
            # items that are always present on desktop
            for title, url in get_public_desktop_links():
                navbar_content.add(
                    NavBarLink(title, url)
                )

        # Based on the user's status, display the appropriate buttons
        if user_is_logged_in and current_user is not None:
            # Only show currency on desktop (it's in sidebar on mobile)
            if not mobile:
                navbar_content.add(
                    rio.Card(
                        rio.Text(
                            current_user.primary_currency_formatted_with_label,
                            style="text",
                        ),
                        margin=0.5,
                        color="hud",
                    )
                )

                navbar_content.add(
                    NavBarLink('Settings', '/app/settings')
                )

            # Logout - always visible
            navbar_content.add(
                rio.Button(
                    "Logout",
                    on_press=self.on_logout,
                    shape='rounded',
                )
            )

        else:
            # Display the login button if the user is not logged in
            login_title, login_url = get_public_login_link()
            navbar_content.add(
                NavBarLink(login_title, login_url)
            )

        # The navbar should appear above all other components. This is easily
        # done by using a `rio.Overlay` component.

        return navbar_content
