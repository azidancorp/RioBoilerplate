from __future__ import annotations

import typing as t
from dataclasses import KW_ONLY, field
from datetime import datetime, timezone

import rio
import app.theme as theme
from app.persistence import Persistence
from app.data_models import AppUser, UserSession


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


class Navbar(rio.Component):
    """
    A navbar with a fixed position and responsive width.
    """

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
        try:
            # Which page is currently active? This will be used to highlight the
            # correct navigation button.
            #
            # `active_page_instances` contains `rio.ComponentPage` instances
            # that are created during app creation. Since multiple pages
            # can be active at a time (e.g., /foo/bar/baz), this is a list rather
            # than just a single page.
            active_page = self.session.active_page_instances[1]
            active_page_url_segment = active_page.url_segment
        except IndexError:
            # Handle the case where there are no active sub-pages, e.g., when the
            # user is not logged in.
            active_page_url_segment = None

        # Check if the user is logged in and display the appropriate buttons
        # based on the user's status
        try:
            self.session[AppUser]
            user_is_logged_in = True
        except KeyError:
            user_is_logged_in = False

        # Create the content of the navbar. First, create a row with a certain
        # spacing and margin. Use the `.add()` method to add components
        # conditionally to the row.
        navbar_content = rio.Row(spacing=1, margin=1)

        # Links can be used to navigate to other pages and
        # external URLs. You can pass either a simple string or
        # another component as their content.
        navbar_content.add(
            rio.Link(
                rio.Text(
                    "HOME",
                    style=rio.TextStyle(
                        font_size=2.5,
                    ),
                ),
                "/",
            )
        )

        # This spacer will take up any superfluous space,
        # effectively pushing the subsequent buttons to the
        # right.
        navbar_content.add(rio.Spacer())
        
        # items that are always present
        navbar_content.add(
            NavBarLink('About', '/about')
        )
        navbar_content.add(
            NavBarLink('FAQ', '/faq')
        )
        navbar_content.add(
            NavBarLink('Pricing', '/pricing')
        )
        navbar_content.add(
            NavBarLink('Contact', '/contact')
        )

        # Based on the user's status, display the appropriate buttons
        if user_is_logged_in:
            # By placing buttons inside a `rio.Link`, we can easily
            # make the buttons navigate to other pages without
            # having to write an event handler. Notice how there is
            # no Python function called when the button is clicked.

            navbar_content.add(
                NavBarLink('Settings', '/app/settings')
            )

            # Logout
            navbar_content.add(
                rio.Button(
                    "Logout",
                    on_press=self.on_logout,
                    shape='rounded',
                )
            )

        else:
            # Display the login button if the user is not logged in
            navbar_content.add(
                NavBarLink('Login', '/login')
            )

        # The navbar should appear above all other components. This is easily
        # done by using a `rio.Overlay` component.
        
        return navbar_content