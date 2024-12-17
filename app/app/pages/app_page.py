from __future__ import annotations

import typing as t
from dataclasses import KW_ONLY, field

import rio

from app.data_models import AppUser, UserSession
from app.permissions import PAGE_ROLE_MAPPING, check_access


def guard(event: rio.GuardEvent) -> str | None:
    # This website allows access to sensitive information. Enforce stringent
    # access control to all in-app pages.
    
    

    # Check if the user is authenticated by looking for a user session
    try:
        session = event.session[UserSession]
        prefix = "/app/"

        # Get the current page path
        current_page = event.active_pages[-1].url_segment
        full_path = f"{prefix}{current_page}"
        # print("guard checking:", full_path)

        # Use the check_access function to verify permissions
        if not check_access(full_path, session.role):
            print("Access denied, redirecting to home")
            return f"/"

        return None

    except KeyError:
        # User is not logged in, redirect to the login page
        print("User is not logged in, redirecting to login page")
        return "/"


@rio.page(
    name="App",
    url_segment="app",
    guard=guard,
)
class InnerAppPage(rio.Component):
    def build(self) -> rio.Component:
        return rio.PageView(
            grow_y=True,
        )
