from __future__ import annotations

import logging

import rio

from app.permissions import check_access
from app.session_validation import detach_auth_attachments, refresh_attached_user_session

logger = logging.getLogger(__name__)


def guard(event: rio.GuardEvent) -> str | None:
    # This website allows access to sensitive information. Enforce stringent
    # access control to all in-app pages.

    # Check if the user is authenticated by looking for a user session
    try:
        session, _ = refresh_attached_user_session(event.session)
        prefix = "/app/"

        # Get the current page path
        current_page = event.active_pages[-1].url_segment
        full_path = f"{prefix}{current_page}"
        logger.debug(f"Guard checking access to: {full_path}")

        # Use the check_access function to verify permissions
        if not check_access(full_path, session.role):
            logger.warning(
                f"Access denied for user (role: {session.role}) to path: {full_path}. "
                f"Redirecting to home."
            )
            return "/"

        return None

    except KeyError:
        # User is not logged in, redirect to the login page
        detach_auth_attachments(event.session)
        logger.info("Unauthenticated user attempted to access protected page. Redirecting to login.")
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
