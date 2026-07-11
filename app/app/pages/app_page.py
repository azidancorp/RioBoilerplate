from __future__ import annotations

import logging
from urllib.parse import urlencode

import rio

from app.navigation import get_registered_app_path
from app.permissions import check_access
from app.session_validation import refresh_attached_user_session, reject_stale_user_session

logger = logging.getLogger(__name__)


def _requested_app_path(event: rio.GuardEvent) -> str | None:
    segments = [
        str(page.url_segment).strip("/")
        for page in event.active_pages
        if getattr(page, "url_segment", None)
    ]
    if not segments:
        return None
    try:
        app_index = segments.index("app")
    except ValueError:
        candidate = f"/app/{segments[-1]}"
    else:
        candidate = "/" + "/".join(segments[app_index:])
    return get_registered_app_path(candidate)


def _login_redirect(return_to: str | None) -> str:
    if return_to is None:
        return "/login"
    return f"/login?{urlencode({'return_to': return_to})}"


def guard(event: rio.GuardEvent) -> str | None:
    # This website allows access to sensitive information. Enforce stringent
    # access control to all in-app pages.

    requested_path = _requested_app_path(event)

    # Check if the user is authenticated by looking for a user session
    try:
        session, _ = refresh_attached_user_session(event.session)
        logger.debug("Guard checking access to: %s", requested_path)

        # Use the check_access function to verify permissions
        if requested_path is None or not check_access(requested_path, session.role):
            logger.warning(
                "Access denied for role %s to path %s. Redirecting to home.",
                session.role,
                requested_path,
            )
            return "/"

        return None

    except KeyError:
        # User is not logged in, redirect to the login page
        reject_stale_user_session(event.session, redirect_to=None)
        logger.info(
            "Unauthenticated user attempted to access protected page. "
            "Redirecting to login."
        )
        return _login_redirect(requested_path)


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
