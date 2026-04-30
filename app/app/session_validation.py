from __future__ import annotations

import rio

from app.data_models import AppUser, UserSession
from app.persistence import Persistence


def detach_auth_attachments(session: rio.Session) -> None:
    for attachment_type in (AppUser, UserSession):
        try:
            session.detach(attachment_type)
        except (AttributeError, KeyError):
            pass


def refresh_attached_user_session(session: rio.Session) -> tuple[UserSession, AppUser]:
    cached_session = session[UserSession]
    persistence = session[Persistence]
    user_session, user = persistence.get_valid_session_by_auth_token(cached_session.id)
    session.attach(user_session)
    session.attach(user)
    return user_session, user
