from __future__ import annotations

import typing as t
from datetime import datetime, timedelta, timezone
from pathlib import Path

import rio

from app.persistence import Persistence
from app.data_models import UserSettings
import app.theme as theme
from app.components.root_component import RootComponent
from app.api.test import router as test_router


async def on_app_start(app: rio.App) -> None:
    # Create a persistence instance. This class hides the gritty details of
    # database interaction from the app.
    pers = Persistence()

    # Now attach it to the session. This way, the persistence instance is
    # available to all components using `self.session[persistence.Persistence]`
    app.default_attachments.append(pers)


async def on_session_start(rio_session: rio.Session) -> None:
    # A new user has just connected. Check if they have a valid auth token.
    #
    # Any classes inheriting from `rio.UserSettings` will be automatically
    # stored on the client's device when attached to the session. Thus, by
    # retrieving the value here, we can check if the user has a valid auth token
    # stored.
    user_settings = rio_session[UserSettings]

    # Get the persistence instance
    pers = rio_session[Persistence]

    # Try to find a session with the given auth token
    try:
        user_session = await pers.get_session_by_auth_token(
            user_settings.auth_token,
        )

    # None was found - this auth token is invalid
    except KeyError:
        pass

    # A session was found. Welcome back!
    else:
        # Make sure the session is still valid
        if user_session.valid_until > datetime.now(tz=timezone.utc):
            # Attach the session. This way any component that wishes to access
            # information about the user can do so.
            rio_session.attach(user_session)

            # For a user to be considered logged in, a `UserInfo` also needs to
            # be attached.
            userinfo = await pers.get_user_by_id(user_session.user_id)
            rio_session.attach(userinfo)

            # Since this session has only just been used, let's extend its
            # duration. This way users don't get logged out as long as they keep
            # using the app.
            await pers.update_session_duration(
                user_session,
                new_valid_until=datetime.now(tz=timezone.utc)
                + timedelta(days=7),
            )





app = rio.App(
    name='app',
    default_attachments=[UserSettings(auth_token='')],
    on_app_start=on_app_start,
    on_session_start=on_session_start,
    build=RootComponent,
    theme=(theme.LIGHT_THEME, theme.DARK_THEME),
    assets_dir=Path(__file__).parent / "assets",
)

fastapi_app = app.as_fastapi()

fastapi_app.include_router(test_router)