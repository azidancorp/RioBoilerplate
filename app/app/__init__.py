from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

import rio

from app.persistence import Persistence
from app.data_models import UserSettings
from app.config import config
import app.theme as theme
from app.components.root_component import RootComponent
from app.api.example import router as example_router
from app.api.profiles import router as profile_router
from app.api.currency import router as currency_router


async def on_app_start(app: rio.App) -> None:
    # Initialize the database schema early so first user/session doesn't pay
    # the setup cost. Avoid attaching a single Persistence globally, because
    # that would share one sqlite3.Connection across sessions/threads.
    pers = Persistence(allow_username_login=config.ALLOW_USERNAME_LOGIN)
    pers.close()


async def on_session_start(rio_session: rio.Session) -> None:
    # Create a per-session Persistence so the underlying sqlite3.Connection is
    # not shared across sessions/threads.
    pers = Persistence(allow_username_login=config.ALLOW_USERNAME_LOGIN)
    rio_session.attach(pers)

    # A new user has just connected. Check if they have a valid auth token.
    #
    # Any classes inheriting from `rio.UserSettings` will be automatically
    # stored on the client's device when attached to the session. Thus, by
    # retrieving the value here, we can check if the user has a valid auth token
    # stored.
    user_settings = rio_session[UserSettings]

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

async def on_session_close(rio_session: rio.Session) -> None:
    # Best-effort cleanup. The session might be closing due to network loss, etc.
    try:
        pers = rio_session[Persistence]
    except Exception:
        return

    try:
        pers.close()
    except Exception:
        # Don't let teardown exceptions prevent session close.
        pass





app = rio.App(
    name='app',
    default_attachments=[UserSettings(auth_token='')],
    on_app_start=on_app_start,
    on_session_start=on_session_start,
    on_session_close=on_session_close,
    build=RootComponent,
    theme=(theme.LIGHT_THEME, theme.DARK_THEME),
    assets_dir=Path(__file__).parent / "assets",
)

fastapi_app = app.as_fastapi()

fastapi_app.include_router(example_router)
fastapi_app.include_router(profile_router)
fastapi_app.include_router(currency_router)
