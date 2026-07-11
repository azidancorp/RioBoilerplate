from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

# Load secret values from .env file.
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
from app.api.health import router as health_router
from app.api.oauth import router as oauth_router
from starlette.middleware.sessions import SessionMiddleware


async def on_app_start(app: rio.App) -> None:
    # Create a persistence instance. This class hides the gritty details of
    # database interaction from the app.
    pers = Persistence(allow_username_login=config.ALLOW_USERNAME_LOGIN)

    if pers.get_user_count() == 0:
        bootstrap_command = "python -m app.scripts.bootstrap_root"
        print(
            "WARNING: No users are registered yet. Password signup and OAuth "
            "registration cannot initialize this deployment. "
            f"Run {bootstrap_command} to create the verified root account.",
            file=sys.stderr,
        )

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

    if not user_settings.auth_token:
        return

    # Revalidate and renew under one database write transaction. The returned
    # objects are only attached after the renewed expiry commits successfully.
    try:
        user_session, userinfo = await pers.get_and_extend_valid_session_by_auth_token(
            user_settings.auth_token,
            valid_for=timedelta(days=7),
        )

    # None was found - this auth token is invalid, expired, or inactive.
    except KeyError:
        # Persist the cleared value so a bad HTTP-only cookie is not retried on
        # every connection.
        user_settings.auth_token = ""
        rio_session.attach(user_settings)

    # A session was found. Welcome back!
    else:
        # Attach the session. This way any component that wishes to access
        # information about the user can do so.
        rio_session.attach(user_session)

        # For a user to be considered logged in, a `UserInfo` also needs to
        # be attached.
        rio_session.attach(userinfo)





app = rio.App(
    name='app',
    # TODO: check the favicon.ico — assets/favicon.ico is generated but not
    # wired up; the browser favicon is served from `icon` below via /rio/favicon.png.
    icon=Path(__file__).parent / "assets" / "logo.png",
    meta_tags={
        "og:title": "RioBoilerplate",
        "og:description": "Production-ready Rio web app template.",
        "og:image": f"{config.APP_URL.rstrip('/')}/rio/assets/user/og_image.png",
        "og:type": "website",
        "twitter:card": "summary_large_image",
        "twitter:image": f"{config.APP_URL.rstrip('/')}/rio/assets/user/og_image.png",
    },
    default_attachments=[UserSettings(auth_token='')],
    on_app_start=on_app_start,
    on_session_start=on_session_start,
    build=RootComponent,
    theme=theme.DARK_THEME,
    assets_dir=Path(__file__).parent / "assets",
)

fastapi_app = app.as_fastapi()

if config.SESSION_SECRET_KEY:
    fastapi_app.add_middleware(
        SessionMiddleware,
        secret_key=config.SESSION_SECRET_KEY,
        same_site="lax",
        https_only=config.OAUTH_COOKIE_SECURE,
    )

fastapi_app.include_router(oauth_router)
fastapi_app.include_router(example_router)
fastapi_app.include_router(profile_router)
fastapi_app.include_router(currency_router)
fastapi_app.include_router(health_router)
