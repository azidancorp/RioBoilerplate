from __future__ import annotations

import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

import rio
from starlette.middleware.sessions import SessionMiddleware

from app.config import config
import app.theme as theme
from app.api.currency import router as currency_router
from app.api.example import router as example_router
from app.api.health import router as health_router
from app.api.oauth import router as oauth_router
from app.api.profiles import router as profile_router
from app.components.root_component import RootComponent
from app.data_models import UserSettings
from app.http_surface import install_http_surface
from app.persistence import Persistence
from app.rio_cookie_security import install_rio_cookie_security


_PRESTART_MODULE = "app.scripts.prestart"


def _is_prestart_module_invocation(argv: Sequence[str]) -> bool:
    """Return whether Python is executing this project's prestart module.

    Python imports the parent ``app`` package before it executes a ``-m``
    submodule.  Prestart must therefore bypass application-only initialization
    long enough to report configuration errors itself.  Parse only Python's
    interpreter arguments, stopping at another execution mode or a script, so
    a coincidental ``-m app.scripts.prestart`` in application arguments cannot
    disable the runtime hardening.
    """
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "--" or argument == "-" or not argument.startswith("-"):
            return False

        if argument == "--check-hash-based-pycs":
            index += 2
            continue
        if argument.startswith("--"):
            index += 1
            continue

        # CPython accepts both ``-m module`` and combined forms such as
        # ``-im module`` or ``-mapp.scripts.prestart``.
        short_options = argument[1:]
        option_index = 0
        while option_index < len(short_options):
            option = short_options[option_index]
            if option == "c":
                return False
            if option == "m":
                module_name = short_options[option_index + 1 :]
                if module_name:
                    return module_name == _PRESTART_MODULE
                return (
                    index + 1 < len(argv)
                    and argv[index + 1] == _PRESTART_MODULE
                )
            if option in {"W", "X"}:
                # The remainder of this argument, or the next argument when
                # empty, belongs to the interpreter option.
                if option_index + 1 == len(short_options):
                    index += 1
                break
            option_index += 1

        index += 1

    return False


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
if not _is_prestart_module_invocation(getattr(sys, "orig_argv", sys.argv)):
    install_rio_cookie_security(
        fastapi_app,
        secure_auth_cookie=config.AUTH_TOKEN_COOKIE_SECURE,
        canonical_origin=(
            config.APP_URL if config.AUTH_TOKEN_COOKIE_SECURE else None
        ),
    )

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
install_http_surface(fastapi_app)
