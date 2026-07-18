from __future__ import annotations

from authlib.integrations.starlette_client import OAuth

from app.config import config


oauth = OAuth()


def is_google_login_configured() -> bool:
    return bool(
        config.ENABLE_GOOGLE_LOGIN
        and config.SESSION_SECRET_KEY
        and config.GOOGLE_CLIENT_ID
        and config.GOOGLE_CLIENT_SECRET
    )


def _google_registration_kwargs() -> dict[str, object]:
    return {
        "name": "google",
        "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "server_metadata_url": (
            "https://accounts.google.com/.well-known/openid-configuration"
        ),
        "client_kwargs": {
            "scope": "openid profile email",
            "code_challenge_method": "S256",
        },
    }


if config.ENABLE_GOOGLE_LOGIN and config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET:
    oauth.register(**_google_registration_kwargs())


def get_oauth_client(provider: str):
    if provider != "google" or not is_google_login_configured():
        return None
    return oauth.create_client(provider)
