from __future__ import annotations

import json
import time
from dataclasses import dataclass
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import RedirectResponse

from app.api.auth_dependencies import get_persistence
from app.config import config
from app.data_models import AppUser
from app.navigation import get_registered_app_path
from app.oauth_clients import get_oauth_client
from app.persistence import BootstrapRequiredError, Persistence
from app.persistence_social import OAUTH_DELETE_CHALLENGE_PREFIX
from app.validation import SecuritySanitizer


router = APIRouter(prefix="/auth", tags=["auth"])

_OAUTH_DELETE_CHALLENGE_SESSION_KEY = "oauth_delete_account_challenge"
_OAUTH_LOGIN_RETURN_TO_SESSION_KEY = "oauth_login_return_to"


@dataclass(frozen=True)
class SocialIdentity:
    provider: str
    provider_user_id: str
    email: str
    email_verified: bool
    display_name: str | None = None
    avatar_url: str | None = None


def _settings_delete_redirect(
    *,
    token: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    query = urlencode(
        {
            key: value
            for key, value in {
                "delete_account_oauth_token": token,
                "delete_account_oauth_error": error,
            }.items()
            if value
        }
    )
    suffix = f"?{query}" if query else ""
    return RedirectResponse(f"/app/settings{suffix}")


def _login_redirect(
    *,
    error: str | None = None,
    social_login_token: str | None = None,
    return_to: str | None = None,
) -> RedirectResponse:
    query = urlencode(
        {
            key: value
            for key, value in {
                "oauth_error": error,
                "social_login_token": social_login_token,
                "return_to": get_registered_app_path(return_to),
            }.items()
            if value
        }
    )
    suffix = f"?{query}" if query else ""
    return RedirectResponse(f"/login{suffix}")


def _has_recent_auth_time(value: object) -> bool:
    if isinstance(value, bool):
        return False
    try:
        auth_time = float(value)
    except (TypeError, ValueError):
        return False
    now = time.time()
    maximum_age = config.OAUTH_HANDOFF_TTL_MINUTES * 60
    return now - maximum_age <= auth_time <= now + 60


@router.get("/{provider}/login", name="oauth_login")
async def oauth_login(
    provider: str,
    request: Request,
    return_to: str = "",
):
    safe_return_to = get_registered_app_path(return_to)
    client = get_oauth_client(provider)
    if client is None:
        if provider == "google":
            return _login_redirect(
                error="provider_not_configured",
                return_to=safe_return_to,
            )
        raise HTTPException(status_code=404, detail="Provider is not enabled")

    if safe_return_to:
        request.session[_OAUTH_LOGIN_RETURN_TO_SESSION_KEY] = safe_return_to
    else:
        request.session.pop(_OAUTH_LOGIN_RETURN_TO_SESSION_KEY, None)
    redirect_uri = request.url_for("oauth_callback", provider=provider)
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/{provider}/delete-account", name="oauth_delete_account")
async def oauth_delete_account(
    provider: str,
    request: Request,
    deletion_challenge: str = "",
):
    client = get_oauth_client(provider)
    if client is None:
        if provider == "google":
            return _settings_delete_redirect(error="provider_not_configured")
        raise HTTPException(status_code=404, detail="Provider is not enabled")
    if provider != "google":
        return _settings_delete_redirect(error="unsupported_provider")

    try:
        challenge = SecuritySanitizer.sanitize_auth_code(
            deletion_challenge,
            max_length=128,
        )
    except HTTPException:
        challenge = None
    if not challenge or not challenge.startswith(OAUTH_DELETE_CHALLENGE_PREFIX):
        return _settings_delete_redirect(error="invalid_challenge")

    request.session[_OAUTH_DELETE_CHALLENGE_SESSION_KEY] = challenge
    redirect_uri = request.url_for(
        "oauth_delete_account_callback",
        provider=provider,
    )
    return await client.authorize_redirect(
        request,
        redirect_uri,
        prompt="select_account",
        max_age=0,
        claims=json.dumps(
            {"id_token": {"auth_time": {"essential": True}}},
            separators=(",", ":"),
        ),
    )


@router.get(
    "/{provider}/delete-account/callback",
    name="oauth_delete_account_callback",
)
async def oauth_delete_account_callback(
    provider: str,
    request: Request,
    pers: Persistence = Depends(get_persistence),
):
    client = get_oauth_client(provider)
    if client is None:
        if provider == "google":
            return _settings_delete_redirect(error="provider_not_configured")
        raise HTTPException(status_code=404, detail="Provider is not enabled")
    if provider != "google":
        return _settings_delete_redirect(error="unsupported_provider")

    challenge = str(
        request.session.pop(_OAUTH_DELETE_CHALLENGE_SESSION_KEY, "")
    )
    if not challenge:
        return _settings_delete_redirect(error="invalid_challenge")

    try:
        token = await client.authorize_access_token(request)
    except Exception:
        return _settings_delete_redirect(error="provider_failed")

    userinfo = token.get("userinfo") or {}
    provider_user_id = str(userinfo.get("sub") or "").strip()
    if not provider_user_id:
        return _settings_delete_redirect(error="identity_mismatch")
    if not _has_recent_auth_time(userinfo.get("auth_time")):
        return _settings_delete_redirect(error="reauth_stale")

    try:
        approval = await pers.exchange_oauth_account_deletion_challenge(
            challenge_token=challenge,
            provider=provider,
            provider_user_id=provider_user_id,
        )
    except (KeyError, ValueError):
        return _settings_delete_redirect(error="identity_mismatch")

    return _settings_delete_redirect(token=approval)


@router.get("/{provider}/callback", name="oauth_callback")
async def oauth_callback(
    provider: str,
    request: Request,
    pers: Persistence = Depends(get_persistence),
):
    client = get_oauth_client(provider)
    if client is None:
        if provider == "google":
            return _login_redirect(error="provider_not_configured")
        raise HTTPException(status_code=404, detail="Provider is not enabled")

    return_to = get_registered_app_path(
        request.session.pop(_OAUTH_LOGIN_RETURN_TO_SESSION_KEY, "")
    )

    try:
        token = await client.authorize_access_token(request)
    except Exception:
        return _login_redirect(error="provider_failed", return_to=return_to)

    if provider != "google":
        return _login_redirect(
            error="unsupported_provider",
            return_to=return_to,
        )

    userinfo = token.get("userinfo") or {}
    provider_user_id = str(userinfo.get("sub") or "")
    email = str(userinfo.get("email") or "").lower().strip()
    email_verified = bool(userinfo.get("email_verified"))

    if not provider_user_id:
        return _login_redirect(
            error="missing_provider_id",
            return_to=return_to,
        )

    if not email or not email_verified:
        return _login_redirect(
            error="unverified_email",
            return_to=return_to,
        )

    try:
        email = SecuritySanitizer.validate_email_format(email)
    except HTTPException:
        return _login_redirect(
            error="unverified_email",
            return_to=return_to,
        )

    display_name = SecuritySanitizer.sanitize_string(userinfo.get("name"), 100)
    identity = SocialIdentity(
        provider="google",
        provider_user_id=provider_user_id,
        email=email,
        email_verified=email_verified,
        display_name=display_name,
        avatar_url=userinfo.get("picture"),
    )

    try:
        user = await pers.get_user_by_provider_identity(
            identity.provider,
            identity.provider_user_id,
        )
    except KeyError:
        try:
            await pers.get_user_by_email(identity.email)
        except KeyError:
            user = AppUser.create_social_user(
                email=identity.email,
                provider=identity.provider,
                provider_user_id=identity.provider_user_id,
                username=None,
                is_verified=True,
            )
            try:
                await pers.create_user(user)
            except BootstrapRequiredError:
                return _login_redirect(
                    error="bootstrap_required",
                    return_to=return_to,
                )
        else:
            return _login_redirect(
                error="account_exists",
                return_to=return_to,
            )

    try:
        handoff = await pers.create_oauth_handoff(
            user_id=user.id,
            provider=identity.provider,
        )
    except ValueError:
        return _login_redirect(
            error="account_inactive",
            return_to=return_to,
        )

    return _login_redirect(
        social_login_token=handoff,
        return_to=return_to,
    )
