from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import RedirectResponse

from app.data_models import AppUser
from app.oauth_clients import get_oauth_client
from app.persistence_runtime import get_persistence
from app.validation import SecuritySanitizer


router = APIRouter(prefix="/auth", tags=["auth"])


@dataclass(frozen=True)
class SocialIdentity:
    provider: str
    provider_user_id: str
    email: str
    email_verified: bool
    display_name: str | None = None
    avatar_url: str | None = None


@router.get("/{provider}/login", name="oauth_login")
async def oauth_login(provider: str, request: Request):
    client = get_oauth_client(provider)
    if client is None:
        if provider == "google":
            return RedirectResponse("/login?oauth_error=provider_not_configured")
        raise HTTPException(status_code=404, detail="Provider is not enabled")

    redirect_uri = request.url_for("oauth_callback", provider=provider)
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/{provider}/callback", name="oauth_callback")
async def oauth_callback(provider: str, request: Request):
    client = get_oauth_client(provider)
    if client is None:
        if provider == "google":
            return RedirectResponse("/login?oauth_error=provider_not_configured")
        raise HTTPException(status_code=404, detail="Provider is not enabled")

    try:
        token = await client.authorize_access_token(request)
    except Exception:
        return RedirectResponse("/login?oauth_error=provider_failed")

    if provider != "google":
        return RedirectResponse("/login?oauth_error=unsupported_provider")

    userinfo = token.get("userinfo") or {}
    provider_user_id = str(userinfo.get("sub") or "")
    email = str(userinfo.get("email") or "").lower().strip()
    email_verified = bool(userinfo.get("email_verified"))

    if not provider_user_id:
        return RedirectResponse("/login?oauth_error=missing_provider_id")

    if not email or not email_verified:
        return RedirectResponse("/login?oauth_error=unverified_email")

    try:
        email = SecuritySanitizer.validate_email_format(email)
    except HTTPException:
        return RedirectResponse("/login?oauth_error=unverified_email")

    display_name = SecuritySanitizer.sanitize_string(userinfo.get("name"), 100)
    identity = SocialIdentity(
        provider="google",
        provider_user_id=provider_user_id,
        email=email,
        email_verified=email_verified,
        display_name=display_name,
        avatar_url=userinfo.get("picture"),
    )

    pers = get_persistence()

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
            await pers.create_user(user)
        else:
            return RedirectResponse("/login?oauth_error=account_exists")

    try:
        handoff = await pers.create_oauth_handoff(
            user_id=user.id,
            provider=identity.provider,
        )
    except ValueError:
        return RedirectResponse("/login?oauth_error=account_inactive")

    return RedirectResponse(f"/login?social_login_token={handoff}")
