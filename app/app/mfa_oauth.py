from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlencode

import rio
from fastapi import HTTPException

from app.persistence_social import oauth_reauth_approval_prefix
from app.validation import SecuritySanitizer


@dataclass(frozen=True, slots=True)
class OAuthMfaCallbackResult:
    token: str = ""
    error_message: str = ""
    should_scrub_url: bool = False


def oauth_mfa_error_message(error_code: str) -> str:
    messages = {
        "provider_failed": "Google verification failed. Please try again.",
        "provider_not_configured": "Google verification is not configured.",
        "unsupported_provider": "That sign-in provider is not supported.",
        "invalid_challenge": (
            "Google verification expired or your session changed. "
            "Verify with Google again."
        ),
        "identity_mismatch": (
            "That Google account does not match the account currently signed in."
        ),
        "reauth_stale": (
            "Google did not confirm a recent sign-in. Verify with Google again."
        ),
    }
    return messages.get(error_code, "Google verification failed. Please try again.")


def read_oauth_mfa_callback(
    session: rio.Session,
    *,
    purpose: str,
    token_parameter: str,
    error_parameter: str,
) -> OAuthMfaCallbackResult:
    active_page_url = getattr(session, "active_page_url", None)
    query = getattr(active_page_url, "query", {})
    token_raw = str(query.get(token_parameter, "")).strip()
    error_code = str(query.get(error_parameter, "")).strip()
    if not token_raw and not error_code:
        return OAuthMfaCallbackResult()

    if error_code:
        return OAuthMfaCallbackResult(
            error_message=oauth_mfa_error_message(error_code),
            should_scrub_url=True,
        )

    try:
        token = SecuritySanitizer.sanitize_auth_code(
            token_raw,
            max_length=128,
        )
    except HTTPException:
        token = None
    if not token or not token.startswith(oauth_reauth_approval_prefix(purpose)):
        return OAuthMfaCallbackResult(
            error_message=oauth_mfa_error_message("invalid_challenge"),
            should_scrub_url=True,
        )

    return OAuthMfaCallbackResult(
        token=token,
        should_scrub_url=True,
    )


def navigate_to_google_mfa_reauth(
    session: rio.Session,
    *,
    purpose: str,
    challenge: str,
) -> None:
    query = urlencode({"mfa_challenge": challenge})
    try:
        base_url = session.base_url.joinpath("auth", "google", "mfa", purpose)
        url = f"{base_url}?{query}"
    except Exception:
        url = f"/auth/google/mfa/{purpose}?{query}"

    async def worker() -> None:
        await session._evaluate_javascript(
            f"window.location.href = {json.dumps(url)};",
        )

    session.create_task(worker(), name=f"Verify {purpose} with Google")
