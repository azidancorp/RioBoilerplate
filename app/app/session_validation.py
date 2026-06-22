from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import rio

from app.config import config
from app.data_models import AppUser, UserSession, UserSettings
from app.persistence import Persistence
from app.persistence_auth import TwoFactorFailure


def detach_auth_attachments(session: rio.Session) -> None:
    for attachment_type in (AppUser, UserSession):
        try:
            session.detach(attachment_type)
        except KeyError:
            pass


def refresh_attached_user_session(session: rio.Session) -> tuple[UserSession, AppUser]:
    cached_session = session[UserSession]
    persistence = session[Persistence]
    user_session, user = persistence.get_valid_session_by_auth_token(cached_session.id)
    session.attach(user_session)
    session.attach(user)
    return user_session, user


def reject_stale_user_session(session: rio.Session, *, redirect_to: str | None = "/") -> None:
    detach_auth_attachments(session)

    try:
        user_settings = session[UserSettings]
    except KeyError:
        pass
    else:
        user_settings.auth_token = ""
        session.attach(user_settings)

    if redirect_to is not None:
        session.navigate_to(redirect_to)


def require_fresh_user_session(
    session: rio.Session,
    *,
    redirect_to: str | None = "/",
) -> tuple[UserSession, AppUser] | None:
    try:
        return refresh_attached_user_session(session)
    except KeyError:
        reject_stale_user_session(session, redirect_to=redirect_to)
        return None


def require_elevated_session(
    session: rio.Session,
    *,
    now: datetime | None = None,
) -> tuple[UserSession, AppUser] | None:
    """
    Like ``require_fresh_user_session``, but additionally requires the session to
    be within its sudo elevation window.

    Returns ``(user_session, user)`` when the session is both fresh and elevated,
    otherwise ``None`` (the caller should prompt for step-up re-auth). Adds no
    extra query: ``session_is_elevated`` reads the ``elevated_until`` already
    loaded onto ``UserSession`` by ``require_fresh_user_session``.
    """
    fresh = require_fresh_user_session(session)
    if fresh is None:
        return None
    user_session, user = fresh
    persistence = session[Persistence]
    if not persistence.session_is_elevated(user_session, now=now):
        return None
    return user_session, user


@dataclass(frozen=True)
class StepUpResult:
    """Outcome of a step-up (sudo-mode) re-authentication attempt."""

    ok: bool
    error_message: str | None = None
    used_recovery_code: bool = False
    elevated_until: datetime | None = None


async def perform_step_up(
    session: rio.Session,
    *,
    password: str,
    two_factor_code: str | None,
) -> StepUpResult:
    """
    Re-authenticate the CURRENT user and, on success, elevate their session.

    Mirrors the verification sequence of ``settings.py`` password-change:
    verify the user's own password, then (if 2FA is enabled) verify their TOTP /
    recovery code via the centralized verifier. On success the session is marked
    sudo-elevated for ``config.SUDO_MODE_TTL_SECONDS``.

    OAuth-only admins (``auth_provider != "password"``) cannot satisfy a password
    leg — ``verify_password`` short-circuits to ``False`` for them — so the
    password leg is skipped and TOTP is required instead. If such a user has
    neither a local password nor 2FA, the step-up is denied with an actionable
    message rather than a misleading "password incorrect" error.
    """
    fresh = require_fresh_user_session(session)
    if fresh is None:
        return StepUpResult(
            ok=False,
            error_message="Your session has expired. Please log in again.",
        )
    user_session, user = fresh
    persistence = session[Persistence]

    uses_password = user.auth_provider == "password"

    if uses_password:
        if not user.verify_password(password):
            return StepUpResult(ok=False, error_message="Current password is incorrect")
    elif not user.two_factor_enabled:
        # No password leg available and no 2FA to fall back on.
        return StepUpResult(
            ok=False,
            error_message="Set up a password or 2FA to perform this action.",
        )

    used_recovery_code = False
    if user.two_factor_enabled:
        result = persistence.verify_two_factor_challenge(
            user_session.user_id,
            two_factor_code,
        )
        if not result.ok:
            if result.failure == TwoFactorFailure.MISSING_CODE:
                return StepUpResult(ok=False, error_message="2FA code is required")
            return StepUpResult(ok=False, error_message="Invalid 2FA or recovery code.")
        used_recovery_code = result.used_recovery_code

    deadline = await persistence.elevate_session(
        user_session.id,
        config.SUDO_MODE_TTL_SECONDS,
    )
    # Keep the in-memory attachment consistent with the persisted row so the
    # very next require_elevated_session in this request sees the elevation.
    user_session.elevated_until = deadline
    session.attach(user_session)

    return StepUpResult(
        ok=True,
        used_recovery_code=used_recovery_code,
        elevated_until=deadline,
    )
