from __future__ import annotations

from dataclasses import dataclass

import rio

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


@dataclass(frozen=True)
class StepUpResult:
    """Outcome of a step-up re-authentication attempt."""

    ok: bool
    error_message: str | None = None
    used_recovery_code: bool = False


async def verify_step_up_credentials(
    persistence: Persistence,
    user_session: UserSession,
    user: AppUser,
    *,
    password: str,
    two_factor_code: str | None,
) -> StepUpResult:
    """
    Re-authenticate the CURRENT user for a single sensitive action.

    Mirrors the verification sequence of ``settings.py`` password-change:
    verify the user's own password, then (if 2FA is enabled) verify their TOTP /
    recovery code via the centralized verifier. Used per-action by sensitive
    mutations (role changes, admin-authorized user deletion, currency updates);
    success grants nothing durable — each action re-verifies.

    OAuth-only admins (``auth_provider != "password"``) cannot satisfy a password
    leg — ``verify_password`` short-circuits to ``False`` for them — so the
    password leg is skipped and TOTP is required instead. If such a user has
    neither a local password nor 2FA, the step-up is denied with an actionable
    message rather than a misleading "password incorrect" error.
    """
    if user_session.user_id != user.id:
        return StepUpResult(
            ok=False,
            error_message="Your session has expired. Please log in again.",
        )

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

    return StepUpResult(ok=True, used_recovery_code=used_recovery_code)
