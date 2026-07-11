from __future__ import annotations

from dataclasses import dataclass

from app.config import config
from app.passwords import get_password_strength


@dataclass(frozen=True, slots=True)
class PasswordPolicyDecision:
    """Result of applying the configured policy to a proposed password."""

    ok: bool
    strength: int
    requires_acknowledgement: bool = False
    message: str | None = None


def evaluate_new_password(
    password: str,
    *,
    acknowledged_weak: bool = False,
    allow_weak: bool | None = None,
    minimum_strength: int | None = None,
) -> PasswordPolicyDecision:
    """Evaluate one password consistently across every creation/reset flow."""
    if not password:
        return PasswordPolicyDecision(
            ok=False,
            strength=0,
            message="Please enter a password.",
        )

    strength = get_password_strength(password)
    threshold = (
        config.MIN_PASSWORD_STRENGTH
        if minimum_strength is None
        else minimum_strength
    )
    weak_passwords_allowed = (
        config.ALLOW_WEAK_PASSWORDS if allow_weak is None else allow_weak
    )

    if strength >= threshold:
        return PasswordPolicyDecision(ok=True, strength=strength)

    if not weak_passwords_allowed:
        return PasswordPolicyDecision(
            ok=False,
            strength=strength,
            message=(
                "Your password is too weak. Please choose a stronger password "
                f"(minimum strength: {threshold})."
            ),
        )

    if not acknowledged_weak:
        return PasswordPolicyDecision(
            ok=False,
            strength=strength,
            requires_acknowledgement=True,
            message=(
                "Your password is weak. Please acknowledge this below or "
                "choose a stronger password."
            ),
        )

    return PasswordPolicyDecision(ok=True, strength=strength)


def require_new_password(
    password: str,
    *,
    acknowledged_weak: bool = False,
) -> int:
    """Raise `ValueError` unless the proposed password satisfies the policy."""
    decision = evaluate_new_password(
        password,
        acknowledged_weak=acknowledged_weak,
    )
    if not decision.ok:
        raise ValueError(decision.message or "Password does not meet policy.")
    return decision.strength
