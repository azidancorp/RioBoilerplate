from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from app.common_passwords import COMMON_PASSWORDS
from app.config import config
from app.passwords import get_password_strength, normalize_password


# Deployment-specific and long-form values supplement the vendored common-
# password corpus and cover predictable phrases used in boilerplate deployments.
APPLICATION_PASSWORDS = frozenset(
    {
        "correct horse battery staple",
        "correcthorsebatterystaple",
        "defaultpassword",
        "defaultpassword1",
        "qazwsxedcrfvtgb",
        "qwertyuiopasdfgh",
        "rio-boilerplate",
        "rio-boilerplate-password",
        "rioboilerplate",
        "rioboilerplatepassword",
        "temporarypassword",
        "temporarypassword1",
    }
)


@dataclass(frozen=True, slots=True)
class PasswordPolicyWarning:
    """One advisory password-quality finding with a stable machine code."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class PasswordPolicyDecision:
    """Result of applying the configured policy to a proposed password."""

    ok: bool
    strength: int
    warnings: tuple[PasswordPolicyWarning, ...] = ()
    requires_acknowledgement: bool = False
    message: str | None = None


def evaluate_new_password(
    password: str,
    *,
    acknowledged_weak: bool = False,
    expected_passwords: Iterable[str] = (),
) -> PasswordPolicyDecision:
    """Analyze a new password and apply the configured warning semantics."""
    if not isinstance(acknowledged_weak, bool):
        raise TypeError("acknowledged_weak must be a bool")
    return _evaluate_password(
        password,
        acknowledged_weak=acknowledged_weak,
        expected_passwords=expected_passwords,
    )


def evaluate_bootstrap_password(
    password: str,
    *,
    allow_insecure_password: bool,
    expected_passwords: Iterable[str] = (),
) -> PasswordPolicyDecision:
    """Treat the explicit bootstrap flag as a warning acknowledgement."""
    if not isinstance(allow_insecure_password, bool):
        raise TypeError("allow_insecure_password must be a bool")
    return _evaluate_password(
        password,
        acknowledged_weak=allow_insecure_password,
        expected_passwords=expected_passwords,
    )


def require_new_password(
    password: str,
    *,
    acknowledged_weak: bool = False,
    expected_passwords: Iterable[str] = (),
) -> int:
    """Raise unless the password passes or its warnings are acknowledged."""
    decision = evaluate_new_password(
        password,
        acknowledged_weak=acknowledged_weak,
        expected_passwords=expected_passwords,
    )
    if not decision.ok:
        raise ValueError(decision.message or "Password does not meet policy.")
    return decision.strength


def require_bootstrap_password(
    password: str,
    *,
    allow_insecure_password: bool,
    expected_passwords: Iterable[str] = (),
) -> int:
    """Raise unless initial-root warnings are explicitly acknowledged."""
    decision = evaluate_bootstrap_password(
        password,
        allow_insecure_password=allow_insecure_password,
        expected_passwords=expected_passwords,
    )
    if not decision.ok:
        raise ValueError(decision.message or "Password does not meet policy.")
    return decision.strength


def account_password_context(
    *,
    email: str,
    username: str | None = None,
) -> tuple[str, ...]:
    """Return account-specific values analyzed as predictable passwords."""
    values = [email, email.partition("@")[0], username or ""]
    return tuple(dict.fromkeys(value for value in values if value.strip()))


def _evaluate_password(
    password: str,
    *,
    acknowledged_weak: bool,
    expected_passwords: Iterable[str],
) -> PasswordPolicyDecision:
    if password == "":
        return PasswordPolicyDecision(
            ok=False,
            strength=0,
            message="Please enter a password.",
        )

    # Lone surrogate code points cannot be encoded by the UTF-8 hashing path.
    # Check this technical constraint before returning an acknowledgeable
    # quality warning, including for oversized input.
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        return PasswordPolicyDecision(
            ok=False,
            strength=0,
            message="Password contains invalid Unicode characters.",
        )

    # Keep expensive scoring and blocklist work bounded. Length is advisory,
    # so an acknowledged oversized password remains usable and is hashed in
    # full by the normal NFC hashing path.
    if len(password) > config.MAX_PASSWORD_LENGTH:
        return _decision_from_warnings(
            strength=0,
            warnings=(
                PasswordPolicyWarning(
                    code="too_long",
                    message=(
                        "Your password is longer than the recommended maximum "
                        f"of {config.MAX_PASSWORD_LENGTH} characters."
                    ),
                ),
            ),
            acknowledged_weak=acknowledged_weak,
        )

    canonical_password = normalize_password(password)
    if len(canonical_password) > config.MAX_PASSWORD_LENGTH:
        return _decision_from_warnings(
            strength=0,
            warnings=(
                PasswordPolicyWarning(
                    code="too_long",
                    message=(
                        "Your password is longer than the recommended maximum "
                        f"of {config.MAX_PASSWORD_LENGTH} characters."
                    ),
                ),
            ),
            acknowledged_weak=acknowledged_weak,
        )

    strength = get_password_strength(
        canonical_password,
        minimum_length=config.MIN_PASSWORD_LENGTH,
        maximum_length=config.MAX_PASSWORD_LENGTH,
        warning_threshold=config.PASSWORD_STRENGTH_WARNING_THRESHOLD,
    )
    warnings: list[PasswordPolicyWarning] = []
    stripped_password = canonical_password.strip()
    if not stripped_password:
        warnings.append(
            PasswordPolicyWarning(
                code="whitespace_only",
                message="Your password contains only whitespace.",
            )
        )
    elif stripped_password != canonical_password:
        warnings.append(
            PasswordPolicyWarning(
                code="surrounding_whitespace",
                message=(
                    "Your password starts or ends with whitespace, which can "
                    "be difficult to enter reliably."
                ),
            )
        )

    if any(
        unicodedata.category(character) == "Cc"
        for character in canonical_password
    ):
        warnings.append(
            PasswordPolicyWarning(
                code="control_characters",
                message="Your password contains control characters.",
            )
        )

    if any(
        unicodedata.category(character) == "Cf"
        for character in canonical_password
    ):
        warnings.append(
            PasswordPolicyWarning(
                code="invisible_characters",
                message="Your password contains invisible format characters.",
            )
        )

    normalized_password = _normalize_for_comparison(canonical_password)
    if not normalized_password:
        warnings.append(
            PasswordPolicyWarning(
                code="no_visible_characters",
                message=(
                    "Your password has no visible letters, numbers, or symbols "
                    "after normalization."
                ),
            )
        )

    if _minimum_length_codepoints(canonical_password) < config.MIN_PASSWORD_LENGTH:
        warnings.append(
            PasswordPolicyWarning(
                code="too_short",
                message=(
                    "Your password is shorter than the recommended minimum of "
                    f"{config.MIN_PASSWORD_LENGTH} characters; surrounding "
                    "spaces and invisible format characters do not count."
                ),
            ),
        )

    if strength < config.PASSWORD_STRENGTH_WARNING_THRESHOLD:
        warnings.append(
            PasswordPolicyWarning(
                code="low_strength",
                message="The password strength meter rates this password as weak.",
            )
        )

    normalized_expected = frozenset(
        normalized
        for value in expected_passwords
        if value.strip()
        if (normalized := _normalize_for_comparison(value))
    )
    if normalized_password:
        predictability_code = _predictability_warning_code(
            normalized_password,
            expected_passwords=normalized_expected,
        )
        if predictability_code is not None:
            warnings.append(_predictability_warning(predictability_code))

    return _decision_from_warnings(
        strength=strength,
        warnings=tuple(warnings),
        acknowledged_weak=acknowledged_weak,
    )


def _decision_from_warnings(
    *,
    strength: int,
    warnings: tuple[PasswordPolicyWarning, ...],
    acknowledged_weak: bool,
) -> PasswordPolicyDecision:
    if not warnings:
        return PasswordPolicyDecision(ok=True, strength=strength)

    warning_strength = _warning_strength(strength)
    warning_summary = " ".join(warning.message for warning in warnings)
    if not config.ALLOW_WEAK_PASSWORDS:
        return PasswordPolicyDecision(
            ok=False,
            strength=warning_strength,
            warnings=warnings,
            message=(
                f"{warning_summary} This deployment does not allow passwords "
                "with these warnings."
            ),
        )

    if not acknowledged_weak:
        return PasswordPolicyDecision(
            ok=False,
            strength=warning_strength,
            warnings=warnings,
            requires_acknowledgement=True,
            message=(
                f"{warning_summary} Please acknowledge these warnings or "
                "choose a different password."
            ),
        )

    return PasswordPolicyDecision(
        ok=True,
        strength=warning_strength,
        warnings=warnings,
    )


def _predictability_warning(code: str) -> PasswordPolicyWarning:
    messages = {
        "account_derived": (
            "Your password is based on an account identifier and is predictable."
        ),
        "common_password": "This password is too common or predictable.",
        "repeated_pattern": "Your password contains a predictable repeated pattern.",
        "sequential_pattern": "Your password contains a predictable sequence.",
    }
    return PasswordPolicyWarning(code=code, message=messages[code])


def _normalize_for_comparison(value: str) -> str:
    """Build a compatibility skeleton for blocklist comparisons only."""
    compatibility_value = unicodedata.normalize("NFKD", value.casefold())
    without_invisible_padding = "".join(
        character
        for character in compatibility_value
        if unicodedata.category(character)[0] not in {"C", "M"}
    )
    return unicodedata.normalize("NFKC", without_invisible_padding).strip()


def _minimum_length_codepoints(canonical_password: str) -> int:
    """Count policy-length code points without script-biased mark removal."""
    return sum(
        unicodedata.category(character) != "Cf"
        for character in canonical_password.strip()
    )


_STATIC_BLOCKLIST = frozenset(
    normalized
    for value in COMMON_PASSWORDS | APPLICATION_PASSWORDS
    if (normalized := _normalize_for_comparison(value))
)
_STATIC_BLOCKLIST_LENGTHS = frozenset(map(len, _STATIC_BLOCKLIST))


def _predictability_warning_code(
    normalized_password: str,
    *,
    expected_passwords: frozenset[str],
) -> str | None:
    if not normalized_password:
        return "common_password"

    if normalized_password in expected_passwords:
        return "account_derived"
    if normalized_password in _STATIC_BLOCKLIST:
        return "common_password"

    if _is_repeated_pattern(normalized_password):
        return "repeated_pattern"

    if _is_monotonic_sequence(normalized_password):
        return "sequential_pattern"

    affix_warning_code = _predictable_affix_warning_code(
        normalized_password,
        expected_passwords=expected_passwords,
    )
    return affix_warning_code


def _predictable_affix_warning_code(
    value: str,
    *,
    expected_passwords: frozenset[str],
) -> str | None:
    # Catch the smallest alphabetic mutation which can otherwise turn an exact
    # account or blocklist value into a high-scoring password. Limit this to one
    # letter on either edge (or one on both edges); treating arbitrary letter
    # runs as adornments would make ordinary words containing a warned value
    # produce noisy substring matches.
    alphabetic_warning_code = _single_alphabetic_edge_warning_code(
        value,
        expected_passwords=expected_passwords,
    )
    if alphabetic_warning_code is not None:
        return alphabetic_warning_code

    # Check every split inside a trailing adornment run. This preserves digits
    # and punctuation that belong to the blocklisted base itself (for example,
    # ``agent007``) instead of destructively stripping the whole run.
    for split_index in range(len(value) - 1, 0, -1):
        if not _is_predictable_adornment(value[split_index]):
            break
        warning_code = _blocked_base_warning_code(
            value[:split_index],
            expected_passwords=expected_passwords,
        )
        if warning_code is not None:
            return warning_code

    # Apply the same derivative check to leading adornments.
    for split_index in range(1, len(value)):
        if not _is_predictable_adornment(value[split_index - 1]):
            break
        warning_code = _blocked_base_warning_code(
            value[split_index:],
            expected_passwords=expected_passwords,
        )
        if warning_code is not None:
            return warning_code

    # If adornments exist on both sides, neither one-sided pass can expose the
    # base by itself. Check only lengths that can match a static or contextual
    # blocklist value, keeping work bounded even for a 1,024-character input.
    leading_starts: list[int] = []
    for split_index in range(1, len(value)):
        if not _is_predictable_adornment(value[split_index - 1]):
            break
        leading_starts.append(split_index)

    trailing_ends: set[int] = set()
    for split_index in range(len(value) - 1, 0, -1):
        if not _is_predictable_adornment(value[split_index]):
            break
        trailing_ends.add(split_index)

    if not leading_starts or not trailing_ends:
        return None

    # Detect a repeated or monotonic core even when it is longer than every
    # static/contextual blocklist value. The length-indexed scan below is
    # intentionally bounded, so it cannot discover an arbitrary-length core
    # surrounded by adornments (for example, ``!!abab...123!!``).
    stripped_start = leading_starts[-1]
    stripped_end = min(trailing_ends)
    structural_candidates = (
        (value[start_index:stripped_end] for start_index in leading_starts),
        (value[stripped_start:end_index] for end_index in trailing_ends),
    )
    for candidates in structural_candidates:
        for candidate in candidates:
            if _is_repeated_pattern(candidate):
                return "repeated_pattern"
            if _is_monotonic_sequence(candidate):
                return "sequential_pattern"

    blocked_lengths = _STATIC_BLOCKLIST_LENGTHS | frozenset(
        map(len, expected_passwords)
    )
    for start_index in leading_starts:
        for blocked_length in blocked_lengths:
            end_index = start_index + blocked_length
            if end_index not in trailing_ends:
                continue
            warning_code = _blocked_base_warning_code(
                value[start_index:end_index],
                expected_passwords=expected_passwords,
            )
            if warning_code is not None:
                return warning_code

    return None


def _single_alphabetic_edge_warning_code(
    value: str,
    *,
    expected_passwords: frozenset[str],
) -> str | None:
    candidates: list[str] = []
    if value[-1:].isalpha():
        candidates.append(value[:-1])
    if value[:1].isalpha():
        candidates.append(value[1:])
    if len(value) > 2 and value[0].isalpha() and value[-1].isalpha():
        candidates.append(value[1:-1])

    for candidate in candidates:
        warning_code = _blocked_base_warning_code(
            candidate,
            expected_passwords=expected_passwords,
        )
        if warning_code is not None:
            return warning_code
    return None


def _blocked_base_warning_code(
    value: str,
    *,
    expected_passwords: frozenset[str],
) -> str | None:
    if value in expected_passwords:
        return "account_derived"

    # Very short blocklist entries would make almost every numeric/symbolic
    # password look like a derivative. Exact short values are detected above.
    if len(value) < 4:
        return None
    if value in _STATIC_BLOCKLIST:
        return "common_password"
    if _is_repeated_pattern(value):
        return "repeated_pattern"
    if _is_monotonic_sequence(value):
        return "sequential_pattern"
    return None


def _is_predictable_adornment(character: str) -> bool:
    category = unicodedata.category(character)[0]
    return character.isdigit() or character.isspace() or category in {"P", "S"}


def _is_repeated_pattern(value: str) -> bool:
    """Return whether the entire value is repetitions of a shorter value."""
    return len(value) > 1 and value in (value + value)[1:-1]


def _is_monotonic_sequence(value: str) -> bool:
    """Detect full-value ascending/descending ASCII letter or digit sequences."""
    if len(value) < 3:
        return False

    if value.isascii() and value.isdigit():
        numbers = [int(character) for character in value]
        return all(
            (right - left) % 10 == 1
            for left, right in zip(numbers, numbers[1:])
        ) or all(
            (left - right) % 10 == 1
            for left, right in zip(numbers, numbers[1:])
        )

    if value.isascii() and value.isalpha():
        codepoints = [ord(character) - ord("a") for character in value]
        return all(
            (right - left) % 26 == 1
            for left, right in zip(codepoints, codepoints[1:])
        ) or all(
            (left - right) % 26 == 1
            for left, right in zip(codepoints, codepoints[1:])
        )

    return False


def _warning_strength(strength: int) -> int:
    return min(
        strength,
        max(0, config.PASSWORD_STRENGTH_WARNING_THRESHOLD - 1),
    )
