from __future__ import annotations

import hashlib
import re
import secrets
import unicodedata
from dataclasses import dataclass

from pwdlib import PasswordHash


HASH_SCHEME_ARGON2ID = "argon2id"
HASH_SCHEME_PBKDF2_SHA256 = "pbkdf2_sha256"
LEGACY_PBKDF2_ITERATIONS = 100000

_password_hash = PasswordHash.recommended()


def get_password_strength(
    password: str,
    *,
    minimum_length: int = 15,
    maximum_length: int = 1024,
    warning_threshold: int = 50,
) -> int:
    """Return a display-only 0-99 heuristic score for a proposed password."""
    if len(password) > maximum_length:
        return 0

    password = normalize_password(password)
    if len(password) > maximum_length:
        return 0

    length = len(password)
    score = 0

    score += length * 4

    upper_case_letters = re.findall(r"[A-Z]", password)
    lower_case_letters = re.findall(r"[a-z]", password)
    numbers = re.findall(r"\d", password)
    symbols = re.findall(r"[\W_]", password)

    if upper_case_letters:
        score += (length - len(upper_case_letters)) * 2
    if lower_case_letters:
        score += (length - len(lower_case_letters)) * 2
    if numbers:
        score += len(numbers) * 4
    if symbols:
        score += len(symbols) * 6

    if length > 2:
        middle_chars = password[1:-1]
        score += len(re.findall(r"[\d\W_]", middle_chars)) * 2

    requirements = [
        length >= 12,
        bool(upper_case_letters),
        bool(lower_case_letters),
        bool(numbers),
        bool(symbols),
    ]
    fulfilled_requirements = sum(requirements)
    if fulfilled_requirements >= 3:
        score += fulfilled_requirements * 2

    if re.match(r"^[a-zA-Z]+$", password):
        score -= length
    if re.match(r"^\d+$", password):
        score -= length

    score -= len(password) - len(set(password.lower()))
    score -= len(re.findall(r"[A-Z]{2,}", password)) * 2
    score -= len(re.findall(r"[a-z]{2,}", password)) * 2
    score -= len(re.findall(r"\d{2,}", password)) * 2

    score -= sum(
        1
        for index in range(len(password) - 2)
        if password[index : index + 3].isalpha()
        and ord(password[index + 1]) == ord(password[index]) + 1
        and ord(password[index + 2]) == ord(password[index]) + 2
    ) * 3
    score -= sum(
        1
        for index in range(len(password) - 2)
        if password[index : index + 3].isdigit()
        and ord(password[index + 1]) == ord(password[index]) + 1
        and ord(password[index + 2]) == ord(password[index]) + 2
    ) * 3
    score -= sum(
        1
        for index in range(len(password) - 2)
        if re.match(r"[\W_]{3}", password[index : index + 3])
        and ord(password[index + 1]) == ord(password[index]) + 1
        and ord(password[index + 2]) == ord(password[index]) + 2
    ) * 3

    score = max(0, min(score, 99))
    meaningful_password = password.strip()
    if not meaningful_password:
        return 0

    below_recommendation = max(0, min(warning_threshold - 1, 99))
    if len(password) < minimum_length:
        score = min(score, below_recommendation)
    if len(set(meaningful_password.casefold())) == 1:
        score = min(score, min(10, below_recommendation))

    return score


@dataclass(frozen=True)
class PasswordVerificationResult:
    ok: bool
    needs_rehash: bool = False


def legacy_pbkdf2_password_hash(password: str, password_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=password_salt,
        iterations=LEGACY_PBKDF2_ITERATIONS,
    )


def hash_password(password: str) -> tuple[bytes, None, str]:
    encoded_hash = _password_hash.hash(normalize_password(password)).encode("utf-8")
    return encoded_hash, None, HASH_SCHEME_ARGON2ID


def verify_password(
    password: str,
    stored_hash: bytes | str | None,
    stored_salt: bytes | None,
    scheme: str | None,
) -> PasswordVerificationResult:
    if stored_hash is None:
        return PasswordVerificationResult(ok=False)

    normalized_password = normalize_password(password)
    password_candidates = (normalized_password,)
    if normalized_password != password:
        password_candidates += (password,)

    normalized_scheme = scheme or HASH_SCHEME_PBKDF2_SHA256
    if normalized_scheme == HASH_SCHEME_PBKDF2_SHA256:
        if stored_salt is None:
            return PasswordVerificationResult(ok=False)
        for candidate in password_candidates:
            expected_hash = legacy_pbkdf2_password_hash(candidate, stored_salt)
            if secrets.compare_digest(_as_bytes(stored_hash), expected_hash):
                return PasswordVerificationResult(ok=True, needs_rehash=True)
        return PasswordVerificationResult(ok=False)

    if normalized_scheme == HASH_SCHEME_ARGON2ID:
        for candidate in password_candidates:
            try:
                ok, updated_hash = _password_hash.verify_and_update(
                    candidate,
                    _as_text(stored_hash),
                )
            except Exception:
                continue
            if ok:
                return PasswordVerificationResult(
                    ok=True,
                    needs_rehash=(
                        updated_hash is not None
                        or candidate != normalized_password
                    ),
                )
        return PasswordVerificationResult(ok=False)

    return PasswordVerificationResult(ok=False)


def normalize_password(password: str) -> str:
    """Return the NFC form used for all newly stored password hashes."""
    return unicodedata.normalize("NFC", password)


def _as_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _as_text(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value
