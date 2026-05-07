from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from pwdlib import PasswordHash


HASH_SCHEME_ARGON2ID = "argon2id"
HASH_SCHEME_PBKDF2_SHA256 = "pbkdf2_sha256"
LEGACY_PBKDF2_ITERATIONS = 100000

_password_hash = PasswordHash.recommended()


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
    encoded_hash = _password_hash.hash(password).encode("utf-8")
    return encoded_hash, None, HASH_SCHEME_ARGON2ID


def verify_password(
    password: str,
    stored_hash: bytes | str | None,
    stored_salt: bytes | None,
    scheme: str | None,
) -> PasswordVerificationResult:
    if stored_hash is None:
        return PasswordVerificationResult(ok=False)

    normalized_scheme = scheme or HASH_SCHEME_PBKDF2_SHA256
    if normalized_scheme == HASH_SCHEME_PBKDF2_SHA256:
        if stored_salt is None:
            return PasswordVerificationResult(ok=False)
        expected_hash = legacy_pbkdf2_password_hash(password, stored_salt)
        ok = secrets.compare_digest(_as_bytes(stored_hash), expected_hash)
        return PasswordVerificationResult(
            ok=ok,
            needs_rehash=ok,
        )

    if normalized_scheme == HASH_SCHEME_ARGON2ID:
        try:
            ok, updated_hash = _password_hash.verify_and_update(
                password,
                _as_text(stored_hash),
            )
        except Exception:
            return PasswordVerificationResult(ok=False)
        return PasswordVerificationResult(ok=ok, needs_rehash=updated_hash is not None)

    return PasswordVerificationResult(ok=False)


def _as_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _as_text(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value
