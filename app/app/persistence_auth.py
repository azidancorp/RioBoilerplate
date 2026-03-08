import hashlib
import secrets
import sqlite3
import typing as t
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol

import pyotp

from app.config import config
from app.data_models import (
    AppUser,
    ExpirableVerificationToken,
    RecoveryCodeRecord,
    UserSession,
)
from app.validation import SecuritySanitizer


class TwoFactorMethod(str, Enum):
    NOT_REQUIRED = "not_required"
    TOTP = "totp"
    RECOVERY_CODE = "recovery_code"


class TwoFactorFailure(str, Enum):
    MISSING_CODE = "missing_code"
    INVALID_FORMAT = "invalid_format"
    INVALID_CODE = "invalid_code"


@dataclass(frozen=True)
class TwoFactorChallengeResult:
    ok: bool
    method: TwoFactorMethod | None = None
    used_recovery_code: bool = False
    failure: TwoFactorFailure | None = None
    failure_detail: str | None = None

    def get_error_message(self) -> str:
        """Return a user-facing error message for a failed 2FA challenge."""
        if self.failure == TwoFactorFailure.INVALID_FORMAT:
            return self.failure_detail or "Invalid 2FA code format."
        if self.failure == TwoFactorFailure.MISSING_CODE:
            return "Please enter your 2FA or recovery code."
        return "Invalid verification or recovery code. Please try again."


class AuthPersistence(Protocol):
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...

    async def get_user_by_id(self, id: uuid.UUID) -> AppUser:
        ...


def _get_connection(persistence: AuthPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _generate_recovery_code() -> str:
    """
    Generate a human-friendly recovery code in the format XXXX-XXXX-XXXX.
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(12))
    return "-".join(raw[i : i + 4] for i in range(0, 12, 4))


def _normalize_recovery_code(code: str | None) -> str:
    """
    Normalize a recovery code for hashing/verification.
    """
    if not code:
        return ""
    return "".join(part.strip() for part in code.upper().split("-"))


def _hash_one_time_token(token: str) -> str:
    """
    Hash a one-time token before storing or comparing it.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_recovery_codes(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    count: int = 10,
) -> list[str]:
    """
    Generate a fresh set of recovery codes for a user, replacing any existing codes.
    """
    conn = _get_connection(persistence)
    normalized_user_id = str(user_id)
    cursor = persistence._get_cursor()
    new_codes: list[str] = []

    try:
        conn.execute("BEGIN IMMEDIATE")

        # Clear existing codes within the same transaction to keep operations atomic.
        invalidate_recovery_codes(persistence, user_id, commit=False)

        for _ in range(count):
            code = _generate_recovery_code()
            normalized_code = _normalize_recovery_code(code)
            created_at = datetime.now(timezone.utc)
            valid_until = created_at + timedelta(days=config.RECOVERY_CODE_TTL_DAYS)
            code_hash = _hash_one_time_token(normalized_code)

            cursor.execute(
                """
                INSERT INTO two_factor_recovery_codes (
                    user_id, code_hash, created_at, valid_until, used_at
                ) VALUES (?, ?, ?, ?, NULL)
                """,
                (
                    normalized_user_id,
                    code_hash,
                    created_at.timestamp(),
                    valid_until.timestamp(),
                ),
            )
            new_codes.append(code)

        conn.commit()
    except Exception:
        conn.rollback()
        raise

    # TODO: Send notification email once email infrastructure supports recovery code events.
    return new_codes


def invalidate_recovery_codes(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    *,
    commit: bool = True,
) -> None:
    """Remove all recovery codes for a user."""
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    cursor.execute(
        "DELETE FROM two_factor_recovery_codes WHERE user_id = ?",
        (str(user_id),),
    )
    if commit:
        conn.commit()


def consume_recovery_code(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    code: str,
) -> bool:
    """
    Attempt to consume a recovery code. Returns True if a valid unused code was supplied.
    Uses atomic check-and-set to prevent race conditions under concurrent load.
    """
    normalized_code = _normalize_recovery_code(code)
    if not normalized_code:
        return False

    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    # Begin immediate transaction to acquire exclusive lock and prevent race conditions
    conn.execute("BEGIN IMMEDIATE")

    try:
        # Only fetch unused, non-expired codes.
        now_ts = datetime.now(timezone.utc).timestamp()
        cursor.execute(
            """
            SELECT id, code_hash
            FROM two_factor_recovery_codes
            WHERE user_id = ? AND used_at IS NULL AND valid_until > ?
            """,
            (str(user_id), now_ts),
        )

        rows = cursor.fetchall()
        candidate_hash = _hash_one_time_token(normalized_code)
        for code_id, stored_hash in rows:
            if secrets.compare_digest(stored_hash, candidate_hash):
                # Atomic update with WHERE clause to ensure code is still unused
                cursor.execute(
                    """
                    UPDATE two_factor_recovery_codes
                    SET used_at = ?
                    WHERE id = ? AND used_at IS NULL
                    """,
                    (datetime.now(timezone.utc).timestamp(), code_id),
                )

                # Verify the update actually modified a row (prevents double-spend)
                if cursor.rowcount == 1:
                    conn.commit()
                    # TODO: Send notification email once email infrastructure supports recovery code events.
                    return True

                # Another request consumed this code between our SELECT and UPDATE
                conn.rollback()
                return False

        conn.rollback()
        return False

    except Exception:
        conn.rollback()
        raise


def get_recovery_codes_metadata(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> list[RecoveryCodeRecord]:
    """
    Retrieve metadata for all recovery codes belonging to a user.
    """
    cursor = persistence._get_cursor()
    cursor.execute(
        """
        SELECT id, created_at, used_at
        FROM two_factor_recovery_codes
        WHERE user_id = ?
        ORDER BY created_at ASC, id ASC
        """,
        (str(user_id),),
    )

    rows = cursor.fetchall()
    metadata: list[RecoveryCodeRecord] = []
    for code_id, created_ts, used_ts in rows:
        metadata.append(
            RecoveryCodeRecord(
                id=code_id,
                user_id=user_id,
                created_at=datetime.fromtimestamp(created_ts, tz=timezone.utc),
                used_at=(
                    datetime.fromtimestamp(used_ts, tz=timezone.utc)
                    if used_ts is not None
                    else None
                ),
            )
        )
    return metadata


def get_recovery_codes_summary(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> dict[str, t.Any]:
    """
    Provide aggregate information about a user's recovery codes.
    """
    metadata = get_recovery_codes_metadata(persistence, user_id)
    if not metadata:
        return {
            "total": 0,
            "used": 0,
            "remaining": 0,
            "last_generated": None,
        }

    total = len(metadata)
    used = sum(1 for record in metadata if record.used_at is not None)
    remaining = total - used
    last_generated = max(record.created_at for record in metadata)

    return {
        "total": total,
        "used": used,
        "remaining": remaining,
        "last_generated": last_generated,
    }


async def create_session(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> UserSession:
    """
    Create a new user session and store it in the database.

    ## Parameters

    `user_id`: The UUID of the user for whom to create the session.
    """
    conn = _get_connection(persistence)
    now = datetime.now(tz=timezone.utc)

    user = await persistence.get_user_by_id(user_id)

    session = UserSession(
        id=secrets.token_urlsafe(),
        user_id=user_id,
        created_at=now,
        valid_until=now + timedelta(days=1),
        role=user.role,
    )

    cursor = persistence._get_cursor()
    cursor.execute(
        """
        INSERT INTO user_sessions (id, user_id, created_at, valid_until, role)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            session.id,
            str(session.user_id),
            session.created_at.timestamp(),
            session.valid_until.timestamp(),
            session.role,
        ),
    )
    conn.commit()

    return session


async def update_session_duration(
    persistence: AuthPersistence,
    session: UserSession,
    new_valid_until: datetime,
) -> None:
    """
    Extend the duration of an existing session. This will update the
    session's validity timestamp both in the given object and the database.

    ## Parameters

    `session`: The session whose duration to extend.

    `new_valid_until`: The new timestamp until which the session should be
        considered valid.
    """
    conn = _get_connection(persistence)
    session.valid_until = new_valid_until

    cursor = persistence._get_cursor()
    cursor.execute(
        """
        UPDATE user_sessions
        SET valid_until = ?
        WHERE id = ?
        """,
        (
            session.valid_until.timestamp(),
            session.id,
        ),
    )
    conn.commit()


async def get_session_by_auth_token(
    persistence: AuthPersistence,
    auth_token: str,
) -> UserSession:
    """
    Retrieve a user session from the database by authentication token.

    ## Parameters

    `auth_token`: The authentication token (session ID) of the session to
        retrieve.

    ## Raises

    `KeyError`: If there is no session with the specified authentication
    token.
    """
    cursor = persistence._get_cursor()
    cursor.execute(
        "SELECT id, user_id, created_at, valid_until, role FROM user_sessions WHERE id = ? ORDER BY created_at LIMIT 1",
        (auth_token,),
    )

    row = cursor.fetchone()
    if row is None:
        raise KeyError(f"No session found with auth token {auth_token}")

    return UserSession(
        id=row[0],
        user_id=uuid.UUID(row[1]),
        created_at=datetime.fromtimestamp(row[2], tz=timezone.utc),
        valid_until=datetime.fromtimestamp(row[3], tz=timezone.utc),
        role=row[4],
    )


def _get_two_factor_secret(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> str | None:
    cursor = persistence._get_cursor()
    cursor.execute("SELECT two_factor_secret FROM users WHERE id = ?", (str(user_id),))
    row = cursor.fetchone()
    if not row:
        return None
    return t.cast(str | None, row[0])


def verify_two_factor_challenge(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    code: str | None,
    *,
    consume_recovery_code: bool = True,
) -> TwoFactorChallengeResult:
    """
    Verify a user-supplied 2FA input against either TOTP or a recovery code.

    This is the centralized 2FA verification entrypoint used by UI flows.
    It owns:
    - input sanitization (`SecuritySanitizer.sanitize_auth_code`)
    - token normalization (strip hyphens)
    - branching between TOTP vs. recovery-code verification
    - recovery-code consumption (single-use semantics)
    """
    secret = _get_two_factor_secret(persistence, user_id)
    if not secret:
        return TwoFactorChallengeResult(ok=True, method=TwoFactorMethod.NOT_REQUIRED)

    try:
        sanitized_code = SecuritySanitizer.sanitize_auth_code(code)
    except Exception as exc:
        detail = getattr(exc, "detail", None)
        return TwoFactorChallengeResult(
            ok=False,
            failure=TwoFactorFailure.INVALID_FORMAT,
            failure_detail=str(detail) if detail else "Invalid authentication code.",
        )

    if not sanitized_code:
        return TwoFactorChallengeResult(
            ok=False,
            failure=TwoFactorFailure.MISSING_CODE,
            failure_detail="Two-factor authentication code is required.",
        )

    normalized = sanitized_code.replace("-", "")
    if normalized.isdigit():
        totp = pyotp.TOTP(secret)
        if totp.verify(normalized):
            return TwoFactorChallengeResult(ok=True, method=TwoFactorMethod.TOTP)

    if consume_recovery_code and consume_recovery_code_token(
        persistence, user_id, sanitized_code
    ):
        return TwoFactorChallengeResult(
            ok=True,
            method=TwoFactorMethod.RECOVERY_CODE,
            used_recovery_code=True,
        )

    return TwoFactorChallengeResult(
        ok=False,
        failure=TwoFactorFailure.INVALID_CODE,
        failure_detail="Invalid verification or recovery code.",
    )


def consume_recovery_code_token(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    code: str,
) -> bool:
    return consume_recovery_code(persistence, user_id, code)


def is_2fa_enabled(persistence: AuthPersistence, user_id: uuid.UUID) -> bool:
    """Check if 2FA is enabled for a user."""
    cursor = persistence._get_cursor()
    cursor.execute("SELECT two_factor_secret FROM users WHERE id = ?", (str(user_id),))
    result = cursor.fetchone()
    return bool(result and result[0])


def set_2fa_secret(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    secret: str | None,
) -> None:
    """Enable or Disable 2FA for a user.
    Set to str if enabling, or to None if disabling
    """
    conn = _get_connection(persistence)
    if secret is not None:
        secret = secret.strip() or None
    cursor = persistence._get_cursor()
    cursor.execute(
        "UPDATE users SET two_factor_secret = ? WHERE id = ?",
        (secret, str(user_id)),
    )
    conn.commit()
    if secret is None:
        invalidate_recovery_codes(persistence, user_id)


async def invalidate_all_sessions(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> None:
    """
    Invalidate all sessions for a given user by setting their valid_until
    timestamp to the current time.

    ## Parameters

    `user_id`: The UUID of the user whose sessions to invalidate.
    """
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    now = datetime.now(timezone.utc).timestamp()

    cursor.execute(
        "UPDATE user_sessions SET valid_until = ? WHERE user_id = ?",
        (now, str(user_id)),
    )
    conn.commit()


async def update_password(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    new_password: str,
) -> None:
    """
    Update a user's password hash and salt.

    ## Parameters

    `user_id`: The UUID of the user whose password to update
    `new_password`: The new password to set

    ## Raises

    `KeyError`: If the user does not exist
    """
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    # First verify the user exists
    await persistence.get_user_by_id(user_id)

    # Generate new password hash and salt using AppUser's method
    # TODO: Enforce minimum password strength once QA convenience window closes.
    password_salt = secrets.token_bytes(64)
    password_hash = AppUser.get_password_hash(new_password, password_salt)

    # Update the password in database
    cursor.execute(
        """
        UPDATE users
        SET password_hash = ?, password_salt = ?
        WHERE id = ?
        """,
        (password_hash, password_salt, str(user_id)),
    )
    conn.commit()

    # Invalidate all existing sessions for security
    await invalidate_all_sessions(persistence, user_id)


async def create_reset_token(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> ExpirableVerificationToken:
    """
    Create a new password reset token for a user.

    ## Parameters

    `user_id`: The UUID of the user to create a reset token for

    ## Returns

    The newly created reset token

    ## Raises

    `KeyError`: If the user does not exist
    """
    conn = _get_connection(persistence)

    # First verify the user exists
    await persistence.get_user_by_id(user_id)

    # Remove any existing tokens for this user to enforce single-use semantics
    await clear_reset_tokens(persistence, user_id)

    cursor = persistence._get_cursor()
    reset_token = ExpirableVerificationToken.create(
        user_id=user_id,
        valid_for=timedelta(minutes=config.PASSWORD_RESET_TOKEN_TTL_MINUTES),
    )
    hashed_token = _hash_one_time_token(reset_token.token)

    cursor.execute(
        """
        INSERT INTO password_reset_tokens (token_hash, user_id, created_at, valid_until)
        VALUES (?, ?, ?, ?)
        """,
        (
            hashed_token,
            str(reset_token.user_id),
            reset_token.created_at.timestamp(),
            reset_token.valid_until.timestamp(),
        ),
    )
    conn.commit()
    return reset_token


async def get_user_by_reset_token(
    persistence: AuthPersistence,
    token: str,
) -> AppUser:
    """
    Find a user by their reset token. The token must be valid (not expired).

    ## Parameters

    `token`: The reset token to look up

    ## Returns

    The user associated with this reset token

    ## Raises

    `KeyError`: If the token is invalid, expired, or the associated user doesn't exist
    """
    conn = _get_connection(persistence)
    hashed_token = _hash_one_time_token(token)
    cursor = persistence._get_cursor()

    # Get the reset token entry
    cursor.execute(
        """
        SELECT user_id, valid_until
        FROM password_reset_tokens
        WHERE token_hash = ?
        """,
        (hashed_token,),
    )

    row = cursor.fetchone()
    if not row:
        raise KeyError(f"Invalid reset token: {token}")

    # Check if the token is expired
    valid_until = datetime.fromtimestamp(row[1], tz=timezone.utc)
    if datetime.now(timezone.utc) >= valid_until:
        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE token_hash = ?",
            (hashed_token,),
        )
        conn.commit()
        raise KeyError(f"Reset token has expired: {token}")

    # Get and return the associated user
    return await persistence.get_user_by_id(uuid.UUID(row[0]))


async def consume_reset_token(
    persistence: AuthPersistence,
    token: str,
    user_id: uuid.UUID,
) -> bool:
    """
    Delete a password reset token after successful use.

    Returns True when the token was removed; False when the token was missing.
    """
    conn = _get_connection(persistence)
    hashed_token = _hash_one_time_token(token)
    cursor = persistence._get_cursor()

    conn.execute("BEGIN IMMEDIATE")

    try:
        cursor.execute(
            """
            DELETE FROM password_reset_tokens
            WHERE token_hash = ? AND user_id = ?
            """,
            (hashed_token, str(user_id)),
        )

        if cursor.rowcount != 1:
            conn.rollback()
            return False

        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise


async def clear_reset_tokens(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> None:
    """
    Delete all reset tokens for a user.

    ## Parameters

    `user_id`: The UUID of the user whose reset tokens to clear
    """
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    cursor.execute(
        "DELETE FROM password_reset_tokens WHERE user_id = ?",
        (str(user_id),),
    )
    conn.commit()


async def set_user_verified(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    is_verified: bool = True,
) -> None:
    """Mark a user account as verified/unverified."""
    conn = _get_connection(persistence)
    await persistence.get_user_by_id(user_id)
    cursor = persistence._get_cursor()
    cursor.execute(
        "UPDATE users SET is_verified = ? WHERE id = ?",
        (1 if is_verified else 0, str(user_id)),
    )
    conn.commit()


async def create_email_verification_token(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> ExpirableVerificationToken:
    """
    Create a new email verification token for a user.
    """
    conn = _get_connection(persistence)
    await persistence.get_user_by_id(user_id)
    await clear_email_verification_tokens(persistence, user_id)

    cursor = persistence._get_cursor()
    token = ExpirableVerificationToken.create(
        user_id=user_id,
        valid_for=timedelta(minutes=config.EMAIL_VERIFICATION_TOKEN_TTL_MINUTES),
    )
    token_hash = _hash_one_time_token(token.token)

    cursor.execute(
        """
        INSERT INTO email_verification_tokens (token_hash, user_id, created_at, valid_until)
        VALUES (?, ?, ?, ?)
        """,
        (
            token_hash,
            str(token.user_id),
            token.created_at.timestamp(),
            token.valid_until.timestamp(),
        ),
    )
    conn.commit()
    return token


async def consume_email_verification_token(
    persistence: AuthPersistence,
    token: str,
) -> AppUser:
    """
    Consume a verification token and mark the user as verified.
    """
    conn = _get_connection(persistence)
    token_hash = _hash_one_time_token(token)
    cursor = persistence._get_cursor()

    conn.execute("BEGIN IMMEDIATE")
    try:
        cursor.execute(
            """
            SELECT user_id, valid_until
            FROM email_verification_tokens
            WHERE token_hash = ?
            LIMIT 1
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        if not row:
            conn.rollback()
            raise KeyError("Invalid verification token.")

        user_id_str = str(row[0])
        valid_until = datetime.fromtimestamp(row[1], tz=timezone.utc)
        if datetime.now(timezone.utc) >= valid_until:
            cursor.execute(
                "DELETE FROM email_verification_tokens WHERE token_hash = ?",
                (token_hash,),
            )
            conn.commit()
            raise KeyError("Verification token has expired.")

        cursor.execute(
            "DELETE FROM email_verification_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        cursor.execute(
            "DELETE FROM email_verification_tokens WHERE user_id = ?",
            (user_id_str,),
        )
        cursor.execute(
            "UPDATE users SET is_verified = 1 WHERE id = ?",
            (user_id_str,),
        )

        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return await persistence.get_user_by_id(uuid.UUID(user_id_str))


async def clear_email_verification_tokens(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
) -> None:
    """Delete all email verification tokens for a user."""
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    cursor.execute(
        "DELETE FROM email_verification_tokens WHERE user_id = ?",
        (str(user_id),),
    )
    conn.commit()
