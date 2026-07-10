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

from app import passwords as password_utils
from app.config import config
from app.data_models import (
    AppUser,
    ExpirableVerificationToken,
    RecoveryCodeRecord,
    UserSession,
)
from app.persistence_users import get_user_select_columns, _row_to_app_user
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
    if not user.is_active:
        raise KeyError(f"User account is inactive: {user_id}")

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
            # Store the SHA-256 hash of the token at rest; the raw token is
            # returned to the caller (and handed to the client) but never
            # persisted in cleartext. See get_session_by_auth_token for the
            # matching hash-on-lookup.
            _hash_one_time_token(session.id),
            str(session.user_id),
            session.created_at.timestamp(),
            session.valid_until.timestamp(),
            session.role,
        ),
    )
    conn.commit()

    return session


async def invalidate_session(
    persistence: AuthPersistence,
    auth_token: str,
) -> None:
    """Invalidate one session by deleting its hashed bearer-token row."""
    if not auth_token:
        return

    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    try:
        cursor.execute(
            "DELETE FROM user_sessions WHERE id = ?",
            (_hash_one_time_token(auth_token),),
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


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
        (_hash_one_time_token(auth_token),),
    )

    row = cursor.fetchone()
    if row is None:
        raise KeyError("No session found for the supplied auth token")

    return UserSession(
        # Return the raw token the caller supplied, never row[0] (the stored
        # hash). UserSession.id must stay equal to the client's bearer token.
        id=auth_token,
        user_id=uuid.UUID(row[1]),
        created_at=datetime.fromtimestamp(row[2], tz=timezone.utc),
        valid_until=datetime.fromtimestamp(row[3], tz=timezone.utc),
        role=row[4],
    )


def _get_valid_session_by_auth_token(
    persistence: AuthPersistence,
    auth_token: str,
    *,
    now: datetime,
) -> tuple[UserSession, AppUser]:
    cursor = persistence._get_cursor()
    cursor.execute(
        f"""
        SELECT
            s.id,
            s.user_id,
            s.created_at,
            s.valid_until,
            s.role,
            {get_user_select_columns("u")}
        FROM user_sessions AS s
        JOIN users AS u ON u.id = s.user_id
        WHERE s.id = ?
        ORDER BY s.created_at
        LIMIT 1
        """,
        (_hash_one_time_token(auth_token),),
    )

    row = cursor.fetchone()
    if row is None:
        raise KeyError("No session found for the supplied auth token")

    valid_until = datetime.fromtimestamp(row[3], tz=timezone.utc)
    if valid_until <= now:
        raise KeyError("Session expired for the supplied auth token")

    # The session columns occupy indices 0-4; the user columns follow, so the
    # user slice starts at row[5:].
    user = _row_to_app_user(row[5:])
    if not user.is_active:
        raise KeyError("User account is inactive for the supplied auth token")

    session = UserSession(
        # Raw token in, raw token out (row[0] is the stored hash).
        id=auth_token,
        user_id=uuid.UUID(row[1]),
        created_at=datetime.fromtimestamp(row[2], tz=timezone.utc),
        valid_until=valid_until,
        role=user.role,
    )

    return session, user


def get_valid_session_by_auth_token(
    persistence: AuthPersistence,
    auth_token: str,
) -> tuple[UserSession, AppUser]:
    """
    Retrieve a non-expired user session and its current user row.

    This is intentionally synchronous so Rio page guards can revalidate
    already-attached sessions before allowing protected navigation.
    """
    return _get_valid_session_by_auth_token(
        persistence,
        auth_token,
        now=datetime.now(tz=timezone.utc),
    )


async def get_and_extend_valid_session_by_auth_token(
    persistence: AuthPersistence,
    auth_token: str,
    *,
    valid_for: timedelta,
) -> tuple[UserSession, AppUser]:
    """Atomically validate a live session and extend its sliding lifetime."""
    if not auth_token:
        raise KeyError("No session found for the supplied auth token")
    if valid_for <= timedelta(0):
        raise ValueError("Session extension duration must be positive")

    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    try:
        # Keep this transaction free of awaits. BEGIN IMMEDIATE establishes the
        # ordering point against concurrent revocations before we re-read state.
        conn.execute("BEGIN IMMEDIATE")
        now = datetime.now(tz=timezone.utc)
        session, user = _get_valid_session_by_auth_token(
            persistence,
            auth_token,
            now=now,
        )

        renewed_until = now + valid_for
        if config.SESSION_ABSOLUTE_MAX_DAYS > 0:
            absolute_deadline = session.created_at + timedelta(
                days=config.SESSION_ABSOLUTE_MAX_DAYS
            )
            renewed_until = min(renewed_until, absolute_deadline)

        if renewed_until <= now:
            # Absolute expiry is terminal. Commit the deletion before raising so
            # the failure handler does not roll it back and leave a bearer token
            # usable through read-only API authentication.
            cursor.execute(
                "DELETE FROM user_sessions WHERE id = ?",
                (_hash_one_time_token(auth_token),),
            )
            conn.commit()
            raise KeyError("Session exceeded its absolute lifetime")

        cursor.execute(
            """
            UPDATE user_sessions
            SET valid_until = ?
            WHERE id = ? AND valid_until > ?
            """,
            (
                renewed_until.timestamp(),
                _hash_one_time_token(auth_token),
                now.timestamp(),
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError("Session expired before it could be extended")

        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    # Do not expose an expiry that was not committed successfully.
    session.valid_until = renewed_until
    return session, user


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
    Invalidate all sessions for a given user by deleting their rows.

    ## Parameters

    `user_id`: The UUID of the user whose sessions to invalidate.
    """
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    try:
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = ?",
            (str(user_id),),
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


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
    # Generate new password hash and salt using the current password scheme.
    # TODO: Enforce minimum password strength once QA convenience window closes.
    password_hash, password_salt, password_scheme = password_utils.hash_password(new_password)
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?, password_salt = ?, password_scheme = ?
            WHERE id = ?
            """,
            (password_hash, password_salt, password_scheme, str(user_id)),
        )
        if cursor.rowcount == 0:
            raise KeyError(user_id)

        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = ?",
            (str(user_id),),
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


async def upgrade_user_password_hash(
    persistence: AuthPersistence,
    user_id: uuid.UUID,
    password: str,
) -> AppUser:
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    current_user = await persistence.get_user_by_id(user_id)
    result = current_user.verify_password_result(password)
    if not result.ok:
        raise ValueError("Password verification failed during hash upgrade")
    if not result.needs_rehash:
        return current_user

    password_hash, password_salt, password_scheme = password_utils.hash_password(password)

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor.execute(
            f"""
            SELECT {get_user_select_columns()}
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (str(user_id),),
        )
        row = cursor.fetchone()
        if row is None:
            raise KeyError(user_id)

        user = _row_to_app_user(row)
        result = user.verify_password_result(password)
        if not result.ok:
            raise ValueError("Password verification failed during hash upgrade")
        if not result.needs_rehash:
            conn.rollback()
            return user

        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?, password_salt = ?, password_scheme = ?
            WHERE id = ?
            """,
            (password_hash, password_salt, password_scheme, str(user_id)),
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return await persistence.get_user_by_id(user_id)


async def consume_reset_token_and_update_password(
    persistence: AuthPersistence,
    token: str,
    user_id: uuid.UUID,
    new_password: str,
) -> bool:
    password_hash, password_salt, password_scheme = password_utils.hash_password(new_password)
    token_hash = _hash_one_time_token(token)
    now = datetime.now(timezone.utc)
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor.execute(
            """
            SELECT user_id, valid_until
            FROM password_reset_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        if row is None:
            conn.rollback()
            return False

        token_user_id = uuid.UUID(row[0])
        valid_until = datetime.fromtimestamp(row[1], tz=timezone.utc)
        if token_user_id != user_id or valid_until <= now:
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = ?",
                (token_hash,),
            )
            conn.commit()
            return False

        cursor.execute(
            "SELECT is_active FROM users WHERE id = ?",
            (str(user_id),),
        )
        user_row = cursor.fetchone()
        if user_row is None or not bool(user_row[0]):
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = ?",
                (token_hash,),
            )
            conn.commit()
            return False

        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?, password_salt = ?, password_scheme = ?
            WHERE id = ?
            """,
            (password_hash, password_salt, password_scheme, str(user_id)),
        )
        if cursor.rowcount == 0:
            raise KeyError(user_id)

        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = ?",
            (str(user_id),),
        )
        conn.commit()
        return True
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


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
    user = await persistence.get_user_by_id(user_id)
    if not user.is_active:
        raise ValueError("Cannot create a reset token for an inactive user.")

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
    user = await persistence.get_user_by_id(uuid.UUID(row[0]))
    if not user.is_active:
        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE token_hash = ?",
            (hashed_token,),
        )
        conn.commit()
        raise KeyError(f"Reset token belongs to an inactive user: {token}")
    return user


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
            "SELECT is_active FROM users WHERE id = ?",
            (user_id_str,),
        )
        user_row = cursor.fetchone()
        if user_row is None or not bool(user_row[0]):
            cursor.execute(
                "DELETE FROM email_verification_tokens WHERE token_hash = ?",
                (token_hash,),
            )
            conn.commit()
            raise KeyError("Verification token belongs to an inactive user.")

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
