import hashlib
import json
import os
import secrets
import sqlite3
import uuid
import typing as t
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.data_models import (
    AppUser,
    UserSession,
    PasswordResetCode,
    RecoveryCodeRecord,
    CurrencyLedgerEntry,
)
from app.validation import SecuritySanitizer
from app.config import config
from app.permissions import get_first_user_role, validate_role, get_all_roles
from app.currency import (
    get_currency_config,
    format_minor_amount,
    get_major_amount,
)
import pyotp


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


# Define the UserPersistence dataclass to handle database operations
class Persistence:
    """
    A class to handle database operations for users and sessions.

    User data is stored in the 'users' table, and session data is stored in the
    'user_sessions' table.

    You can adapt this class to your needs by adding more methods to interact
    with the database or support different databases like MongoDB.

    ## Attributes

    `db_path`: Path to the SQLite database file
    `allow_username_login`: Feature flag for username-based login fallbacks. Defaults to False.

    ## Foreign Key Enforcement

    This class enforces referential integrity via SQLite foreign key constraints.
    All database connections automatically enable `PRAGMA foreign_keys = ON`.

    **Active Foreign Key Constraints:**
    - `user_sessions.user_id` → `users.id`
    - `password_reset_codes.user_id` → `users.id`
    - `profiles.user_id` → `users.id`

    **Implications:**
    - Cannot create child records (sessions, profiles, reset codes) for non-existent users
    - Cannot delete users without first deleting all related child records
    - Violations raise `sqlite3.IntegrityError` with foreign key constraint details
    - All operations follow proper cascade order (verified safe)
    """

    USER_SELECT_COLUMNS = (
        "id, email, username, created_at, password_hash, password_salt, "
        "auth_provider, auth_provider_id, role, is_verified, "
        "two_factor_secret, referral_code, "
        "email_notifications_enabled, sms_notifications_enabled, "
        "primary_currency_balance, primary_currency_updated_at"
    )

    def __init__(
        self,
        db_path: Path = Path("app", "data", "app.db"),
        *,
        allow_username_login: bool = False,
    ) -> None:
        """
        Initialize the Persistence instance and ensure necessary tables exist.
        """
        self.db_path = db_path
        self.allow_username_login = allow_username_login
        self.conn = None
        self._ensure_connection()
        self._create_user_table()  # Ensure the users table exists
        self._create_user_indexes()  # Ensure supporting indexes exist
        self._create_session_table()  # Ensure the sessions table exists
        self._create_reset_codes_table()  # Ensure the reset codes table exists
        self._create_profiles_table()  # Ensure the profiles table exists
        self._create_recovery_codes_table()  # Ensure 2FA recovery codes table exists
        self._create_currency_ledger_table()  # Ensure ledger exists

    def _ensure_connection(self) -> None:
        """
        Ensure database connection is active. Reconnect if needed.

        CRITICAL: Enables foreign key constraints for data integrity.
        SQLite disables FK enforcement by default for backwards compatibility.
        This MUST be executed on EVERY connection to prevent orphaned records.
        """
        if self.conn is None:
            # Keep SQLite's default thread-safety check enabled. If a connection
            # must be used across threads, fix the calling pattern instead
            # (e.g. per-session/per-request connections or explicit locking).
            self.conn = sqlite3.connect(self.db_path)
            # Enable foreign key constraint enforcement
            # Without this, FK declarations in schema are completely ignored
            self.conn.execute("PRAGMA foreign_keys = ON")
            
    def _get_cursor(self):
        """
        Get a database cursor, ensuring connection is active.
        """
        self._ensure_connection()
        return self.conn.cursor()
        
    def close(self) -> None:
        """
        Close the database connection.
        """
        if not self.conn:
            return

        self.conn.close()
        self.conn = None
            
    def __del__(self) -> None:
        """
        Cleanup method to ensure connection is closed when object is destroyed.
        """
        self.close()
        
    def __enter__(self):
        """
        Context manager entry.
        """
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit - close connection.
        """
        self.close()

    def _create_user_table(self) -> None:
        """
        Create the 'users' table in the database if it does not exist.

        The table stores user information including the primary email identifier,
        optional username, authentication metadata, and password storage where
        applicable. Columns are intentionally flexible so future identity
        providers (Google, Microsoft, anonymous handles) can be supported
        without schema rewrites.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                username TEXT,
                created_at REAL NOT NULL,
                password_hash BLOB,
                password_salt BLOB,
                auth_provider TEXT NOT NULL DEFAULT 'password',
                auth_provider_id TEXT,
                role TEXT NOT NULL,
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                two_factor_secret TEXT,
                referral_code TEXT DEFAULT '',
                email_notifications_enabled BOOLEAN NOT NULL DEFAULT 1,
                sms_notifications_enabled BOOLEAN NOT NULL DEFAULT 0,
                primary_currency_balance INTEGER NOT NULL DEFAULT 0,
                primary_currency_updated_at REAL NOT NULL DEFAULT 0
            )
        """
        )
        self.conn.commit()

    def _create_user_indexes(self) -> None:
        """Ensure supporting indexes exist for common lookups."""
        cursor = self._get_cursor()
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)"
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE username IS NOT NULL"
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider ON users(auth_provider, auth_provider_id) WHERE auth_provider_id IS NOT NULL"
        )
        self.conn.commit()

    def _create_currency_ledger_table(self) -> None:
        """Ensure the currency ledger table exists."""
        cursor = self._get_cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_currency_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                delta INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                reason TEXT,
                metadata TEXT,
                actor_user_id TEXT,
                created_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_currency_ledger_user_id_created
            ON user_currency_ledger(user_id, created_at DESC)
            """
        )
        self.conn.commit()

    def _append_currency_ledger_entry(
        self,
        *,
        user_id: uuid.UUID,
        delta: int,
        balance_after: int,
        reason: str | None,
        metadata: dict[str, t.Any] | None,
        actor_user_id: uuid.UUID | None,
        created_at: float | None = None,
        commit: bool = False,
    ) -> CurrencyLedgerEntry:
        """
        Internal helper to insert a row into the currency ledger table.
        """
        cursor = self._get_cursor()
        timestamp = created_at or datetime.now(timezone.utc).timestamp()
        metadata_json = json.dumps(metadata) if metadata is not None else None
        cursor.execute(
            """
            INSERT INTO user_currency_ledger (
                user_id,
                delta,
                balance_after,
                reason,
                metadata,
                actor_user_id,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(user_id),
                int(delta),
                int(balance_after),
                reason,
                metadata_json,
                str(actor_user_id) if actor_user_id else None,
                timestamp,
            ),
        )
        entry_id = cursor.lastrowid
        if commit:
            self.conn.commit()

        return CurrencyLedgerEntry(
            id=entry_id,
            user_id=user_id,
            delta=int(delta),
            balance_after=int(balance_after),
            reason=reason,
            metadata=metadata,
            actor_user_id=actor_user_id,
            created_at=datetime.fromtimestamp(timestamp, tz=timezone.utc),
        )

    def _create_session_table(self) -> None:
        """
        Create the 'user_sessions' table in the database if it does not exist.
        The table stores session information including session id, user id, and
        timestamps.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                valid_until REAL NOT NULL,
                role TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )
        self.conn.commit()

    def _create_reset_codes_table(self) -> None:
        """
        Create the 'password_reset_codes' table in the database if it does not exist.
        The table stores reset codes that allow users to reset their passwords.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_codes (
                code TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                valid_until REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )
        self.conn.commit()

    def _create_profiles_table(self) -> None:
        """
        Create the 'profiles' table in the database if it does not exist.
        The table stores user profile information.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                full_name TEXT,
                email TEXT UNIQUE,
                phone TEXT,
                address TEXT,
                bio TEXT,
                avatar_url TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
        self.conn.commit()

    def _create_recovery_codes_table(self) -> None:
        """
        Create the 'two_factor_recovery_codes' table to store hashed backup codes.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS two_factor_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                code_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at REAL NOT NULL,
                used_at REAL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id
            ON two_factor_recovery_codes(user_id)
            """
        )
        self.conn.commit()

    @staticmethod
    def _generate_recovery_code() -> str:
        """
        Generate a human-friendly recovery code in the format XXXX-XXXX-XXXX.
        """
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        raw = "".join(secrets.choice(alphabet) for _ in range(12))
        return "-".join(raw[i : i + 4] for i in range(0, 12, 4))

    @staticmethod
    def _normalize_recovery_code(code: str | None) -> str:
        """
        Normalize a recovery code for hashing/verification.
        """
        if not code:
            return ""
        return "".join(part.strip() for part in code.upper().split("-"))

    @staticmethod
    def _hash_recovery_code(code: str, salt: bytes) -> bytes:
        """
        Hash a recovery code using PBKDF2 to avoid storing it in plaintext.
        """
        return hashlib.pbkdf2_hmac(
            "sha256",
            code.encode("utf-8"),
            salt,
            100_000,
        )

    def generate_recovery_codes(
        self,
        user_id: uuid.UUID,
        count: int = 10,
    ) -> list[str]:
        """
        Generate a fresh set of recovery codes for a user, replacing any existing codes.
        """
        normalized_user_id = str(user_id)
        cursor = self._get_cursor()
        new_codes: list[str] = []

        try:
            self.conn.execute("BEGIN IMMEDIATE")

            # Clear existing codes within the same transaction to keep operations atomic.
            self.invalidate_recovery_codes(user_id, commit=False)

            for _ in range(count):
                code = self._generate_recovery_code()
                normalized_code = self._normalize_recovery_code(code)
                salt = secrets.token_bytes(32)
                code_hash = self._hash_recovery_code(normalized_code, salt)

                cursor.execute(
                    """
                    INSERT INTO two_factor_recovery_codes (
                        user_id, code_hash, salt, created_at, used_at
                    ) VALUES (?, ?, ?, ?, NULL)
                    """,
                    (
                        normalized_user_id,
                        code_hash,
                        salt,
                        datetime.now(timezone.utc).timestamp(),
                    ),
                )
                new_codes.append(code)

            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        # TODO: Send notification email once email infrastructure supports recovery code events.
        return new_codes

    def invalidate_recovery_codes(self, user_id: uuid.UUID, *, commit: bool = True) -> None:
        """Remove all recovery codes for a user."""
        cursor = self._get_cursor()
        cursor.execute(
            "DELETE FROM two_factor_recovery_codes WHERE user_id = ?",
            (str(user_id),),
        )
        if commit:
            self.conn.commit()

    def consume_recovery_code(self, user_id: uuid.UUID, code: str) -> bool:
        """
        Attempt to consume a recovery code. Returns True if a valid unused code was supplied.
        Uses atomic check-and-set to prevent race conditions under concurrent load.
        """
        normalized_code = self._normalize_recovery_code(code)
        if not normalized_code:
            return False

        cursor = self._get_cursor()

        # Begin immediate transaction to acquire exclusive lock and prevent race conditions
        self.conn.execute("BEGIN IMMEDIATE")

        try:
            # Only fetch unused codes
            cursor.execute(
                """
                SELECT id, code_hash, salt
                FROM two_factor_recovery_codes
                WHERE user_id = ? AND used_at IS NULL
                """,
                (str(user_id),),
            )

            rows = cursor.fetchall()
            for code_id, stored_hash, salt in rows:
                candidate_hash = self._hash_recovery_code(normalized_code, salt)
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
                        self.conn.commit()
                        # TODO: Send notification email once email infrastructure supports recovery code events.
                        return True
                    else:
                        # Another request consumed this code between our SELECT and UPDATE
                        self.conn.rollback()
                        return False

            self.conn.rollback()
            return False

        except Exception:
            self.conn.rollback()
            raise

    def get_recovery_codes_metadata(self, user_id: uuid.UUID) -> list[RecoveryCodeRecord]:
        """
        Retrieve metadata for all recovery codes belonging to a user.
        """
        cursor = self._get_cursor()
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
        self,
        user_id: uuid.UUID,
    ) -> dict[str, t.Any]:
        """
        Provide aggregate information about a user's recovery codes.
        """
        metadata = self.get_recovery_codes_metadata(user_id)
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

    async def create_user(self, user: AppUser) -> None:
        """
        Add a new user to the database.

        ## Parameters

        `user`: The user object containing user details.

        ## Raises

        `HTTPException`: If email validation is enabled and the email format is invalid.
        """
        # BACKEND VALIDATION: Enforce email validation if configured
        # This provides defense-in-depth even if frontend validation is bypassed
        if config.REQUIRE_VALID_EMAIL:
            SecuritySanitizer.validate_email_format(user.email, require_valid=True)

        cursor = self._get_cursor()

        # Check if this is the first user
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        # If this is the first user, set their role to the highest privilege role
        if user_count == 0:
            user.role = get_first_user_role()

        # Validate that the role is valid
        if not validate_role(user.role):
            raise ValueError(f"Invalid role: {user.role}. Must be one of: {', '.join(get_all_roles())}")

        now_ts = datetime.now(timezone.utc).timestamp()

        cursor.execute(
            """
            INSERT INTO users (
                id,
                email,
                username,
                created_at,
                password_hash,
                password_salt,
                auth_provider,
                auth_provider_id,
                role,
                is_verified,
                two_factor_secret,
                referral_code,
                email_notifications_enabled,
                sms_notifications_enabled,
                primary_currency_balance,
                primary_currency_updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(user.id),
                user.email,
                user.username,
                user.created_at.timestamp(),
                user.password_hash,
                user.password_salt,
                user.auth_provider,
                user.auth_provider_id,
                user.role,
                user.is_verified,
                user.two_factor_secret,
                user.referral_code,
                user.email_notifications_enabled,
                user.sms_notifications_enabled,
                user.primary_currency_balance,
                now_ts,
            ),
        )

        # Create a default profile for the new user
        now = now_ts
        cursor.execute(
            """
            INSERT INTO profiles 
            (user_id, full_name, email, phone, address, bio, avatar_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(user.id),
                user.username or "",
                user.email,
                None,
                None,
                None,
                None,
                now,
                now,
            )
        )

        if user.primary_currency_balance:
            self._append_currency_ledger_entry(
                user_id=user.id,
                delta=user.primary_currency_balance,
                balance_after=user.primary_currency_balance,
                reason="Initial balance",
                metadata=None,
                actor_user_id=None,
                created_at=now_ts,
                commit=False,
            )
        self.conn.commit()

    def _row_to_app_user(self, row: tuple) -> AppUser:
        """Convert a database row into an AppUser instance."""
        cfg = get_currency_config()
        updated_at_ts = row[15] if len(row) > 15 else None
        updated_at = (
            datetime.fromtimestamp(updated_at_ts, tz=timezone.utc)
            if updated_at_ts
            else datetime.now(timezone.utc)
        )
        return AppUser(
            id=uuid.UUID(row[0]),
            email=row[1],
            username=row[2],
            created_at=datetime.fromtimestamp(row[3], tz=timezone.utc),
            password_hash=row[4],
            password_salt=row[5],
            auth_provider=row[6],
            auth_provider_id=row[7],
            role=row[8],
            is_verified=bool(row[9]),
            two_factor_secret=row[10],
            referral_code=row[11],
            email_notifications_enabled=bool(row[12]) if len(row) > 12 else True,
            sms_notifications_enabled=bool(row[13]) if len(row) > 13 else False,
            primary_currency_balance=int(row[14]) if len(row) > 14 and row[14] is not None else cfg.initial_balance,
            primary_currency_updated_at=updated_at,
        )

    def _row_to_currency_ledger_entry(self, row: tuple) -> CurrencyLedgerEntry:
        """Convert a ledger row tuple into a dataclass instance."""
        metadata_json = row[5]
        metadata = json.loads(metadata_json) if metadata_json else None
        actor_id = uuid.UUID(row[6]) if row[6] else None
        return CurrencyLedgerEntry(
            id=row[0],
            user_id=uuid.UUID(row[1]),
            delta=int(row[2]),
            balance_after=int(row[3]),
            reason=row[4],
            metadata=metadata,
            actor_user_id=actor_id,
            created_at=datetime.fromtimestamp(row[7], tz=timezone.utc),
        )

    async def get_user_by_email(self, email: str) -> AppUser:
        """Retrieve a user from the database by email address."""
        cursor = self._get_cursor()
        cursor.execute(
            f"""
            SELECT {self.USER_SELECT_COLUMNS}
            FROM users
            WHERE lower(email) = lower(?)
            LIMIT 1
            """,
            (email,),
        )

        row = cursor.fetchone()

        if row:
            return self._row_to_app_user(row)

        raise KeyError(email)

    async def get_user_by_username(
        self,
        username: str,
    ) -> AppUser:
        """
        Retrieve a user from the database by username.


        ## Parameters

        `username`: The username of the user to retrieve.


        ## Raises

        `KeyError`: If there is no user with the specified username.
        """
        cursor = self._get_cursor()
        cursor.execute(
            f"""
            SELECT {self.USER_SELECT_COLUMNS}
            FROM users
            WHERE username = ?
            LIMIT 1
            """,
            (username,),
        )

        row = cursor.fetchone()

        if row:
            return self._row_to_app_user(row)

        raise KeyError(username)

    async def get_user_by_identity(self, identifier: str) -> AppUser:
        """
        Retrieve a user by primary identifier (email) with username fallback.

        This keeps email as the default login value while still supporting
        optional username-based flows for niche apps.
        """
        try:
            return await self.get_user_by_email(identifier)
        except KeyError:
            if not self.allow_username_login:
                raise
            return await self.get_user_by_username(identifier)

    async def get_user_by_id(
        self,
        id: uuid.UUID,
    ) -> AppUser:
        """
        Retrieve a user from the database by user ID.


        ## Parameters

        `id`: The UUID of the user to retrieve.


        ## Raises

        `KeyError`: If there is no user with the specified ID.
        """
        cursor = self._get_cursor()

        cursor.execute(
            f"""
            SELECT {self.USER_SELECT_COLUMNS}
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (str(id),),
        )

        row = cursor.fetchone()

        if row:
            return self._row_to_app_user(row)

        raise KeyError(id)

    async def list_users(self) -> list[AppUser]:
        """
        Retrieve all users from the database.

        Returns:
            list[AppUser]: List of users ordered by creation time.
        """
        cursor = self._get_cursor()
        cursor.execute(
            f"""
            SELECT {self.USER_SELECT_COLUMNS}
            FROM users
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()
        return [self._row_to_app_user(row) for row in rows]

    async def get_currency_balance(self, user_id: uuid.UUID) -> int:
        """Return the raw minor-unit balance for a user."""
        overview = await self.get_currency_overview(user_id)
        return overview["balance_minor"]

    async def get_currency_overview(self, user_id: uuid.UUID) -> dict[str, t.Any]:
        """Retrieve balance, formatted string, and last update timestamp for a user."""
        cursor = self._get_cursor()
        cursor.execute(
            """
            SELECT primary_currency_balance, primary_currency_updated_at
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (str(user_id),),
        )
        row = cursor.fetchone()
        if not row:
            raise KeyError(user_id)

        balance_minor = int(row[0]) if row[0] is not None else 0
        updated_at_ts = row[1] or 0
        updated_at = (
            datetime.fromtimestamp(updated_at_ts, tz=timezone.utc)
            if updated_at_ts
            else None
        )

        formatted = format_minor_amount(balance_minor)
        cfg = get_currency_config()

        return {
            "balance_minor": balance_minor,
            "balance_major": float(get_major_amount(balance_minor)),
            "formatted": formatted,
            "label": cfg.display_name(get_major_amount(balance_minor)),
            "updated_at": updated_at,
        }

    async def adjust_currency_balance(
        self,
        user_id: uuid.UUID,
        delta_minor: int,
        *,
        reason: str | None = None,
        metadata: dict[str, t.Any] | None = None,
        actor_user_id: uuid.UUID | None = None,
    ) -> CurrencyLedgerEntry:
        """
        Increment a user's balance by the specified delta and record a ledger entry.
        """
        cfg = get_currency_config()
        cursor = self._get_cursor()

        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a mapping if provided")

        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "SELECT primary_currency_balance FROM users WHERE id = ?",
                (str(user_id),),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyError(user_id)

            current_balance = int(row[0] or 0)
            new_balance = current_balance + int(delta_minor)

            if not cfg.allow_negative and new_balance < 0:
                raise ValueError("Currency balance cannot be negative")

            timestamp = datetime.now(timezone.utc).timestamp()
            cursor.execute(
                """
                UPDATE users
                SET primary_currency_balance = ?, primary_currency_updated_at = ?
                WHERE id = ?
                """,
                (new_balance, timestamp, str(user_id)),
            )

            ledger_entry = self._append_currency_ledger_entry(
                user_id=user_id,
                delta=int(delta_minor),
                balance_after=new_balance,
                reason=reason,
                metadata=metadata,
                actor_user_id=actor_user_id,
                created_at=timestamp,
            )

            self.conn.commit()
            return ledger_entry
        except Exception:
            self.conn.rollback()
            raise

    async def set_currency_balance(
        self,
        user_id: uuid.UUID,
        new_balance_minor: int,
        *,
        reason: str | None = None,
        metadata: dict[str, t.Any] | None = None,
        actor_user_id: uuid.UUID | None = None,
    ) -> CurrencyLedgerEntry:
        """Set a user's balance to the provided amount and record ledger delta."""
        cfg = get_currency_config()
        if not cfg.allow_negative and new_balance_minor < 0:
            raise ValueError("Currency balance cannot be negative")

        cursor = self._get_cursor()

        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "SELECT primary_currency_balance FROM users WHERE id = ?",
                (str(user_id),),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyError(user_id)

            current_balance = int(row[0] or 0)
            delta = int(new_balance_minor) - current_balance

            timestamp = datetime.now(timezone.utc).timestamp()
            cursor.execute(
                """
                UPDATE users
                SET primary_currency_balance = ?, primary_currency_updated_at = ?
                WHERE id = ?
                """,
                (int(new_balance_minor), timestamp, str(user_id)),
            )

            ledger_entry = self._append_currency_ledger_entry(
                user_id=user_id,
                delta=delta,
                balance_after=int(new_balance_minor),
                reason=reason,
                metadata=metadata,
                actor_user_id=actor_user_id,
                created_at=timestamp,
            )

            self.conn.commit()
            return ledger_entry
        except Exception:
            self.conn.rollback()
            raise

    async def list_currency_ledger(
        self,
        user_id: uuid.UUID,
        *,
        limit: int = 50,
        before: datetime | None = None,
        after: datetime | None = None,
    ) -> list[CurrencyLedgerEntry]:
        """Retrieve ledger entries for a user ordered by most recent first."""
        cursor = self._get_cursor()

        clauses = ["user_id = ?"]
        params: list[t.Any] = [str(user_id)]

        if before is not None:
            clauses.append("created_at < ?")
            params.append(before.timestamp())

        if after is not None:
            clauses.append("created_at > ?")
            params.append(after.timestamp())

        query = """
            SELECT id, user_id, delta, balance_after, reason, metadata, actor_user_id, created_at
            FROM user_currency_ledger
            WHERE {conditions}
            ORDER BY created_at DESC, id DESC
            LIMIT ?
        """.format(conditions=" AND ".join(clauses))

        params.append(max(1, min(limit, 500)))

        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [self._row_to_currency_ledger_entry(row) for row in rows]

    async def get_user_by_email_or_username(self, identifier: str) -> AppUser:
        """
        Retrieve a user by email or username regardless of login feature flags.

        Args:
            identifier: Email or username to look up.

        Raises:
            KeyError: If no matching user is found.
        """
        sanitized_identifier = identifier.strip()
        if not sanitized_identifier:
            raise KeyError(identifier)

        cursor = self._get_cursor()
        cursor.execute(
            f"""
            SELECT {self.USER_SELECT_COLUMNS}
            FROM users
            WHERE lower(email) = lower(?)
            LIMIT 1
            """,
            (sanitized_identifier,),
        )

        row = cursor.fetchone()
        if row:
            return self._row_to_app_user(row)

        cursor.execute(
            f"""
            SELECT {self.USER_SELECT_COLUMNS}
            FROM users
            WHERE username = ?
            LIMIT 1
            """,
            (sanitized_identifier,),
        )

        row = cursor.fetchone()
        if row:
            return self._row_to_app_user(row)

        raise KeyError(identifier)

    async def update_user_role(self, user_id: uuid.UUID, new_role: str) -> None:
        """
        Update a user's role and keep active sessions in sync.

        Args:
            user_id: The user to update.
            new_role: The new role value.

        Raises:
            KeyError: If the user does not exist.
            ValueError: If the role is not valid.
        """
        # Validate the new role
        if not validate_role(new_role):
            raise ValueError(f"Invalid role: {new_role}. Must be one of: {', '.join(get_all_roles())}")

        cursor = self._get_cursor()

        # Ensure the user exists before updating.
        await self.get_user_by_id(user_id)

        cursor.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (new_role, str(user_id)),
        )

        if cursor.rowcount == 0:
            raise KeyError(user_id)

        cursor.execute(
            "UPDATE user_sessions SET role = ? WHERE user_id = ?",
            (new_role, str(user_id)),
        )

        self.conn.commit()

    async def create_session(
        self,
        user_id: uuid.UUID,
    ) -> UserSession:
        """
        Create a new user session and store it in the database.

        ## Parameters

        `user_id`: The UUID of the user for whom to create the session.
        """
        now = datetime.now(tz=timezone.utc)

        user = await self.get_user_by_id(user_id)
        
        session = UserSession(
            id=secrets.token_urlsafe(),
            user_id=user_id,
            created_at=now,
            valid_until=now + timedelta(days=1),
            role=user.role
        )

        cursor = self._get_cursor()
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
        self.conn.commit()

        return session

    async def update_session_duration(
        self,
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
        session.valid_until = new_valid_until

        cursor = self._get_cursor()

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
        self.conn.commit()

    async def get_session_by_auth_token(
        self,
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
        cursor = self._get_cursor()

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


    def _get_two_factor_secret(self, user_id: uuid.UUID) -> str | None:
        cursor = self._get_cursor()
        cursor.execute("SELECT two_factor_secret FROM users WHERE id = ?", (str(user_id),))
        row = cursor.fetchone()
        if not row:
            return None
        return t.cast(str | None, row[0])

    def verify_two_factor_challenge(
        self,
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
        secret = self._get_two_factor_secret(user_id)
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

        if consume_recovery_code and self.consume_recovery_code(user_id, sanitized_code):
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

    def is_2fa_enabled(self, user_id: uuid.UUID) -> bool:
        """Check if 2FA is enabled for a user."""
        cursor = self._get_cursor()
        cursor.execute("SELECT two_factor_secret FROM users WHERE id = ?", (str(user_id),))
        result = cursor.fetchone()
        return bool(result and result[0])

    def set_2fa_secret(self, user_id: uuid.UUID, secret: str | None) -> None:
        """Enable or Disable 2FA for a user.
        Set to str if enabling, or to None if disabling
        """
        if secret is not None:
            secret = secret.strip() or None
        cursor = self._get_cursor()
        cursor.execute(
            "UPDATE users SET two_factor_secret = ? WHERE id = ?",
            (secret, str(user_id)),
        )
        self.conn.commit()
        if secret is None:
            self.invalidate_recovery_codes(user_id)

    async def invalidate_all_sessions(
        self,
        user_id: uuid.UUID,
    ) -> None:
        """
        Invalidate all sessions for a given user by setting their valid_until
        timestamp to the current time.

        ## Parameters

        `user_id`: The UUID of the user whose sessions to invalidate.
        """
        cursor = self._get_cursor()
        now = datetime.now(timezone.utc).timestamp()

        cursor.execute(
            "UPDATE user_sessions SET valid_until = ? WHERE user_id = ?",
            (now, str(user_id)),
        )
        self.conn.commit()

    async def update_password(
        self,
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
        cursor = self._get_cursor()
        
        # First verify the user exists
        await self.get_user_by_id(user_id)  # Will raise KeyError if user doesn't exist
        
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
            (password_hash, password_salt, str(user_id))
        )
        self.conn.commit()
        
        # Invalidate all existing sessions for security
        await self.invalidate_all_sessions(user_id)

    async def update_notification_preferences(
        self,
        user_id: uuid.UUID,
        email_notifications_enabled: bool | None = None,
        sms_notifications_enabled: bool | None = None,
    ) -> None:
        """
        Update a user's notification preferences.

        ## Parameters

        `user_id`: The UUID of the user whose preferences to update
        `email_notifications_enabled`: Whether email notifications should be enabled
        `sms_notifications_enabled`: Whether SMS notifications should be enabled

        ## Raises

        `KeyError`: If the user does not exist
        """
        cursor = self._get_cursor()

        # First verify the user exists
        await self.get_user_by_id(user_id)  # Will raise KeyError if user doesn't exist

        # Build the update query dynamically based on provided fields
        update_fields = []
        params = []

        if email_notifications_enabled is not None:
            update_fields.append("email_notifications_enabled = ?")
            params.append(email_notifications_enabled)

        if sms_notifications_enabled is not None:
            update_fields.append("sms_notifications_enabled = ?")
            params.append(sms_notifications_enabled)

        if not update_fields:
            return  # Nothing to update

        # Add user_id to params
        params.append(str(user_id))

        query = f"""
            UPDATE users
            SET {', '.join(update_fields)}
            WHERE id = ?
        """

        cursor.execute(query, params)
        self.conn.commit()

    async def create_reset_code(self, user_id: uuid.UUID) -> PasswordResetCode:
        """
        Create a new password reset code for a user.
        
        ## Parameters
        
        `user_id`: The UUID of the user to create a reset code for
        
        ## Returns
        
        The newly created reset code
        
        ## Raises
        
        `KeyError`: If the user does not exist
        """
        # First verify the user exists
        await self.get_user_by_id(user_id)

        # Remove any existing codes for this user to enforce single-use semantics
        await self.clear_reset_code(user_id)

        cursor = self._get_cursor()
        attempts = 0

        while attempts < 5:
            attempts += 1
            reset_code = PasswordResetCode.create_new_reset_code(user_id)

            try:
                cursor.execute(
                    """
                    INSERT INTO password_reset_codes (code, user_id, created_at, valid_until)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        reset_code.code,
                        str(reset_code.user_id),
                        reset_code.created_at.timestamp(),
                        reset_code.valid_until.timestamp(),
                    ),
                )
                self.conn.commit()
                return reset_code
            except sqlite3.IntegrityError:
                self.conn.rollback()
                continue
            except Exception:
                self.conn.rollback()
                raise

        raise RuntimeError("Failed to generate a unique password reset code.")

    async def get_user_by_reset_code(self, code: str) -> AppUser:
        """
        Find a user by their reset code. The code must be valid (not expired).
        
        ## Parameters
        
        `code`: The reset code to look up
        
        ## Returns
        
        The user associated with this reset code
        
        ## Raises
        
        `KeyError`: If the code is invalid, expired, or the associated user doesn't exist
        """
        cursor = self._get_cursor()
        
        # Get the reset code entry
        cursor.execute(
            """
            SELECT user_id, valid_until 
            FROM password_reset_codes 
            WHERE code = ?
            """,
            (code,)
        )
        
        row = cursor.fetchone()
        if not row:
            raise KeyError(f"Invalid reset code: {code}")
            
        # Check if the code is expired
        valid_until = datetime.fromtimestamp(row[1], tz=timezone.utc)
        if datetime.now(timezone.utc) >= valid_until:
            cursor.execute(
                "DELETE FROM password_reset_codes WHERE code = ?",
                (code,),
            )
            self.conn.commit()
            raise KeyError(f"Reset code has expired: {code}")
            
        # Get and return the associated user
        return await self.get_user_by_id(uuid.UUID(row[0]))

    async def consume_reset_code(self, code: str, user_id: uuid.UUID) -> bool:
        """
        Delete a password reset code after successful use.

        Returns True when the code was removed; False when the code was missing.
        """
        cursor = self._get_cursor()

        self.conn.execute("BEGIN IMMEDIATE")

        try:
            cursor.execute(
                """
                DELETE FROM password_reset_codes
                WHERE code = ? AND user_id = ?
                """,
                (code, str(user_id)),
            )

            if cursor.rowcount != 1:
                self.conn.rollback()
                return False

            self.conn.commit()
            return True
        except Exception:
            self.conn.rollback()
            raise

    async def clear_reset_code(self, user_id: uuid.UUID) -> None:
        """
        Delete all reset codes for a user.
        
        ## Parameters
        
        `user_id`: The UUID of the user whose reset codes to clear
        """
        cursor = self._get_cursor()
        cursor.execute(
            "DELETE FROM password_reset_codes WHERE user_id = ?",
            (str(user_id),)
        )
        self.conn.commit()

    async def delete_user(self, user_id: uuid.UUID, password: str, two_factor_code: str | None = None) -> bool:
        """
        Delete a user and all their associated sessions from the database.
        
        ## Parameters
        
        `user_id`: The UUID of the user to delete
        `password`: The password for verification. For admin deletion, must match ADMIN_DELETION_PASSWORD
        `two_factor_code`: Optional 2FA code, required if 2FA is enabled for the user
        
        ## Returns

        `bool`: True if deletion was successful, False if authentication failed
        or the user does not exist
        """
        # First verify the user exists and get their data
        try:
            user = await self.get_user_by_id(user_id)
        except KeyError:
            return False

        # Determine whether the provided password is a valid user password or admin override
        admin_password = config.ADMIN_DELETION_PASSWORD
        admin_override = bool(
            admin_password and secrets.compare_digest(password, admin_password)
        )

        user_password_valid = False
        if user.auth_provider == "password":
            user_password_valid = user.verify_password(password)

        if not (user_password_valid or admin_override):
            return False

        # If the user has 2FA enabled, require a valid code unless using the admin override
        if user.two_factor_enabled and not admin_override:
            result = self.verify_two_factor_challenge(user_id, two_factor_code)
            if not result.ok:
                return False

        cursor = self._get_cursor()

        # First delete all sessions first (due to foreign key constraint)
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = ?",
            (str(user_id),)
        )
        
        # Delete all reset codes for this user
        cursor.execute(
            "DELETE FROM password_reset_codes WHERE user_id = ?",
            (str(user_id),)
        )

        # Delete all recovery codes for this user
        cursor.execute(
            "DELETE FROM two_factor_recovery_codes WHERE user_id = ?",
            (str(user_id),)
        )

        # Delete the user's profile
        cursor.execute(
            "DELETE FROM profiles WHERE user_id = ?",
            (str(user_id),)
        )
        
        # Delete the user
        cursor.execute(
            "DELETE FROM users WHERE id = ?",
            (str(user_id),)
        )
        
        self.conn.commit()
        return True

    # Profile management methods

    def _row_to_profile(self, row: tuple) -> dict[str, t.Any]:
        """Convert a database row into a serializable profile dict."""
        return {
            "id": row[0],
            "user_id": str(row[1]) if row[1] is not None else None,
            "full_name": row[2],
            "email": row[3],
            "phone": row[4],
            "address": row[5],
            "bio": row[6],
            "avatar_url": row[7],
            "created_at": float(row[8]) if row[8] is not None else None,
            "updated_at": float(row[9]) if row[9] is not None else None,
        }

    async def create_profile(self, user_id: str, full_name: str, email: str,
                           phone: str = None, address: str = None,
                           bio: str = None, avatar_url: str = None) -> dict[str, t.Any]:
        """
        Create a new user profile.

        Args:
            user_id: The ID of the user this profile belongs to
            full_name: User's full name
            email: User's email address
            phone: User's phone number (optional)
            address: User's address (optional)
            bio: Short bio/description (optional)
            avatar_url: URL to user's avatar image (optional)

        Returns:
            dict[str, Any]: The created profile data

        Raises:
            sqlite3.IntegrityError: If a profile with the user_id or email already exists
        """
        cursor = self._get_cursor()
        now = datetime.now(timezone.utc).timestamp()

        cursor.execute(
            """
            INSERT INTO profiles
            (user_id, full_name, email, phone, address, bio, avatar_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, full_name, email, phone, address, bio, avatar_url, now, now)
        )
        self.conn.commit()

        return await self.get_profile_by_user_id(user_id)
    
    async def get_profile(self, profile_id: int) -> dict[str, t.Any] | None:
        """
        Retrieve a profile by its ID.

        Args:
            profile_id: The ID of the profile to retrieve

        Returns:
            dict[str, Any] | None: The profile data if found, None otherwise
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            SELECT id, user_id, full_name, email, phone, address, bio, avatar_url,
                   created_at, updated_at
            FROM profiles
            WHERE id = ?
            """,
            (profile_id,)
        )

        row = cursor.fetchone()
        if not row:
            return None

        return self._row_to_profile(row)
    
    async def get_profile_by_user_id(self, user_id: str) -> dict[str, t.Any] | None:
        """
        Retrieve a profile by user ID.

        Args:
            user_id: The ID of the user whose profile to retrieve

        Returns:
            dict[str, Any] | None: The profile data if found, None otherwise
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            SELECT id, user_id, full_name, email, phone, address, bio, avatar_url,
                   created_at, updated_at
            FROM profiles
            WHERE user_id = ?
            """,
            (user_id,)
        )

        row = cursor.fetchone()
        if not row:
            return None

        return self._row_to_profile(row)
    
    async def update_profile(
        self,
        user_id: str,
        full_name: str = None,
        email: str = None,
        phone: str = None,
        address: str = None,
        bio: str = None,
        avatar_url: str = None
    ) -> dict[str, t.Any] | None:
        """
        Update a user's profile.

        Args:
            user_id: The ID of the user whose profile to update
            full_name: New full name (optional)
            email: New email (optional)
            phone: New phone number (optional)
            address: New address (optional)
            bio: New bio (optional)
            avatar_url: New avatar URL (optional)

        Returns:
            dict[str, Any] | None: The updated profile data if found, None otherwise
        """
        cursor = self._get_cursor()
        now = datetime.now(timezone.utc).timestamp()

        # Build the update query dynamically based on provided fields
        update_fields = []
        params = []

        if full_name is not None:
            update_fields.append("full_name = ?")
            params.append(full_name)
        if email is not None:
            update_fields.append("email = ?")
            params.append(email)
        if phone is not None:
            update_fields.append("phone = ?")
            params.append(phone)
        if address is not None:
            update_fields.append("address = ?")
            params.append(address)
        if bio is not None:
            update_fields.append("bio = ?")
            params.append(bio)
        if avatar_url is not None:
            update_fields.append("avatar_url = ?")
            params.append(avatar_url)

        if not update_fields:
            return await self.get_profile_by_user_id(user_id)

        # Add updated_at and user_id to params
        update_fields.append("updated_at = ?")
        params.extend([now, user_id])

        query = f"""
            UPDATE profiles
            SET {', '.join(update_fields)}
            WHERE user_id = ?
        """

        cursor.execute(query, params)
        self.conn.commit()

        if cursor.rowcount == 0:
            return None

        return await self.get_profile_by_user_id(user_id)
    
    async def delete_profile(self, user_id: str) -> bool:
        """
        Delete a user's profile.
        
        Args:
            user_id: The ID of the user whose profile to delete
            
        Returns:
            bool: True if the profile was deleted, False if not found
        """
        cursor = self._get_cursor()
        
        cursor.execute(
            "DELETE FROM profiles WHERE user_id = ?",
            (user_id,)
        )
        self.conn.commit()
        
        return cursor.rowcount > 0
    
    async def get_profiles(self) -> list[dict[str, t.Any]]:
        """
        Retrieve all user profiles.

        Returns:
            list[dict[str, Any]]: List of all profiles
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            SELECT id, user_id, full_name, email, phone, address, bio, avatar_url,
                   created_at, updated_at
            FROM profiles
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()
        return [self._row_to_profile(row) for row in rows]
