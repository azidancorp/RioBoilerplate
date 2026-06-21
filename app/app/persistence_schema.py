import sqlite3
from typing import Protocol


class SchemaPersistence(Protocol):
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...


def initialize_schema(persistence: SchemaPersistence) -> None:
    """Create all required tables and indexes for the application."""
    create_user_table(persistence)
    create_user_indexes(persistence)
    create_session_table(persistence)
    create_password_reset_tokens_table(persistence)
    create_email_verification_tokens_table(persistence)
    create_oauth_login_handoffs_table(persistence)
    create_profiles_table(persistence)
    create_recovery_codes_table(persistence)
    create_currency_ledger_table(persistence)
    create_rate_limit_tables(persistence)
    create_admin_audit_table(persistence)


def _get_connection(persistence: SchemaPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def create_user_table(persistence: SchemaPersistence) -> None:
    """
    Create the 'users' table in the database if it does not exist.

    The table stores user information including the primary email identifier,
    optional username, authentication metadata, and password storage where
    applicable. Columns are intentionally flexible so future identity
    providers (Google, Microsoft, anonymous handles) can be supported
    without schema rewrites.
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            username TEXT,
            created_at REAL NOT NULL,
            password_hash BLOB,
            password_salt BLOB,
            password_scheme TEXT NOT NULL DEFAULT 'pbkdf2_sha256',
            auth_provider TEXT NOT NULL DEFAULT 'password',
            auth_provider_id TEXT,
            role TEXT NOT NULL,
            is_verified BOOLEAN NOT NULL DEFAULT 0,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            two_factor_secret TEXT,
            referral_code TEXT DEFAULT '',
            email_notifications_enabled BOOLEAN NOT NULL DEFAULT 1,
            sms_notifications_enabled BOOLEAN NOT NULL DEFAULT 0,
            primary_currency_balance INTEGER NOT NULL DEFAULT 0,
            primary_currency_updated_at REAL NOT NULL DEFAULT 0
        )
    """
    )
    _ensure_user_password_scheme_column(cursor)
    _ensure_user_is_active_column(cursor)
    conn.commit()


def _ensure_user_password_scheme_column(cursor: sqlite3.Cursor) -> None:
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    if "password_scheme" not in existing_columns:
        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN password_scheme TEXT NOT NULL DEFAULT 'pbkdf2_sha256'
            """
        )


def _ensure_user_is_active_column(cursor: sqlite3.Cursor) -> None:
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    if "is_active" not in existing_columns:
        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1
            """
        )


def create_user_indexes(persistence: SchemaPersistence) -> None:
    """Ensure supporting indexes exist for common lookups."""
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE username IS NOT NULL"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider ON users(auth_provider, auth_provider_id) WHERE auth_provider_id IS NOT NULL"
    )
    conn.commit()


def create_currency_ledger_table(persistence: SchemaPersistence) -> None:
    """Ensure the currency ledger table exists."""
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)
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
    conn.commit()


def create_admin_audit_table(persistence: SchemaPersistence) -> None:
    """Ensure the append-only admin action audit log table exists.

    Unlike the currency ledger, this table intentionally has NO foreign keys to
    ``users``: an audit row is a historical fact that must survive deletion of
    the actor or target it references (otherwise deleting a user would erase the
    record of who deleted them).
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id   TEXT,
            actor_role      TEXT,
            action          TEXT NOT NULL,
            target_user_id  TEXT,
            target_label    TEXT,
            before          TEXT,
            after           TEXT,
            metadata        TEXT,
            client_ip       TEXT,
            outcome         TEXT NOT NULL DEFAULT 'success',
            created_at      REAL NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_audit_actor
        ON admin_audit_log(actor_user_id, created_at DESC)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_audit_target
        ON admin_audit_log(target_user_id, created_at DESC)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_audit_action
        ON admin_audit_log(action, created_at DESC)
        """
    )
    conn.commit()


def create_rate_limit_tables(persistence: SchemaPersistence) -> None:
    """Ensure shared rate-limit enforcement and sparse event tables exist."""
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS rate_limit_buckets (
            scope TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            bucket_start INTEGER NOT NULL,
            bucket_seconds INTEGER NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            first_seen_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            PRIMARY KEY (scope, key_hash, bucket_start, bucket_seconds)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expires
        ON rate_limit_buckets(expires_at)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_scope_key
        ON rate_limit_buckets(scope, key_hash, bucket_start)
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS rate_limit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            decision TEXT NOT NULL,
            count_after INTEGER NOT NULL,
            limit_count INTEGER NOT NULL,
            retry_after_seconds INTEGER,
            metadata TEXT,
            created_at REAL NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rate_limit_events_created
        ON rate_limit_events(created_at)
        """
    )
    conn.commit()


def create_session_table(persistence: SchemaPersistence) -> None:
    """
    Create the 'user_sessions' table in the database if it does not exist.
    The table stores session information including session id, user id, and
    timestamps.
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)

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
    conn.commit()


def create_password_reset_tokens_table(persistence: SchemaPersistence) -> None:
    """
    Create the 'password_reset_tokens' table in the database if it does not exist.
    The table stores hashed reset tokens that allow users to reset passwords.
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            valid_until REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """
    )
    conn.commit()


def create_email_verification_tokens_table(persistence: SchemaPersistence) -> None:
    """
    Create the 'email_verification_tokens' table if it does not exist.
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            valid_until REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id
        ON email_verification_tokens(user_id)
        """
    )
    conn.commit()


def create_oauth_login_handoffs_table(persistence: SchemaPersistence) -> None:
    """
    Create short-lived one-time handoffs from FastAPI OAuth callbacks to Rio.
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_login_handoffs (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            created_at REAL NOT NULL,
            valid_until REAL NOT NULL,
            consumed_at REAL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_oauth_login_handoffs_user_id
        ON oauth_login_handoffs(user_id)
        """
    )
    conn.commit()


def create_profiles_table(persistence: SchemaPersistence) -> None:
    """
    Create the 'profiles' table in the database if it does not exist.
    The table stores user profile information.
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)

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
    conn.commit()


def create_recovery_codes_table(persistence: SchemaPersistence) -> None:
    """
    Create the 'two_factor_recovery_codes' table to store hashed backup codes.
    """
    cursor = persistence._get_cursor()
    conn = _get_connection(persistence)
    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name = 'two_factor_recovery_codes'
        """
    )
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(two_factor_recovery_codes)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        expected_columns = {
            "id",
            "user_id",
            "code_hash",
            "created_at",
            "valid_until",
            "used_at",
        }

        # The boilerplate treats recovery codes as disposable bootstrap data.
        # If an old salt-based table is present, reset it in place so the app
        # always starts with the current clean-slate schema.
        if "salt" in existing_columns or not expected_columns.issubset(existing_columns):
            cursor.execute("DROP TABLE two_factor_recovery_codes")
            conn.commit()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS two_factor_recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at REAL NOT NULL,
            valid_until REAL NOT NULL,
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
    conn.commit()
