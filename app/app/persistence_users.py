import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Protocol

from app.currency import get_currency_config
from app.data_models import AppUser


USER_SELECT_COLUMN_NAMES = (
    "id",
    "email",
    "username",
    "created_at",
    "password_hash",
    "password_salt",
    "password_scheme",
    "auth_provider",
    "auth_provider_id",
    "role",
    "is_verified",
    "is_active",
    "two_factor_secret",
    "referral_code",
    "email_notifications_enabled",
    "sms_notifications_enabled",
    "primary_currency_balance",
    "primary_currency_updated_at",
)
USER_SELECT_COLUMNS = ", ".join(USER_SELECT_COLUMN_NAMES)


def get_user_select_columns(table_alias: str | None = None) -> str:
    if table_alias is None:
        return USER_SELECT_COLUMNS
    return ", ".join(
        f"{table_alias}.{column_name}" for column_name in USER_SELECT_COLUMN_NAMES
    )


class UsersPersistence(Protocol):
    allow_username_login: bool
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...


def _get_connection(persistence: UsersPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _row_to_app_user(row: tuple) -> AppUser:
    """Convert a database row into an AppUser instance."""
    cfg = get_currency_config()
    has_password_scheme = len(row) >= len(USER_SELECT_COLUMN_NAMES)
    password_scheme = row[6] if has_password_scheme else "pbkdf2_sha256"
    auth_provider_index = 7 if has_password_scheme else 6
    updated_at_index = 17 if has_password_scheme else 15
    updated_at_ts = row[updated_at_index] if len(row) > updated_at_index else None
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
        password_scheme=password_scheme,
        auth_provider=row[auth_provider_index],
        auth_provider_id=row[auth_provider_index + 1],
        role=row[auth_provider_index + 2],
        is_verified=bool(row[auth_provider_index + 3]),
        is_active=bool(row[auth_provider_index + 4]),
        two_factor_secret=row[auth_provider_index + 5],
        referral_code=row[auth_provider_index + 6],
        email_notifications_enabled=(
            bool(row[auth_provider_index + 7])
            if len(row) > auth_provider_index + 7
            else True
        ),
        sms_notifications_enabled=(
            bool(row[auth_provider_index + 8])
            if len(row) > auth_provider_index + 8
            else False
        ),
        primary_currency_balance=(
            int(row[auth_provider_index + 9])
            if len(row) > auth_provider_index + 9
            and row[auth_provider_index + 9] is not None
            else cfg.initial_balance
        ),
        primary_currency_updated_at=updated_at,
    )


def get_user_count(persistence: UsersPersistence) -> int:
    """
    Return the total number of registered users.

    This is primarily used during app startup to determine whether the
    instance is still in its bootstrap state.
    """
    cursor = persistence._get_cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    return int(cursor.fetchone()[0])


async def get_user_by_email(
    persistence: UsersPersistence,
    email: str,
) -> AppUser:
    """Retrieve a user from the database by email address."""
    cursor = persistence._get_cursor()
    cursor.execute(
        f"""
        SELECT {USER_SELECT_COLUMNS}
        FROM users
        WHERE lower(email) = lower(?)
        LIMIT 1
        """,
        (email,),
    )

    row = cursor.fetchone()

    if row:
        return _row_to_app_user(row)

    raise KeyError(email)


async def get_user_by_username(
    persistence: UsersPersistence,
    username: str,
) -> AppUser:
    """
    Retrieve a user from the database by username.


    ## Parameters

    `username`: The username of the user to retrieve.


    ## Raises

    `KeyError`: If there is no user with the specified username.
    """
    cursor = persistence._get_cursor()
    cursor.execute(
        f"""
        SELECT {USER_SELECT_COLUMNS}
        FROM users
        WHERE username = ?
        LIMIT 1
        """,
        (username,),
    )

    row = cursor.fetchone()

    if row:
        return _row_to_app_user(row)

    raise KeyError(username)


async def get_user_by_identity(
    persistence: UsersPersistence,
    identifier: str,
) -> AppUser:
    """
    Retrieve a user by primary identifier (email) with username fallback.

    This keeps email as the default login value while still supporting
    optional username-based flows for niche apps.
    """
    try:
        return await get_user_by_email(persistence, identifier)
    except KeyError:
        if not persistence.allow_username_login:
            raise
        return await get_user_by_username(persistence, identifier)


async def get_user_by_id(
    persistence: UsersPersistence,
    id: uuid.UUID,
) -> AppUser:
    """
    Retrieve a user from the database by user ID.


    ## Parameters

    `id`: The UUID of the user to retrieve.


    ## Raises

    `KeyError`: If there is no user with the specified ID.
    """
    cursor = persistence._get_cursor()

    cursor.execute(
        f"""
        SELECT {USER_SELECT_COLUMNS}
        FROM users
        WHERE id = ?
        LIMIT 1
        """,
        (str(id),),
    )

    row = cursor.fetchone()

    if row:
        return _row_to_app_user(row)

    raise KeyError(id)


async def list_users(persistence: UsersPersistence) -> list[AppUser]:
    """
    Retrieve all users from the database.

    Returns:
        list[AppUser]: List of users ordered by creation time.
    """
    cursor = persistence._get_cursor()
    cursor.execute(
        f"""
        SELECT {USER_SELECT_COLUMNS}
        FROM users
        ORDER BY created_at DESC
        """
    )

    rows = cursor.fetchall()
    return [_row_to_app_user(row) for row in rows]


async def get_user_by_email_or_username(
    persistence: UsersPersistence,
    identifier: str,
) -> AppUser:
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

    cursor = persistence._get_cursor()
    cursor.execute(
        f"""
        SELECT {USER_SELECT_COLUMNS}
        FROM users
        WHERE lower(email) = lower(?)
        LIMIT 1
        """,
        (sanitized_identifier,),
    )

    row = cursor.fetchone()
    if row:
        return _row_to_app_user(row)

    cursor.execute(
        f"""
        SELECT {USER_SELECT_COLUMNS}
        FROM users
        WHERE username = ?
        LIMIT 1
        """,
        (sanitized_identifier,),
    )

    row = cursor.fetchone()
    if row:
        return _row_to_app_user(row)

    raise KeyError(identifier)


async def update_notification_preferences(
    persistence: UsersPersistence,
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
    await get_user_by_id(persistence, user_id)

    update_fields = []
    params = []

    if email_notifications_enabled is not None:
        update_fields.append("email_notifications_enabled = ?")
        params.append(email_notifications_enabled)

    if sms_notifications_enabled is not None:
        update_fields.append("sms_notifications_enabled = ?")
        params.append(sms_notifications_enabled)

    if not update_fields:
        return

    params.append(str(user_id))

    cursor = persistence._get_cursor()
    cursor.execute(
        f"""
        UPDATE users
        SET {', '.join(update_fields)}
        WHERE id = ?
        """,
        params,
    )
    _get_connection(persistence).commit()
