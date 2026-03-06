import sqlite3
import typing as t
from datetime import datetime, timezone
from typing import Protocol


class ProfilesPersistence(Protocol):
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...


def _get_connection(persistence: ProfilesPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _row_to_profile(row: tuple) -> dict[str, t.Any]:
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


async def create_profile(
    persistence: ProfilesPersistence,
    user_id: str,
    full_name: str,
    email: str,
    phone: str = None,
    address: str = None,
    bio: str = None,
    avatar_url: str = None,
) -> dict[str, t.Any]:
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
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    now = datetime.now(timezone.utc).timestamp()

    cursor.execute(
        """
        INSERT INTO profiles
        (user_id, full_name, email, phone, address, bio, avatar_url, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, full_name, email, phone, address, bio, avatar_url, now, now),
    )
    conn.commit()

    return await get_profile_by_user_id(persistence, user_id)


async def get_profile(
    persistence: ProfilesPersistence,
    profile_id: int,
) -> dict[str, t.Any] | None:
    """
    Retrieve a profile by its ID.

    Args:
        profile_id: The ID of the profile to retrieve

    Returns:
        dict[str, Any] | None: The profile data if found, None otherwise
    """
    cursor = persistence._get_cursor()

    cursor.execute(
        """
        SELECT id, user_id, full_name, email, phone, address, bio, avatar_url,
               created_at, updated_at
        FROM profiles
        WHERE id = ?
        """,
        (profile_id,),
    )

    row = cursor.fetchone()
    if not row:
        return None

    return _row_to_profile(row)


async def get_profile_by_user_id(
    persistence: ProfilesPersistence,
    user_id: str,
) -> dict[str, t.Any] | None:
    """
    Retrieve a profile by user ID.

    Args:
        user_id: The ID of the user whose profile to retrieve

    Returns:
        dict[str, Any] | None: The profile data if found, None otherwise
    """
    cursor = persistence._get_cursor()

    cursor.execute(
        """
        SELECT id, user_id, full_name, email, phone, address, bio, avatar_url,
               created_at, updated_at
        FROM profiles
        WHERE user_id = ?
        """,
        (user_id,),
    )

    row = cursor.fetchone()
    if not row:
        return None

    return _row_to_profile(row)


async def update_profile(
    persistence: ProfilesPersistence,
    user_id: str,
    full_name: str = None,
    email: str = None,
    phone: str = None,
    address: str = None,
    bio: str = None,
    avatar_url: str = None,
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
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    now = datetime.now(timezone.utc).timestamp()

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
        return await get_profile_by_user_id(persistence, user_id)

    update_fields.append("updated_at = ?")
    params.extend([now, user_id])

    query = f"""
        UPDATE profiles
        SET {', '.join(update_fields)}
        WHERE user_id = ?
    """

    cursor.execute(query, params)
    conn.commit()

    if cursor.rowcount == 0:
        return None

    return await get_profile_by_user_id(persistence, user_id)


async def delete_profile(persistence: ProfilesPersistence, user_id: str) -> bool:
    """
    Delete a user's profile.

    Args:
        user_id: The ID of the user whose profile to delete

    Returns:
        bool: True if the profile was deleted, False if not found
    """
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    cursor.execute(
        "DELETE FROM profiles WHERE user_id = ?",
        (user_id,),
    )
    conn.commit()

    return cursor.rowcount > 0


async def get_profiles(persistence: ProfilesPersistence) -> list[dict[str, t.Any]]:
    """
    Retrieve all user profiles.

    Returns:
        list[dict[str, Any]]: List of all profiles
    """
    cursor = persistence._get_cursor()

    cursor.execute(
        """
        SELECT id, user_id, full_name, email, phone, address, bio, avatar_url,
               created_at, updated_at
        FROM profiles
        ORDER BY created_at DESC
        """
    )

    rows = cursor.fetchall()
    return [_row_to_profile(row) for row in rows]
