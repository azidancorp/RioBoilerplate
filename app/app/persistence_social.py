from __future__ import annotations

import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.config import config
from app.data_models import AppUser
from app.persistence_auth import _hash_one_time_token
from app.persistence_users import USER_SELECT_COLUMNS, _row_to_app_user


class SocialPersistence(Protocol):
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...

    async def get_user_by_id(self, id: uuid.UUID) -> AppUser:
        ...


def _get_connection(persistence: SocialPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _normalize_provider(provider: str) -> str:
    provider = str(provider).strip().lower()
    if provider != "google":
        raise KeyError(provider)
    return provider


async def get_user_by_provider_identity(
    persistence: SocialPersistence,
    provider: str,
    provider_user_id: str,
) -> AppUser:
    provider = _normalize_provider(provider)
    provider_user_id = str(provider_user_id).strip()
    if not provider_user_id:
        raise KeyError(provider_user_id)

    cursor = persistence._get_cursor()
    cursor.execute(
        f"""
        SELECT {USER_SELECT_COLUMNS}
        FROM users
        WHERE auth_provider = ? AND auth_provider_id = ?
        LIMIT 1
        """,
        (provider, provider_user_id),
    )
    row = cursor.fetchone()
    if row is None:
        raise KeyError((provider, provider_user_id))
    return _row_to_app_user(row)


async def create_oauth_handoff(
    persistence: SocialPersistence,
    *,
    user_id: uuid.UUID,
    provider: str,
    ttl_minutes: int | None = None,
) -> str:
    provider = _normalize_provider(provider)
    user = await persistence.get_user_by_id(user_id)
    if not user.is_active:
        raise ValueError("Cannot create an OAuth handoff for an inactive user.")

    now = datetime.now(timezone.utc)
    ttl = ttl_minutes or config.OAUTH_HANDOFF_TTL_MINUTES
    valid_until = now + timedelta(minutes=ttl)
    token = secrets.token_hex(32).upper()
    token_hash = _hash_one_time_token(token)

    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    cursor.execute(
        """
        INSERT INTO oauth_login_handoffs (
            token_hash, user_id, provider, created_at, valid_until, consumed_at
        )
        VALUES (?, ?, ?, ?, ?, NULL)
        """,
        (
            token_hash,
            str(user_id),
            provider,
            now.timestamp(),
            valid_until.timestamp(),
        ),
    )
    conn.commit()
    return token


async def consume_oauth_handoff(
    persistence: SocialPersistence,
    token: str,
) -> AppUser:
    token_hash = _hash_one_time_token(token)
    now = datetime.now(timezone.utc)
    now_ts = now.timestamp()
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor.execute(
            """
            SELECT user_id, valid_until, consumed_at
            FROM oauth_login_handoffs
            WHERE token_hash = ?
            LIMIT 1
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        if row is None:
            conn.rollback()
            raise KeyError("Invalid OAuth handoff token.")

        user_id_str, valid_until_ts, consumed_at = row
        if consumed_at is not None or datetime.fromtimestamp(valid_until_ts, tz=timezone.utc) <= now:
            cursor.execute(
                "DELETE FROM oauth_login_handoffs WHERE token_hash = ?",
                (token_hash,),
            )
            conn.commit()
            raise KeyError("OAuth handoff token has expired or was already used.")

        cursor.execute(
            "SELECT is_active FROM users WHERE id = ?",
            (user_id_str,),
        )
        user_row = cursor.fetchone()
        if user_row is None or not bool(user_row[0]):
            cursor.execute(
                "DELETE FROM oauth_login_handoffs WHERE token_hash = ?",
                (token_hash,),
            )
            conn.commit()
            raise KeyError("OAuth handoff belongs to an inactive or missing user.")

        cursor.execute(
            """
            UPDATE oauth_login_handoffs
            SET consumed_at = ?
            WHERE token_hash = ? AND consumed_at IS NULL
            """,
            (now_ts, token_hash),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            raise KeyError("OAuth handoff token was already used.")

        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return await persistence.get_user_by_id(uuid.UUID(user_id_str))
