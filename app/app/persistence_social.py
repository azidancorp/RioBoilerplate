from __future__ import annotations

import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.config import config
from app.data_models import AppUser, UserSession
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

    def get_valid_session_by_auth_token(
        self,
        auth_token: str,
    ) -> tuple[UserSession, AppUser]:
        ...


OAUTH_DELETE_CHALLENGE_PREFIX = "DELETE-START-"
OAUTH_DELETE_APPROVAL_PREFIX = "DELETE-APPROVE-"
_OAUTH_DELETE_PROVIDER_MARKER = ":delete-account:"


def _get_connection(persistence: SocialPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _require_top_level_transaction(
    conn: sqlite3.Connection,
    *,
    operation: str,
) -> None:
    if conn.in_transaction:
        raise RuntimeError(
            f"{operation} cannot run inside an existing transaction."
        )


def _normalize_provider(provider: str) -> str:
    provider = str(provider).strip().lower()
    if provider != "google":
        raise KeyError(provider)
    return provider


def _new_handoff_token(*, prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(32).upper()}"


def _oauth_deletion_provider_value(provider: str, auth_token: str) -> str:
    return (
        f"{provider}{_OAUTH_DELETE_PROVIDER_MARKER}"
        f"{_hash_one_time_token(auth_token)}"
    )


def _oauth_deletion_session_hash(stored_provider: str, provider: str) -> str:
    prefix = f"{provider}{_OAUTH_DELETE_PROVIDER_MARKER}"
    if not stored_provider.startswith(prefix):
        raise KeyError("OAuth handoff has the wrong purpose.")
    session_hash = stored_provider[len(prefix):]
    if not session_hash:
        raise KeyError("OAuth handoff is not bound to a session.")
    return session_hash


def _absolute_session_expired(*, created_at: datetime, now: datetime) -> bool:
    return bool(
        config.SESSION_ABSOLUTE_MAX_DAYS > 0
        and created_at + timedelta(days=config.SESSION_ABSOLUTE_MAX_DAYS) <= now
    )


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
    now = datetime.now(timezone.utc)
    ttl = (
        config.OAUTH_HANDOFF_TTL_MINUTES
        if ttl_minutes is None
        else ttl_minutes
    )
    if ttl <= 0:
        raise ValueError("OAuth handoff lifetime must be positive.")
    valid_until = now + timedelta(minutes=ttl)
    token = _new_handoff_token()
    token_hash = _hash_one_time_token(token)

    conn = _get_connection(persistence)
    _require_top_level_transaction(conn, operation="OAuth handoff creation")
    cursor = persistence._get_cursor()
    try:
        # The writer lock establishes ordering against account deactivation.
        # Re-read account state only after the lock is owned, then insert
        # without yielding the transaction to another coroutine.
        conn.execute("BEGIN IMMEDIATE")
        cursor.execute(
            """
            DELETE FROM oauth_login_handoffs
            WHERE valid_until <= ? OR consumed_at IS NOT NULL
            """,
            (now.timestamp(),),
        )
        cursor.execute(
            "SELECT is_active FROM users WHERE id = ?",
            (str(user_id),),
        )
        user_row = cursor.fetchone()
        if user_row is None:
            raise KeyError(user_id)
        if not bool(user_row[0]):
            raise ValueError("Cannot create an OAuth handoff for an inactive user.")

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
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    return token


async def create_oauth_account_deletion_challenge(
    persistence: SocialPersistence,
    *,
    user_id: uuid.UUID,
    provider: str,
    auth_token: str,
    ttl_minutes: int | None = None,
) -> str:
    """Create a one-time, session-bound challenge before provider reauth."""
    provider = _normalize_provider(provider)
    if not auth_token:
        raise KeyError("A live session is required.")

    now = datetime.now(timezone.utc)
    ttl = (
        config.OAUTH_HANDOFF_TTL_MINUTES
        if ttl_minutes is None
        else ttl_minutes
    )
    if ttl <= 0:
        raise ValueError("OAuth handoff lifetime must be positive.")

    token = _new_handoff_token(prefix=OAUTH_DELETE_CHALLENGE_PREFIX)
    stored_provider = _oauth_deletion_provider_value(provider, auth_token)
    conn = _get_connection(persistence)
    _require_top_level_transaction(
        conn,
        operation="OAuth account-deletion challenge creation",
    )
    cursor = persistence._get_cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        user_session, user = persistence.get_valid_session_by_auth_token(auth_token)
        if user_session.user_id != user_id or user.id != user_id:
            raise KeyError("The session does not belong to this user.")
        if user.auth_provider != provider or not user.auth_provider_id:
            raise ValueError("This account does not use the requested provider.")

        cursor.execute(
            """
            DELETE FROM oauth_login_handoffs
            WHERE valid_until <= ? OR consumed_at IS NOT NULL
            """,
            (now.timestamp(),),
        )
        cursor.execute(
            """
            INSERT INTO oauth_login_handoffs (
                token_hash, user_id, provider, created_at, valid_until, consumed_at
            )
            VALUES (?, ?, ?, ?, ?, NULL)
            """,
            (
                _hash_one_time_token(token),
                str(user_id),
                stored_provider,
                now.timestamp(),
                (now + timedelta(minutes=ttl)).timestamp(),
            ),
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return token


async def exchange_oauth_account_deletion_challenge(
    persistence: SocialPersistence,
    *,
    challenge_token: str,
    provider: str,
    provider_user_id: str,
    ttl_minutes: int | None = None,
) -> str:
    """Exchange fresh matching provider auth for a deletion-only approval."""
    provider = _normalize_provider(provider)
    provider_user_id = str(provider_user_id).strip()
    if not challenge_token.startswith(OAUTH_DELETE_CHALLENGE_PREFIX):
        raise KeyError("OAuth account-deletion challenge is invalid.")
    if not provider_user_id:
        raise KeyError("Provider identity is missing.")

    now = datetime.now(timezone.utc)
    ttl = (
        config.OAUTH_HANDOFF_TTL_MINUTES
        if ttl_minutes is None
        else ttl_minutes
    )
    if ttl <= 0:
        raise ValueError("OAuth handoff lifetime must be positive.")

    approval_token = _new_handoff_token(prefix=OAUTH_DELETE_APPROVAL_PREFIX)
    conn = _get_connection(persistence)
    _require_top_level_transaction(
        conn,
        operation="OAuth account-deletion challenge exchange",
    )
    cursor = persistence._get_cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor.execute(
            """
            SELECT user_id, provider, valid_until, consumed_at
            FROM oauth_login_handoffs
            WHERE token_hash = ?
            LIMIT 1
            """,
            (_hash_one_time_token(challenge_token),),
        )
        row = cursor.fetchone()
        if row is None:
            raise KeyError("OAuth account-deletion challenge is invalid.")

        user_id, stored_provider, valid_until_ts, consumed_at = row
        if (
            consumed_at is not None
            or datetime.fromtimestamp(valid_until_ts, tz=timezone.utc) <= now
        ):
            raise KeyError("OAuth account-deletion challenge has expired.")

        session_hash = _oauth_deletion_session_hash(stored_provider, provider)
        cursor.execute(
            """
            SELECT
                u.auth_provider,
                u.auth_provider_id,
                u.is_active,
                s.created_at,
                s.valid_until
            FROM users AS u
            JOIN user_sessions AS s ON s.user_id = u.id
            WHERE u.id = ? AND s.id = ?
            LIMIT 1
            """,
            (user_id, session_hash),
        )
        account_row = cursor.fetchone()
        if account_row is None:
            raise KeyError("The session for this approval is no longer valid.")

        (
            live_provider,
            live_provider_user_id,
            is_active,
            session_created_at_ts,
            session_valid_until_ts,
        ) = account_row
        session_created_at = datetime.fromtimestamp(
            session_created_at_ts,
            tz=timezone.utc,
        )
        session_valid_until = datetime.fromtimestamp(
            session_valid_until_ts,
            tz=timezone.utc,
        )
        if (
            not bool(is_active)
            or live_provider != provider
            or live_provider_user_id != provider_user_id
            or session_valid_until <= now
            or _absolute_session_expired(created_at=session_created_at, now=now)
        ):
            raise KeyError("Provider identity or live session no longer matches.")

        cursor.execute(
            "DELETE FROM oauth_login_handoffs WHERE token_hash = ?",
            (_hash_one_time_token(challenge_token),),
        )
        if cursor.rowcount != 1:
            raise KeyError("OAuth account-deletion challenge was already used.")
        cursor.execute(
            """
            INSERT INTO oauth_login_handoffs (
                token_hash, user_id, provider, created_at, valid_until, consumed_at
            )
            VALUES (?, ?, ?, ?, ?, NULL)
            """,
            (
                _hash_one_time_token(approval_token),
                user_id,
                stored_provider,
                now.timestamp(),
                (now + timedelta(minutes=ttl)).timestamp(),
            ),
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return approval_token


def consume_oauth_account_deletion_approval_in_transaction(
    persistence: SocialPersistence,
    *,
    approval_token: str,
    user_id: uuid.UUID,
    provider: str,
    auth_token: str,
) -> None:
    """Consume a purpose- and session-bound approval without committing."""
    provider = _normalize_provider(provider)
    if not approval_token.startswith(OAUTH_DELETE_APPROVAL_PREFIX):
        raise KeyError("OAuth account-deletion approval is invalid.")

    conn = _get_connection(persistence)
    if not conn.in_transaction:
        raise RuntimeError(
            "OAuth account-deletion approval consumption requires an open "
            "transaction."
        )

    cursor = persistence._get_cursor()
    cursor.execute(
        """
        SELECT user_id, provider, valid_until, consumed_at
        FROM oauth_login_handoffs
        WHERE token_hash = ?
        LIMIT 1
        """,
        (_hash_one_time_token(approval_token),),
    )
    row = cursor.fetchone()
    if row is None:
        raise KeyError("OAuth account-deletion approval is invalid.")

    stored_user_id, stored_provider, valid_until_ts, consumed_at = row
    if (
        stored_user_id != str(user_id)
        or stored_provider != _oauth_deletion_provider_value(provider, auth_token)
        or consumed_at is not None
        or datetime.fromtimestamp(valid_until_ts, tz=timezone.utc)
        <= datetime.now(timezone.utc)
    ):
        raise KeyError("OAuth account-deletion approval does not match.")

    cursor.execute(
        "DELETE FROM oauth_login_handoffs WHERE token_hash = ?",
        (_hash_one_time_token(approval_token),),
    )
    if cursor.rowcount != 1:
        raise KeyError("OAuth account-deletion approval was already used.")


async def consume_oauth_handoff(
    persistence: SocialPersistence,
    token: str,
) -> AppUser:
    if token.startswith("DELETE-"):
        raise KeyError("OAuth handoff has the wrong purpose.")
    token_hash = _hash_one_time_token(token)
    now = datetime.now(timezone.utc)
    conn = _get_connection(persistence)
    _require_top_level_transaction(conn, operation="OAuth handoff consumption")
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
            "DELETE FROM oauth_login_handoffs WHERE token_hash = ?",
            (token_hash,),
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
