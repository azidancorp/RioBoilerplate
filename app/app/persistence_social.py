from __future__ import annotations

import hmac
import re
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
OAUTH_MFA_ENABLE_CHALLENGE_PREFIX = "MFA-ENABLE-START-"
OAUTH_MFA_ENABLE_APPROVAL_PREFIX = "MFA-ENABLE-APPROVE-"
OAUTH_MFA_DISABLE_CHALLENGE_PREFIX = "MFA-DISABLE-START-"
OAUTH_MFA_DISABLE_APPROVAL_PREFIX = "MFA-DISABLE-APPROVE-"
OAUTH_RECOVERY_CODES_CHALLENGE_PREFIX = "RECOVERY-CODES-START-"
OAUTH_RECOVERY_CODES_APPROVAL_PREFIX = "RECOVERY-CODES-APPROVE-"
OAUTH_ACCOUNT_DELETE_PURPOSE = "delete-account"
OAUTH_MFA_ENABLE_PURPOSE = "mfa-enable"
OAUTH_MFA_DISABLE_PURPOSE = "mfa-disable"
OAUTH_RECOVERY_CODES_PURPOSE = "recovery-codes-regenerate"
_BINDING_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_FLOW_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_OAUTH_REAUTH_TOKEN_PREFIXES = {
    OAUTH_ACCOUNT_DELETE_PURPOSE: (
        OAUTH_DELETE_CHALLENGE_PREFIX,
        OAUTH_DELETE_APPROVAL_PREFIX,
    ),
    OAUTH_MFA_ENABLE_PURPOSE: (
        OAUTH_MFA_ENABLE_CHALLENGE_PREFIX,
        OAUTH_MFA_ENABLE_APPROVAL_PREFIX,
    ),
    OAUTH_MFA_DISABLE_PURPOSE: (
        OAUTH_MFA_DISABLE_CHALLENGE_PREFIX,
        OAUTH_MFA_DISABLE_APPROVAL_PREFIX,
    ),
    OAUTH_RECOVERY_CODES_PURPOSE: (
        OAUTH_RECOVERY_CODES_CHALLENGE_PREFIX,
        OAUTH_RECOVERY_CODES_APPROVAL_PREFIX,
    ),
}


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


def _require_binding_digest(binding_digest: str) -> str:
    if (
        not isinstance(binding_digest, str)
        or _BINDING_DIGEST_PATTERN.fullmatch(binding_digest) is None
    ):
        raise KeyError("Invalid OAuth browser-binding digest.")
    return binding_digest


def _require_flow_id(flow_id: str) -> str:
    if (
        not isinstance(flow_id, str)
        or _FLOW_ID_PATTERN.fullmatch(flow_id) is None
    ):
        raise KeyError("Invalid OAuth pending-login flow ID.")
    return flow_id


def _new_handoff_token(*, prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(32).upper()}"


def _require_oauth_reauth_purpose(purpose: str) -> str:
    purpose = str(purpose).strip()
    if purpose not in _OAUTH_REAUTH_TOKEN_PREFIXES:
        raise KeyError("Unsupported OAuth reauthentication purpose.")
    return purpose


def oauth_reauth_challenge_prefix(purpose: str) -> str:
    purpose = _require_oauth_reauth_purpose(purpose)
    return _OAUTH_REAUTH_TOKEN_PREFIXES[purpose][0]


def oauth_reauth_approval_prefix(purpose: str) -> str:
    purpose = _require_oauth_reauth_purpose(purpose)
    return _OAUTH_REAUTH_TOKEN_PREFIXES[purpose][1]


def _oauth_reauth_provider_value(provider: str, purpose: str, auth_token: str) -> str:
    purpose = _require_oauth_reauth_purpose(purpose)
    return (
        f"{provider}:{purpose}:"
        f"{_hash_one_time_token(auth_token)}"
    )


def _oauth_reauth_session_hash(
    stored_provider: str,
    provider: str,
    purpose: str,
) -> str:
    purpose = _require_oauth_reauth_purpose(purpose)
    prefix = f"{provider}:{purpose}:"
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


async def create_oauth_pending_login(
    persistence: SocialPersistence,
    *,
    binding_digest: str,
    flow_id: str,
    user_id: uuid.UUID,
    provider: str,
    ttl_minutes: int | None = None,
) -> None:
    binding_digest = _require_binding_digest(binding_digest)
    flow_id = _require_flow_id(flow_id)
    provider = _normalize_provider(provider)
    ttl = (
        config.OAUTH_HANDOFF_TTL_MINUTES
        if ttl_minutes is None
        else ttl_minutes
    )
    if ttl <= 0:
        raise ValueError("OAuth pending-login lifetime must be positive.")

    conn = _get_connection(persistence)
    _require_top_level_transaction(conn, operation="OAuth pending-login creation")
    cursor = persistence._get_cursor()
    try:
        # The writer lock establishes ordering against account deactivation.
        # Sample time and re-read account state only after the lock is owned,
        # then replace this browser's pending login without yielding.
        conn.execute("BEGIN IMMEDIATE")
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(minutes=ttl)
        cursor.execute(
            """
            DELETE FROM oauth_pending_logins
            WHERE valid_until <= ?
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
            raise ValueError(
                "Cannot create an OAuth pending login for an inactive user."
            )

        # Keep at most one pending login per browser. Two statements inside the
        # transaction preserve the prior row if insertion subsequently fails.
        cursor.execute(
            "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
            (binding_digest,),
        )
        cursor.execute(
            """
            INSERT INTO oauth_pending_logins (
                binding_digest, flow_id, user_id, provider, created_at, valid_until
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                binding_digest,
                flow_id,
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


async def create_oauth_reauth_challenge(
    persistence: SocialPersistence,
    *,
    user_id: uuid.UUID,
    provider: str,
    purpose: str,
    auth_token: str,
    ttl_minutes: int | None = None,
) -> str:
    """Create a one-time, session-bound challenge before provider reauth."""
    provider = _normalize_provider(provider)
    purpose = _require_oauth_reauth_purpose(purpose)
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

    challenge_prefix, _ = _OAUTH_REAUTH_TOKEN_PREFIXES[purpose]
    token = _new_handoff_token(prefix=challenge_prefix)
    stored_provider = _oauth_reauth_provider_value(provider, purpose, auth_token)
    conn = _get_connection(persistence)
    _require_top_level_transaction(
        conn,
        operation="OAuth reauthentication challenge creation",
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


async def create_oauth_account_deletion_challenge(
    persistence: SocialPersistence,
    *,
    user_id: uuid.UUID,
    provider: str,
    auth_token: str,
    ttl_minutes: int | None = None,
) -> str:
    return await create_oauth_reauth_challenge(
        persistence,
        user_id=user_id,
        provider=provider,
        purpose=OAUTH_ACCOUNT_DELETE_PURPOSE,
        auth_token=auth_token,
        ttl_minutes=ttl_minutes,
    )


async def exchange_oauth_reauth_challenge(
    persistence: SocialPersistence,
    *,
    challenge_token: str,
    provider: str,
    purpose: str,
    provider_user_id: str,
    ttl_minutes: int | None = None,
) -> str:
    """Exchange fresh matching provider auth for a purpose-bound approval."""
    provider = _normalize_provider(provider)
    purpose = _require_oauth_reauth_purpose(purpose)
    provider_user_id = str(provider_user_id).strip()
    challenge_prefix, approval_prefix = _OAUTH_REAUTH_TOKEN_PREFIXES[purpose]
    if not challenge_token.startswith(challenge_prefix):
        raise KeyError("OAuth reauthentication challenge is invalid.")
    if not provider_user_id:
        raise KeyError("Provider identity is missing.")

    now = datetime.now(timezone.utc)
    default_ttl = (
        config.OAUTH_HANDOFF_TTL_MINUTES
        if purpose == OAUTH_ACCOUNT_DELETE_PURPOSE
        else config.MFA_LIFECYCLE_APPROVAL_TTL_MINUTES
    )
    ttl = (
        default_ttl
        if ttl_minutes is None
        else ttl_minutes
    )
    if ttl <= 0:
        raise ValueError("OAuth handoff lifetime must be positive.")

    approval_token = _new_handoff_token(prefix=approval_prefix)
    conn = _get_connection(persistence)
    _require_top_level_transaction(
        conn,
        operation="OAuth reauthentication challenge exchange",
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
            raise KeyError("OAuth reauthentication challenge is invalid.")

        user_id, stored_provider, valid_until_ts, consumed_at = row
        if (
            consumed_at is not None
            or datetime.fromtimestamp(valid_until_ts, tz=timezone.utc) <= now
        ):
            raise KeyError("OAuth reauthentication challenge has expired.")

        session_hash = _oauth_reauth_session_hash(stored_provider, provider, purpose)
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
            raise KeyError("OAuth reauthentication challenge was already used.")
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


async def exchange_oauth_account_deletion_challenge(
    persistence: SocialPersistence,
    *,
    challenge_token: str,
    provider: str,
    provider_user_id: str,
    ttl_minutes: int | None = None,
) -> str:
    return await exchange_oauth_reauth_challenge(
        persistence,
        challenge_token=challenge_token,
        provider=provider,
        purpose=OAUTH_ACCOUNT_DELETE_PURPOSE,
        provider_user_id=provider_user_id,
        ttl_minutes=ttl_minutes,
    )


def _require_oauth_reauth_approval_in_transaction(
    persistence: SocialPersistence,
    *,
    approval_token: str,
    user_id: uuid.UUID,
    provider: str,
    purpose: str,
    auth_token: str,
) -> str:
    """Validate a purpose- and session-bound approval in an open transaction."""
    provider = _normalize_provider(provider)
    purpose = _require_oauth_reauth_purpose(purpose)
    _, approval_prefix = _OAUTH_REAUTH_TOKEN_PREFIXES[purpose]
    if not approval_token.startswith(approval_prefix):
        raise KeyError("OAuth reauthentication approval is invalid.")

    conn = _get_connection(persistence)
    if not conn.in_transaction:
        raise RuntimeError(
            "OAuth reauthentication approval validation requires an open "
            "transaction."
        )

    token_hash = _hash_one_time_token(approval_token)
    cursor = persistence._get_cursor()
    cursor.execute(
        """
        SELECT user_id, provider, valid_until, consumed_at
        FROM oauth_login_handoffs
        WHERE token_hash = ?
        LIMIT 1
        """,
        (token_hash,),
    )
    row = cursor.fetchone()
    if row is None:
        raise KeyError("OAuth reauthentication approval is invalid.")

    stored_user_id, stored_provider, valid_until_ts, consumed_at = row
    if (
        stored_user_id != str(user_id)
        or stored_provider != _oauth_reauth_provider_value(provider, purpose, auth_token)
        or consumed_at is not None
        or datetime.fromtimestamp(valid_until_ts, tz=timezone.utc)
        <= datetime.now(timezone.utc)
    ):
        raise KeyError("OAuth reauthentication approval does not match.")

    return token_hash


def validate_oauth_reauth_approval(
    persistence: SocialPersistence,
    *,
    approval_token: str,
    user_id: uuid.UUID,
    provider: str,
    purpose: str,
    auth_token: str,
) -> None:
    """Validate an approval and its live session without consuming it."""
    provider = _normalize_provider(provider)
    purpose = _require_oauth_reauth_purpose(purpose)
    if not auth_token:
        raise KeyError("A live session is required.")

    conn = _get_connection(persistence)
    _require_top_level_transaction(
        conn,
        operation="OAuth reauthentication approval validation",
    )
    try:
        conn.execute("BEGIN")
        user_session, user = persistence.get_valid_session_by_auth_token(auth_token)
        if user_session.user_id != user_id or user.id != user_id:
            raise KeyError("The session does not belong to this user.")
        if user.auth_provider != provider or not user.auth_provider_id:
            raise KeyError("This account does not use the requested provider.")
        _require_oauth_reauth_approval_in_transaction(
            persistence,
            approval_token=approval_token,
            user_id=user_id,
            provider=provider,
            purpose=purpose,
            auth_token=auth_token,
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


def consume_oauth_reauth_approval_in_transaction(
    persistence: SocialPersistence,
    *,
    approval_token: str,
    user_id: uuid.UUID,
    provider: str,
    purpose: str,
    auth_token: str,
) -> None:
    """Consume a purpose- and session-bound approval without committing."""
    token_hash = _require_oauth_reauth_approval_in_transaction(
        persistence,
        approval_token=approval_token,
        user_id=user_id,
        provider=provider,
        purpose=purpose,
        auth_token=auth_token,
    )

    cursor = persistence._get_cursor()
    cursor.execute(
        "DELETE FROM oauth_login_handoffs WHERE token_hash = ?",
        (token_hash,),
    )
    if cursor.rowcount != 1:
        raise KeyError("OAuth reauthentication approval was already used.")


def consume_oauth_account_deletion_approval_in_transaction(
    persistence: SocialPersistence,
    *,
    approval_token: str,
    user_id: uuid.UUID,
    provider: str,
    auth_token: str,
) -> None:
    consume_oauth_reauth_approval_in_transaction(
        persistence,
        approval_token=approval_token,
        user_id=user_id,
        provider=provider,
        purpose=OAUTH_ACCOUNT_DELETE_PURPOSE,
        auth_token=auth_token,
    )


async def consume_oauth_pending_login(
    persistence: SocialPersistence,
    binding_digest: str,
    flow_id: str,
    *,
    provider: str = "google",
) -> AppUser:
    binding_digest = _require_binding_digest(binding_digest)
    flow_id = _require_flow_id(flow_id)
    conn = _get_connection(persistence)
    _require_top_level_transaction(conn, operation="OAuth pending-login consumption")
    cursor = persistence._get_cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        now = datetime.now(timezone.utc)
        cursor.execute(
            """
            SELECT user_id, flow_id, valid_until, provider
            FROM oauth_pending_logins
            WHERE binding_digest = ?
            LIMIT 1
            """,
            (binding_digest,),
        )
        row = cursor.fetchone()
        if row is None:
            raise KeyError("OAuth pending login is invalid or was already used.")

        user_id_str, row_flow_id, valid_until_ts, row_provider = row
        if datetime.fromtimestamp(valid_until_ts, tz=timezone.utc) <= now:
            cursor.execute(
                "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
                (binding_digest,),
            )
            conn.commit()
            raise KeyError("OAuth pending login has expired.")

        # A stale tab from an earlier overlapping flow must fail without
        # destroying the newest flow's still-consumable row.
        if not hmac.compare_digest(str(row_flow_id), flow_id):
            raise KeyError(
                "OAuth pending login does not match this sign-in attempt."
            )

        if row_provider != provider:
            raise KeyError(
                "OAuth pending login was issued for a different provider."
            )

        cursor.execute(
            "SELECT is_active FROM users WHERE id = ?",
            (user_id_str,),
        )
        user_row = cursor.fetchone()
        if user_row is None or not bool(user_row[0]):
            cursor.execute(
                "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
                (binding_digest,),
            )
            conn.commit()
            raise KeyError("OAuth pending login belongs to an inactive or missing user.")

        cursor.execute(
            "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
            (binding_digest,),
        )
        if cursor.rowcount != 1:
            raise KeyError("OAuth pending login was already used.")

        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return await persistence.get_user_by_id(uuid.UUID(user_id_str))


async def validate_oauth_pending_login(
    persistence: SocialPersistence,
    binding_digest: str,
    flow_id: str,
    *,
    provider: str = "google",
) -> AppUser:
    """Validate a pending login without consuming it."""
    binding_digest = _require_binding_digest(binding_digest)
    flow_id = _require_flow_id(flow_id)
    conn = _get_connection(persistence)
    _require_top_level_transaction(conn, operation="OAuth pending-login validation")
    cursor = persistence._get_cursor()

    try:
        conn.execute("BEGIN IMMEDIATE")
        now = datetime.now(timezone.utc)
        cursor.execute(
            """
            SELECT user_id, flow_id, valid_until, provider
            FROM oauth_pending_logins
            WHERE binding_digest = ?
            LIMIT 1
            """,
            (binding_digest,),
        )
        row = cursor.fetchone()
        if row is None:
            raise KeyError("OAuth pending login is invalid or was already used.")

        user_id_str, row_flow_id, valid_until_ts, row_provider = row
        if datetime.fromtimestamp(valid_until_ts, tz=timezone.utc) <= now:
            cursor.execute(
                "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
                (binding_digest,),
            )
            conn.commit()
            raise KeyError("OAuth pending login has expired.")

        if not hmac.compare_digest(str(row_flow_id), flow_id):
            raise KeyError(
                "OAuth pending login does not match this sign-in attempt."
            )

        if row_provider != provider:
            raise KeyError(
                "OAuth pending login was issued for a different provider."
            )

        cursor.execute(
            "SELECT is_active FROM users WHERE id = ?",
            (user_id_str,),
        )
        user_row = cursor.fetchone()
        if user_row is None or not bool(user_row[0]):
            cursor.execute(
                "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
                (binding_digest,),
            )
            conn.commit()
            raise KeyError("OAuth pending login belongs to an inactive or missing user.")

        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return await persistence.get_user_by_id(uuid.UUID(user_id_str))


def consume_oauth_pending_login_in_transaction(
    persistence: SocialPersistence,
    binding_digest: str,
    flow_id: str,
    *,
    provider: str = "google",
) -> uuid.UUID:
    """Consume a pending login inside the caller's open transaction."""
    binding_digest = _require_binding_digest(binding_digest)
    flow_id = _require_flow_id(flow_id)
    conn = _get_connection(persistence)
    if not conn.in_transaction:
        raise RuntimeError("OAuth pending-login consumption requires an open transaction.")
    cursor = persistence._get_cursor()
    now = datetime.now(timezone.utc)
    cursor.execute(
        """
        SELECT user_id, flow_id, valid_until, provider
        FROM oauth_pending_logins
        WHERE binding_digest = ?
        LIMIT 1
        """,
        (binding_digest,),
    )
    row = cursor.fetchone()
    if row is None:
        raise KeyError("OAuth pending login is invalid or was already used.")

    user_id_str, row_flow_id, valid_until_ts, row_provider = row
    if datetime.fromtimestamp(valid_until_ts, tz=timezone.utc) <= now:
        cursor.execute(
            "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
            (binding_digest,),
        )
        raise KeyError("OAuth pending login has expired.")

    if not hmac.compare_digest(str(row_flow_id), flow_id):
        raise KeyError("OAuth pending login does not match this sign-in attempt.")

    if row_provider != provider:
        raise KeyError("OAuth pending login was issued for a different provider.")

    cursor.execute(
        "SELECT is_active FROM users WHERE id = ?",
        (user_id_str,),
    )
    user_row = cursor.fetchone()
    if user_row is None or not bool(user_row[0]):
        cursor.execute(
            "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
            (binding_digest,),
        )
        raise KeyError("OAuth pending login belongs to an inactive or missing user.")

    cursor.execute(
        "DELETE FROM oauth_pending_logins WHERE binding_digest = ?",
        (binding_digest,),
    )
    if cursor.rowcount != 1:
        raise KeyError("OAuth pending login was already used.")
    return uuid.UUID(user_id_str)
