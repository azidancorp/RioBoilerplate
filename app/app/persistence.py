import sqlite3
import threading
import uuid
import typing as t
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.data_models import (
    AppUser,
    UserSession,
    ExpirableVerificationToken,
    CurrencyLedgerEntry,
)
from app.validation import SecuritySanitizer
from app.password_policy import require_new_password
from app.config import config
from app.permissions import (
    can_manage_role,
    check_access,
    get_default_role,
    get_highest_privilege_role,
    validate_role,
    get_all_roles,
)
from app.rate_limits import RateLimitDecision, RateLimitPolicy
import app.persistence_audit as persistence_audit
import app.persistence_auth as persistence_auth
import app.persistence_currency as persistence_currency
import app.persistence_profiles as persistence_profiles
import app.persistence_rate_limits as persistence_rate_limits
import app.persistence_social as persistence_social
import app.persistence_users as persistence_users
from app.persistence_schema import initialize_schema


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "app.db"
TwoFactorStateConflict = persistence_auth.TwoFactorStateConflict
CurrencyIdempotencyConflictError = (
    persistence_currency.CurrencyIdempotencyConflictError
)


class BootstrapRequiredError(RuntimeError):
    """Raised when public registration is attempted before operator bootstrap."""


class AdminSessionInvalidError(PermissionError):
    """Raised when an admin mutation no longer has a live bearer session."""


@dataclass(frozen=True, slots=True)
class AdminMutationContext:
    """Live session context required by every web-admin persistence mutation."""

    auth_token: str
    client_ip: str | None = None


@dataclass
class AdminPasswordResetIssuance(ExpirableVerificationToken):
    """Reset token and recipient captured at the transaction linearization point."""

    recipient_email: str


@dataclass(frozen=True, slots=True)
class _AdminTargetSnapshot:
    """Target fields read while the admin mutation owns the SQLite writer lock."""

    id: uuid.UUID
    email: str
    username: str | None
    role: str
    is_active: bool
    auth_provider: str
    primary_currency_balance: int


# Schema setup is idempotent but does ~29 DDL statements, so we only run it once
# per database file per process instead of on every Persistence() construction
# (the FastAPI dependency builds a fresh facade on each request). The guard is an
# optimization only: initialize_schema() stays safe to call again, so a missed
# guard just costs a redundant no-op pass, never correctness.
_initialized_db_paths: set[str] = set()
_initialized_db_paths_lock = threading.Lock()


def _reset_initialized_db_paths() -> None:
    """Forget which databases have been initialized (used by tests)."""
    with _initialized_db_paths_lock:
        _initialized_db_paths.clear()


class Persistence:
    """Façade for all database operations. Delegates to persistence_* modules."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        *,
        allow_username_login: bool = False,
    ) -> None:
        self.db_path = db_path
        self.allow_username_login = allow_username_login
        self._thread_local = threading.local()
        self._ensure_connection()
        self._initialize_schema_once()

    def _initialize_schema_once(self) -> None:
        key = str(self.db_path)
        with _initialized_db_paths_lock:
            already_done = key in _initialized_db_paths
        if not already_done:
            initialize_schema(self)
            with _initialized_db_paths_lock:
                _initialized_db_paths.add(key)

    @property
    def conn(self) -> sqlite3.Connection | None:
        # Connections are thread-local so a shared Persistence facade does not
        # reuse SQLite connections across Rio/FastAPI worker threads.
        thread_local = getattr(self, "_thread_local", None)
        if thread_local is None:
            return None
        return getattr(thread_local, "conn", None)

    @conn.setter
    def conn(self, value: sqlite3.Connection | None) -> None:
        thread_local = getattr(self, "_thread_local", None)
        if thread_local is None:
            return
        if value is None:
            if hasattr(thread_local, "conn"):
                delattr(thread_local, "conn")
            return
        thread_local.conn = value

    def _ensure_connection(self) -> None:
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path, timeout=30.0)
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA busy_timeout = 5000")

    def _get_cursor(self):
        self._ensure_connection()
        return self.conn.cursor()

    def close(self) -> None:
        # As of the post-a179c6c persistence fix, repo usage is request/session
        # scoped and does not share one facade across long-lived worker threads.
        # If that changes, each worker thread must close its own connection.
        if not self.conn:
            return
        try:
            self.conn.close()
        except sqlite3.ProgrammingError:
            pass
        finally:
            self.conn = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def _hash_one_time_token(token: str) -> str:
        return persistence_auth._hash_one_time_token(token)

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
        return persistence_currency.append_currency_ledger_entry(
            self,
            user_id=user_id,
            delta=delta,
            balance_after=balance_after,
            reason=reason,
            metadata=metadata,
            actor_user_id=actor_user_id,
            created_at=created_at,
            commit=commit,
        )

    def record_admin_action(self, **kwargs) -> None:
        return persistence_audit.record_admin_action(self, **kwargs)

    def list_admin_actions(self, **kwargs) -> list[dict[str, t.Any]]:
        return persistence_audit.list_admin_actions(self, **kwargs)

    def generate_recovery_codes(
        self,
        user_id: uuid.UUID,
        count: int = 10,
        *,
        expected_secret: str | None = None,
    ) -> list[str]:
        return persistence_auth.generate_recovery_codes(
            self,
            user_id,
            count=count,
            expected_secret=expected_secret,
        )

    def enroll_two_factor(
        self,
        user_id: uuid.UUID,
        secret: str,
        count: int = 10,
    ) -> list[str]:
        return persistence_auth.enroll_two_factor(
            self,
            user_id,
            secret,
            count=count,
        )

    def get_recovery_codes_summary(self, user_id: uuid.UUID) -> dict[str, t.Any]:
        return persistence_auth.get_recovery_codes_summary(self, user_id)

    def get_user_count(self) -> int:
        return persistence_users.get_user_count(self)

    def has_verified_root_user(self) -> bool:
        cursor = self._get_cursor()
        cursor.execute(
            "SELECT 1 FROM users WHERE role = ? AND is_verified = 1 LIMIT 1",
            (get_highest_privilege_role(),),
        )
        return cursor.fetchone() is not None

    def check_rate_limit(
        self,
        *,
        policy: RateLimitPolicy,
        key: str,
        cost: int = 1,
        now: datetime | None = None,
        metadata: t.Mapping[str, object] | None = None,
    ) -> RateLimitDecision:
        return persistence_rate_limits.check_rate_limit(
            self,
            policy=policy,
            key=key,
            cost=cost,
            now=now,
            metadata=metadata,
        )

    def clear_rate_limit(self, *, scope: str, key: str) -> None:
        persistence_rate_limits.clear_rate_limit(self, scope=scope, key=key)

    def cleanup_rate_limits(self, *, now: datetime | None = None) -> int:
        return persistence_rate_limits.cleanup_rate_limits(self, now=now)

    def _insert_user_records(
        self,
        cursor: sqlite3.Cursor,
        *,
        user: AppUser,
        assigned_role: str,
        now_ts: float,
        profile_full_name: str | None = None,
    ) -> None:
        if not validate_role(assigned_role):
            raise ValueError(
                f"Invalid role: {assigned_role}. "
                f"Must be one of: {', '.join(get_all_roles())}"
            )

        cursor.execute(
            """
            INSERT INTO users (
                id,
                email,
                username,
                created_at,
                password_hash,
                password_salt,
                password_scheme,
                auth_provider,
                auth_provider_id,
                role,
                is_verified,
                is_active,
                two_factor_secret,
                referral_code,
                email_notifications_enabled,
                sms_notifications_enabled,
                primary_currency_balance,
                primary_currency_updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(user.id),
                user.email,
                user.username,
                user.created_at.timestamp(),
                user.password_hash,
                user.password_salt,
                user.password_scheme,
                user.auth_provider,
                user.auth_provider_id,
                assigned_role,
                user.is_verified,
                user.is_active,
                user.two_factor_secret,
                user.referral_code,
                user.email_notifications_enabled,
                user.sms_notifications_enabled,
                user.primary_currency_balance,
                now_ts,
            ),
        )

        cursor.execute(
            """
            INSERT INTO profiles
            (
                user_id,
                full_name,
                email,
                phone,
                address,
                bio,
                avatar_url,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(user.id),
                (
                    profile_full_name
                    if profile_full_name is not None
                    else user.username or ""
                ),
                user.email,
                None,
                None,
                None,
                None,
                now_ts,
                now_ts,
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

    @staticmethod
    def _require_role_can_manage(
        *,
        actor_role: str,
        target_role: str,
        action: str,
    ) -> None:
        if not can_manage_role(actor_role, target_role):
            raise PermissionError(
                f"User with role {actor_role} cannot {action} users with role {target_role}."
            )

    @staticmethod
    def _require_top_level_transaction(
        conn: sqlite3.Connection,
        *,
        action: str,
    ) -> None:
        if conn.in_transaction:
            raise RuntimeError(f"{action} cannot run inside an existing transaction.")

    def _require_live_admin_actor(
        self,
        admin_context: AdminMutationContext,
    ) -> AppUser:
        """Resolve the actor from a live session inside an open write transaction."""
        if not admin_context.auth_token:
            raise AdminSessionInvalidError("Your admin session is no longer valid.")

        try:
            _, actor = self.get_valid_session_by_auth_token(admin_context.auth_token)
        except KeyError as exc:
            raise AdminSessionInvalidError(
                "Your admin session is no longer valid."
            ) from exc

        if not check_access("/app/admin", actor.role):
            raise PermissionError(
                f"User with role {actor.role} is not authorized for admin actions."
            )
        return actor

    @staticmethod
    def _load_admin_target(
        cursor: sqlite3.Cursor,
        user_id: uuid.UUID,
    ) -> _AdminTargetSnapshot:
        cursor.execute(
            """
            SELECT email, username, role, is_active, auth_provider,
                   primary_currency_balance
            FROM users
            WHERE id = ?
            """,
            (str(user_id),),
        )
        row = cursor.fetchone()
        if row is None:
            raise KeyError(user_id)
        return _AdminTargetSnapshot(
            id=user_id,
            email=t.cast(str, row[0]),
            username=t.cast(str | None, row[1]),
            role=t.cast(str, row[2]),
            is_active=bool(row[3]),
            auth_provider=t.cast(str, row[4]),
            primary_currency_balance=int(row[5] or 0),
        )

    def _require_live_admin_actor_can_manage(
        self,
        cursor: sqlite3.Cursor,
        *,
        admin_context: AdminMutationContext,
        target_user_id: uuid.UUID,
        action: str,
        allow_self: bool = False,
    ) -> tuple[AppUser, _AdminTargetSnapshot]:
        actor = self._require_live_admin_actor(admin_context)
        target = self._load_admin_target(cursor, target_user_id)
        if actor.id != target.id:
            self._require_role_can_manage(
                actor_role=actor.role,
                target_role=target.role,
                action=action,
            )
        elif not allow_self:
            raise PermissionError(
                f"User with role {actor.role} cannot {action} their own account."
            )
        return actor, target

    def _require_live_profile_actor_can_access(
        self,
        cursor: sqlite3.Cursor,
        *,
        auth_token: str,
        target_user_id: str,
        action: str,
    ) -> tuple[AppUser, _AdminTargetSnapshot]:
        """Authorize a self/admin profile write at its transaction boundary."""
        if not auth_token:
            raise AdminSessionInvalidError("Your session is no longer valid.")

        try:
            _, actor = self.get_valid_session_by_auth_token(auth_token)
        except KeyError as exc:
            raise AdminSessionInvalidError(
                "Your session is no longer valid."
            ) from exc

        try:
            target_id = uuid.UUID(target_user_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise KeyError(target_user_id) from exc

        target = self._load_admin_target(cursor, target_id)
        if actor.id == target.id:
            return actor, target

        if not check_access("/app/admin", actor.role):
            raise PermissionError(
                "You do not have permission to access another user's profile."
            )
        self._require_role_can_manage(
            actor_role=actor.role,
            target_role=target.role,
            action=action,
        )
        return actor, target

    async def _create_user_transaction(
        self,
        user: AppUser,
        *,
        assigned_role: str,
        require_existing_user: bool,
    ) -> None:
        """Insert a user and its dependent records in one transaction."""
        # Even future username-only/anonymous mode should pass through this
        # validator; REQUIRE_VALID_EMAIL=False relaxes syntax, not safety checks.
        user.email = SecuritySanitizer.validate_email_format(
            user.email,
            require_valid=config.REQUIRE_VALID_EMAIL,
        )

        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="User creation")
        cursor = conn.cursor()
        now_ts = datetime.now(timezone.utc).timestamp()

        try:
            conn.execute("BEGIN IMMEDIATE")
            if require_existing_user:
                cursor.execute("SELECT 1 FROM users LIMIT 1")
                if cursor.fetchone() is None:
                    raise BootstrapRequiredError(
                        "This deployment must be initialized by an operator. "
                        "Run python -m app.scripts.bootstrap_root."
                    )

            self._insert_user_records(
                cursor,
                user=user,
                assigned_role=assigned_role,
                now_ts=now_ts,
            )

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        user.role = assigned_role

    async def _create_user_unchecked(self, user: AppUser) -> None:
        """Insert a trusted test/internal user with its explicitly assigned role."""
        await self._create_user_transaction(
            user,
            assigned_role=user.role,
            require_existing_user=False,
        )

    # Spans users + profiles + currency ledger; must stay transactional.
    async def create_user(self, user: AppUser) -> None:
        """Register a default-role user after operator bootstrap has completed."""
        await self._create_user_transaction(
            user,
            assigned_role=get_default_role(),
            require_existing_user=True,
        )

    async def admin_create_user(
        self,
        *,
        email: str,
        password: str,
        role: str,
        admin_context: AdminMutationContext,
        username: str | None = None,
        full_name: str | None = None,
        is_verified: bool = False,
        acknowledged_weak: bool = False,
    ) -> AppUser:
        """Create a user from the authenticated admin surface."""
        if not validate_role(role):
            raise ValueError(
                f"Invalid role: {role}. Must be one of: {', '.join(get_all_roles())}"
            )

        require_new_password(
            password,
            acknowledged_weak=acknowledged_weak,
        )

        normalized_email = SecuritySanitizer.validate_email_format(
            email,
            require_valid=config.REQUIRE_VALID_EMAIL,
        )
        sanitized_username = (
            SecuritySanitizer.sanitize_string(username, 100)
            if username
            else None
        )
        sanitized_full_name = (
            SecuritySanitizer.sanitize_string(full_name, 100)
            if full_name
            else None
        )

        user = AppUser.create_new_user_with_default_settings(
            email=normalized_email,
            password=password,
            username=sanitized_username,
        )
        user.role = role
        user.is_verified = is_verified
        user.is_active = True

        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Admin user creation")
        cursor = conn.cursor()

        try:
            conn.execute("BEGIN IMMEDIATE")
            actor = self._require_live_admin_actor(admin_context)
            self._require_role_can_manage(
                actor_role=actor.role,
                target_role=role,
                action="create",
            )
            now_ts = datetime.now(timezone.utc).timestamp()
            self._insert_user_records(
                cursor,
                user=user,
                assigned_role=role,
                now_ts=now_ts,
                profile_full_name=sanitized_full_name,
            )
            self.record_admin_action(
                actor_user_id=actor.id,
                actor_role=actor.role,
                action="user_create",
                target_user_id=user.id,
                target_label=user.email,
                before=None,
                after={"email": user.email, "role": role},
                client_ip=admin_context.client_ip,
                created_at=now_ts,
                commit=False,
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        return await self.get_user_by_id(user.id)

    async def admin_update_user_profile(
        self,
        user_id: uuid.UUID,
        *,
        admin_context: AdminMutationContext,
        email: str | None = None,
        expected_email: str | None = None,
        username: str | None = None,
        full_name: str | None = None,
    ) -> AppUser:
        """Update admin-managed identity fields and the matching profile row."""
        normalized_email = (
            SecuritySanitizer.validate_email_format(
                email,
                require_valid=config.REQUIRE_VALID_EMAIL,
            )
            if email is not None
            else None
        )
        normalized_expected_email = (
            SecuritySanitizer.validate_email_format(
                expected_email,
                require_valid=config.REQUIRE_VALID_EMAIL,
            )
            if expected_email is not None
            else None
        )
        if normalized_email is not None and normalized_expected_email is None:
            raise ValueError("The current email is required when changing an email address.")
        sanitized_username = (
            SecuritySanitizer.sanitize_string(username, 100)
            if username is not None and username.strip()
            else None
        )
        sanitized_full_name = (
            SecuritySanitizer.sanitize_string(full_name, 100)
            if full_name is not None and full_name.strip()
            else ("" if full_name is not None else None)
        )
        if normalized_email is None and username is None and full_name is None:
            return await self.get_user_by_id(user_id)

        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Admin profile updates")
        cursor = conn.cursor()
        uid = str(user_id)

        try:
            conn.execute("BEGIN IMMEDIATE")
            actor, target = self._require_live_admin_actor_can_manage(
                cursor,
                admin_context=admin_context,
                target_user_id=user_id,
                action="edit",
            )
            if (
                normalized_email is not None
                and normalized_expected_email != target.email
            ):
                raise ValueError(
                    "The user's email changed while this edit was pending. Reload and try again."
                )
            email_changed = (
                normalized_email is not None
                and normalized_email != target.email
            )
            now_ts = datetime.now(timezone.utc).timestamp()
            user_fields: list[str] = []
            user_params: list[t.Any] = []
            if normalized_email is not None:
                user_fields.append("email = ?")
                user_params.append(normalized_email)
            if username is not None:
                user_fields.append("username = ?")
                user_params.append(sanitized_username)

            if user_fields:
                user_params.append(uid)
                cursor.execute(
                    f"UPDATE users SET {', '.join(user_fields)} WHERE id = ?",
                    user_params,
                )
                if cursor.rowcount == 0:
                    raise KeyError(user_id)

            if email_changed:
                # Tokens tied to the old address must die: reset links and
                # verification codes were delivered to the previous mailbox
                # and are now confused-deputy material.
                cursor.execute(
                    "DELETE FROM password_reset_tokens WHERE user_id = ?",
                    (uid,),
                )
                cursor.execute(
                    "DELETE FROM email_verification_tokens WHERE user_id = ?",
                    (uid,),
                )
                # user_sessions is intentionally NOT cleared here. Email is
                # the identifier primitive; is_active is the integrity
                # primitive (see admin_set_user_active, which does revoke
                # sessions). Treating a clerical email fix as a global
                # forced-logout would punish typo corrections. If an admin
                # is rotating the email because of compromise or account
                # handover, the documented workflow is deactivate → edit →
                # reactivate, which kills sessions via the deactivation path.

            profile_fields: list[str] = []
            profile_params: list[t.Any] = []
            if sanitized_full_name is not None:
                profile_fields.append("full_name = ?")
                profile_params.append(sanitized_full_name)
            if normalized_email is not None:
                profile_fields.append("email = ?")
                profile_params.append(normalized_email)

            if profile_fields:
                cursor.execute("SELECT id FROM profiles WHERE user_id = ?", (uid,))
                if cursor.fetchone():
                    profile_fields.append("updated_at = ?")
                    profile_params.extend([now_ts, uid])
                    profile_sql = (
                        "UPDATE profiles "
                        f"SET {', '.join(profile_fields)} "
                        "WHERE user_id = ?"
                    )
                    cursor.execute(
                        profile_sql,
                        profile_params,
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO profiles
                        (
                            user_id,
                            full_name,
                            email,
                            phone,
                            address,
                            bio,
                            avatar_url,
                            created_at,
                            updated_at
                        )
                        VALUES (?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
                        """,
                        (
                            uid,
                            sanitized_full_name or sanitized_username or "",
                            normalized_email or target.email,
                            now_ts,
                            now_ts,
                        ),
                    )

            after_email = (
                normalized_email if normalized_email is not None else target.email
            )
            after_username = (
                sanitized_username if username is not None else target.username
            )
            self.record_admin_action(
                actor_user_id=actor.id,
                actor_role=actor.role,
                action="user_edit",
                target_user_id=user_id,
                target_label=after_email,
                before={
                    "email": target.email,
                    "username": target.username,
                },
                after={"email": after_email, "username": after_username},
                client_ip=admin_context.client_ip,
                created_at=now_ts,
                commit=False,
            )

            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        return await self.get_user_by_id(user_id)

    async def admin_set_user_active(
        self,
        user_id: uuid.UUID,
        is_active: bool,
        *,
        admin_context: AdminMutationContext,
    ) -> AppUser:
        """Activate or deactivate a user, invalidating sessions on deactivation."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Admin status updates")
        cursor = conn.cursor()
        uid = str(user_id)

        try:
            conn.execute("BEGIN IMMEDIATE")
            actor, target = self._require_live_admin_actor_can_manage(
                cursor,
                admin_context=admin_context,
                target_user_id=user_id,
                action="update account status for",
            )
            was_active = target.is_active

            cursor.execute(
                "UPDATE users SET is_active = ? WHERE id = ?",
                (1 if is_active else 0, uid),
            )
            if cursor.rowcount == 0:
                raise KeyError(user_id)

            # Deactivation revokes live sessions. Activation also clears any
            # impossible dormant rows left by an older raced session issuer.
            if not is_active or not was_active:
                cursor.execute(
                    "DELETE FROM user_sessions WHERE user_id = ?",
                    (uid,),
                )

            if not is_active:
                cursor.execute(
                    "DELETE FROM oauth_login_handoffs WHERE user_id = ?",
                    (uid,),
                )
                cursor.execute(
                    "DELETE FROM password_reset_tokens WHERE user_id = ?",
                    (uid,),
                )
                cursor.execute(
                    "DELETE FROM email_verification_tokens WHERE user_id = ?",
                    (uid,),
                )

            self.record_admin_action(
                actor_user_id=actor.id,
                actor_role=actor.role,
                action="user_reactivate" if is_active else "user_deactivate",
                target_user_id=user_id,
                target_label=target.email,
                before={"is_active": was_active},
                after={"is_active": is_active},
                client_ip=admin_context.client_ip,
                commit=False,
            )

            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        return await self.get_user_by_id(user_id)

    async def admin_issue_password_reset(
        self,
        user_id: uuid.UUID,
        *,
        admin_context: AdminMutationContext,
    ) -> AdminPasswordResetIssuance:
        """Create a reset token for an active password-authenticated user."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Admin reset issuance")
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN IMMEDIATE")
            actor, target = self._require_live_admin_actor_can_manage(
                cursor,
                admin_context=admin_context,
                target_user_id=user_id,
                action="reset password for",
            )
            if not target.is_active:
                raise ValueError("Cannot issue a password reset for an inactive user.")
            if target.auth_provider != "password":
                raise ValueError(
                    "Cannot issue a password reset for an external-auth user."
                )

            reset_token = persistence_auth.create_reset_token_in_transaction(
                self,
                user_id,
            )
            # The raw token is never stored — only the issuance fact + expiry.
            self.record_admin_action(
                actor_user_id=actor.id,
                actor_role=actor.role,
                action="password_reset_issued",
                target_user_id=user_id,
                target_label=target.email,
                before=None,
                after=None,
                metadata={"valid_until": reset_token.valid_until.timestamp()},
                client_ip=admin_context.client_ip,
                commit=False,
            )
            conn.commit()
            return AdminPasswordResetIssuance(
                token=reset_token.token,
                user_id=reset_token.user_id,
                created_at=reset_token.created_at,
                valid_until=reset_token.valid_until,
                recipient_email=target.email,
            )
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def create_verified_root_user_if_empty(self, user: AppUser) -> bool:
        """Create a verified root user only if the users table is still empty."""
        user.email = SecuritySanitizer.validate_email_format(
            user.email,
            require_valid=config.REQUIRE_VALID_EMAIL,
        )

        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Root bootstrap")
        cursor = conn.cursor()
        now_ts = datetime.now(timezone.utc).timestamp()
        root_role = get_highest_privilege_role()

        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] > 0:
                conn.rollback()
                return False

            user.role = root_role
            user.is_verified = True
            self._insert_user_records(
                cursor,
                user=user,
                assigned_role=root_role,
                now_ts=now_ts,
            )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise

    async def get_user_by_email(self, email: str) -> AppUser:
        return await persistence_users.get_user_by_email(self, email)

    async def get_user_by_username(self, username: str) -> AppUser:
        return await persistence_users.get_user_by_username(self, username)

    async def get_user_by_identity(self, identifier: str) -> AppUser:
        return await persistence_users.get_user_by_identity(self, identifier)

    async def get_user_by_id(self, id: uuid.UUID) -> AppUser:
        return await persistence_users.get_user_by_id(self, id)

    async def get_user_by_provider_identity(
        self,
        provider: str,
        provider_user_id: str,
    ) -> AppUser:
        return await persistence_social.get_user_by_provider_identity(
            self,
            provider,
            provider_user_id,
        )

    async def create_oauth_handoff(
        self,
        *,
        user_id: uuid.UUID,
        provider: str,
        ttl_minutes: int | None = None,
    ) -> str:
        return await persistence_social.create_oauth_handoff(
            self,
            user_id=user_id,
            provider=provider,
            ttl_minutes=ttl_minutes,
        )

    async def consume_oauth_handoff(self, token: str) -> AppUser:
        return await persistence_social.consume_oauth_handoff(self, token)

    async def list_users(self) -> list[AppUser]:
        return await persistence_users.list_users(self)

    async def get_currency_balance(self, user_id: uuid.UUID) -> int:
        return await persistence_currency.get_currency_balance(self, user_id)

    async def get_currency_overview(self, user_id: uuid.UUID) -> dict[str, t.Any]:
        return await persistence_currency.get_currency_overview(self, user_id)

    async def adjust_currency_balance(
        self,
        user_id: uuid.UUID,
        delta_minor: int,
        *,
        reason: str | None = None,
        metadata: dict[str, t.Any] | None = None,
    ) -> CurrencyLedgerEntry:
        return await persistence_currency.adjust_currency_balance(
            self, user_id, delta_minor,
            reason=reason, metadata=metadata,
        )

    async def admin_adjust_currency_balance(
        self,
        user_id: uuid.UUID,
        delta_minor: int,
        *,
        admin_context: AdminMutationContext,
        reason: str | None = None,
        metadata: dict[str, t.Any] | None = None,
        idempotency_key: uuid.UUID | None = None,
        request_fingerprint: str | None = None,
    ) -> CurrencyLedgerEntry:
        """Admin balance adjustment authorized at the write linearization point."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Admin currency adjustments")
        if (idempotency_key is None) != (request_fingerprint is None):
            raise ValueError(
                "Currency idempotency key and fingerprint must be provided together."
            )
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN IMMEDIATE")
            actor, _ = self._require_live_admin_actor_can_manage(
                cursor,
                admin_context=admin_context,
                target_user_id=user_id,
                action="update balances for",
                allow_self=True,
            )
            if idempotency_key is not None and request_fingerprint is not None:
                replay = persistence_currency.get_idempotent_currency_mutation(
                    self,
                    actor_user_id=actor.id,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                )
                if replay is not None:
                    conn.commit()
                    return replay
            entry = persistence_currency.adjust_currency_balance_in_transaction(
                self,
                user_id,
                delta_minor,
                actor_user_id=actor.id,
                actor_role=actor.role,
                client_ip=admin_context.client_ip,
                reason=reason,
                metadata=metadata,
            )
            if idempotency_key is not None and request_fingerprint is not None:
                persistence_currency.record_currency_idempotency_result(
                    self,
                    actor_user_id=actor.id,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                    ledger_entry_id=entry.id,
                )
            conn.commit()
            return entry
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def set_currency_balance(
        self,
        user_id: uuid.UUID,
        new_balance_minor: int,
        *,
        reason: str | None = None,
        metadata: dict[str, t.Any] | None = None,
    ) -> CurrencyLedgerEntry:
        return await persistence_currency.set_currency_balance(
            self, user_id, new_balance_minor,
            reason=reason, metadata=metadata,
        )

    async def admin_set_currency_balance(
        self,
        user_id: uuid.UUID,
        new_balance_minor: int,
        *,
        admin_context: AdminMutationContext,
        reason: str | None = None,
        metadata: dict[str, t.Any] | None = None,
        idempotency_key: uuid.UUID | None = None,
        request_fingerprint: str | None = None,
    ) -> CurrencyLedgerEntry:
        """Admin balance replacement authorized at the write linearization point."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Admin currency replacements")
        if (idempotency_key is None) != (request_fingerprint is None):
            raise ValueError(
                "Currency idempotency key and fingerprint must be provided together."
            )
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN IMMEDIATE")
            actor, _ = self._require_live_admin_actor_can_manage(
                cursor,
                admin_context=admin_context,
                target_user_id=user_id,
                action="update balances for",
                allow_self=True,
            )
            if idempotency_key is not None and request_fingerprint is not None:
                replay = persistence_currency.get_idempotent_currency_mutation(
                    self,
                    actor_user_id=actor.id,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                )
                if replay is not None:
                    conn.commit()
                    return replay
            entry = persistence_currency.set_currency_balance_in_transaction(
                self,
                user_id,
                new_balance_minor,
                actor_user_id=actor.id,
                actor_role=actor.role,
                client_ip=admin_context.client_ip,
                reason=reason,
                metadata=metadata,
            )
            if idempotency_key is not None and request_fingerprint is not None:
                persistence_currency.record_currency_idempotency_result(
                    self,
                    actor_user_id=actor.id,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                    ledger_entry_id=entry.id,
                )
            conn.commit()
            return entry
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def list_currency_ledger(
        self,
        user_id: uuid.UUID,
        *,
        limit: int = 50,
        before: datetime | None = None,
        after: datetime | None = None,
    ) -> list[CurrencyLedgerEntry]:
        return await persistence_currency.list_currency_ledger(
            self, user_id, limit=limit, before=before, after=after,
        )

    async def verify_currency_balance(
        self,
        user_id: uuid.UUID,
        *,
        auto_fix: bool = False,
    ) -> dict[str, t.Any]:
        return await persistence_currency.verify_currency_balance(
            self, user_id, auto_fix=auto_fix,
        )

    async def verify_all_balances(
        self,
        *,
        auto_fix: bool = False,
    ) -> dict[str, t.Any]:
        return await persistence_currency.verify_all_balances(
            self, auto_fix=auto_fix,
        )

    async def get_user_by_email_or_username(self, identifier: str) -> AppUser:
        return await persistence_users.get_user_by_email_or_username(self, identifier)

    def _update_user_role_in_transaction(
        self,
        cursor: sqlite3.Cursor,
        *,
        target: _AdminTargetSnapshot,
        new_role: str,
        actor_user_id: uuid.UUID | None,
        actor_role: str | None,
        client_ip: str | None,
    ) -> None:
        uid = str(target.id)
        cursor.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (new_role, uid),
        )
        if cursor.rowcount == 0:
            raise KeyError(target.id)
        cursor.execute(
            "UPDATE user_sessions SET role = ? WHERE user_id = ?",
            (new_role, uid),
        )
        self.record_admin_action(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action="role_change",
            target_user_id=target.id,
            target_label=target.email,
            before={"role": target.role},
            after={"role": new_role},
            client_ip=client_ip,
            commit=False,
        )

    # Trusted/operator role update. Web-admin callers must use admin_update_user_role.
    async def update_user_role(
        self,
        user_id: uuid.UUID,
        new_role: str,
    ) -> None:
        if not validate_role(new_role):
            raise ValueError(f"Invalid role: {new_role}. Must be one of: {', '.join(get_all_roles())}")

        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        if conn.in_transaction:
            raise RuntimeError(
                "Role changes cannot run inside an existing transaction."
            )
        cursor = conn.cursor()

        try:
            # Acquire the writer lock before reading the old role so concurrent
            # role changes cannot record a stale "before" value in the audit log.
            conn.execute("BEGIN IMMEDIATE")
            target = self._load_admin_target(cursor, user_id)
            self._update_user_role_in_transaction(
                cursor,
                target=target,
                new_role=new_role,
                actor_user_id=None,
                actor_role=None,
                client_ip=None,
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def admin_update_user_role(
        self,
        user_id: uuid.UUID,
        new_role: str,
        *,
        admin_context: AdminMutationContext,
    ) -> None:
        """Role update authorized against live actor and target state."""
        if not validate_role(new_role):
            raise ValueError(
                f"Invalid role: {new_role}. Must be one of: {', '.join(get_all_roles())}"
            )

        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")
        conn = self.conn
        if conn.in_transaction:
            raise RuntimeError(
                "Role changes cannot run inside an existing transaction."
            )
        cursor = conn.cursor()

        try:
            conn.execute("BEGIN IMMEDIATE")
            actor, target = self._require_live_admin_actor_can_manage(
                cursor,
                admin_context=admin_context,
                target_user_id=user_id,
                action="change roles for",
            )
            self._require_role_can_manage(
                actor_role=actor.role,
                target_role=new_role,
                action="assign roles to",
            )
            self._update_user_role_in_transaction(
                cursor,
                target=target,
                new_role=new_role,
                actor_user_id=actor.id,
                actor_role=actor.role,
                client_ip=admin_context.client_ip,
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def create_session(self, user_id: uuid.UUID) -> UserSession:
        return await persistence_auth.create_session(self, user_id)

    async def get_and_extend_valid_session_by_auth_token(
        self,
        auth_token: str,
        *,
        valid_for: timedelta,
    ) -> tuple[UserSession, AppUser]:
        return await persistence_auth.get_and_extend_valid_session_by_auth_token(
            self,
            auth_token,
            valid_for=valid_for,
        )

    async def invalidate_session(self, auth_token: str) -> None:
        await persistence_auth.invalidate_session(self, auth_token)

    async def get_session_by_auth_token(self, auth_token: str) -> UserSession:
        return await persistence_auth.get_session_by_auth_token(self, auth_token)

    def get_valid_session_by_auth_token(self, auth_token: str) -> tuple[UserSession, AppUser]:
        return persistence_auth.get_valid_session_by_auth_token(self, auth_token)

    def verify_two_factor_challenge(
        self, user_id: uuid.UUID, code: str | None, *, consume_recovery_code: bool = True,
    ) -> persistence_auth.TwoFactorChallengeResult:
        return persistence_auth.verify_two_factor_challenge(
            self, user_id, code, consume_recovery_code=consume_recovery_code,
        )

    def is_2fa_enabled(self, user_id: uuid.UUID) -> bool:
        return persistence_auth.is_2fa_enabled(self, user_id)

    def set_2fa_secret(self, user_id: uuid.UUID, secret: str | None) -> None:
        persistence_auth.set_2fa_secret(self, user_id, secret)

    def disable_two_factor(self, user_id: uuid.UUID, expected_secret: str) -> bool:
        return persistence_auth.disable_two_factor(self, user_id, expected_secret)

    async def invalidate_all_sessions(self, user_id: uuid.UUID) -> None:
        await persistence_auth.invalidate_all_sessions(self, user_id)

    async def update_password(
        self,
        user_id: uuid.UUID,
        new_password: str,
        *,
        acknowledged_weak: bool = False,
    ) -> None:
        await persistence_auth.update_password(
            self,
            user_id,
            new_password,
            acknowledged_weak=acknowledged_weak,
        )

    async def upgrade_user_password_hash(self, user_id: uuid.UUID, password: str) -> AppUser:
        return await persistence_auth.upgrade_user_password_hash(self, user_id, password)

    async def consume_reset_token_and_update_password(
        self,
        token: str,
        user_id: uuid.UUID,
        new_password: str,
        *,
        acknowledged_weak: bool = False,
    ) -> bool:
        return await persistence_auth.consume_reset_token_and_update_password(
            self,
            token,
            user_id,
            new_password,
            acknowledged_weak=acknowledged_weak,
        )

    async def update_notification_preferences(
        self, user_id: uuid.UUID,
        email_notifications_enabled: bool | None = None,
        sms_notifications_enabled: bool | None = None,
    ) -> None:
        await persistence_users.update_notification_preferences(
            self, user_id,
            email_notifications_enabled=email_notifications_enabled,
            sms_notifications_enabled=sms_notifications_enabled,
        )

    async def create_reset_token(self, user_id: uuid.UUID) -> ExpirableVerificationToken:
        return await persistence_auth.create_reset_token(self, user_id)

    async def get_user_by_reset_token(self, token: str) -> AppUser:
        return await persistence_auth.get_user_by_reset_token(self, token)

    async def clear_reset_tokens(self, user_id: uuid.UUID) -> None:
        await persistence_auth.clear_reset_tokens(self, user_id)

    async def set_user_verified(self, user_id: uuid.UUID, is_verified: bool = True) -> None:
        await persistence_auth.set_user_verified(self, user_id, is_verified)

    async def create_email_verification_token(self, user_id: uuid.UUID) -> ExpirableVerificationToken:
        return await persistence_auth.create_email_verification_token(self, user_id)

    async def consume_email_verification_token(self, token: str) -> AppUser:
        return await persistence_auth.consume_email_verification_token(self, token)

    async def clear_email_verification_tokens(self, user_id: uuid.UUID) -> None:
        await persistence_auth.clear_email_verification_tokens(self, user_id)

    # Cross-table delete: auth check + FK-ordered cleanup.
    async def delete_user(
        self,
        user_id: uuid.UUID,
        password: str,
        two_factor_code: str | None = None,
        *,
        auth_token: str,
    ) -> bool:
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")
        conn = self.conn
        self._require_top_level_transaction(
            conn,
            action="Self-service user deletion",
        )
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                user_session, user = self.get_valid_session_by_auth_token(auth_token)
                target = self._load_admin_target(cursor, user_id)
            except KeyError:
                conn.rollback()
                return False
            if user_session.user_id != user_id or user.id != user_id:
                conn.rollback()
                return False
            if user.auth_provider != "password" or not user.verify_password(password):
                conn.rollback()
                return False
            if user.two_factor_enabled:
                result = persistence_auth.verify_two_factor_challenge_in_transaction(
                    self,
                    user_id,
                    two_factor_code,
                )
                if not result.ok:
                    conn.rollback()
                    return False
            self._delete_user_in_transaction(
                cursor,
                target=target,
                actor_user_id=user_id,
                actor_role=target.role,
                client_ip=None,
                metadata={"self_service": True},
            )
            conn.commit()
            return True
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    async def admin_delete_user(
        self,
        user_id: uuid.UUID,
        *,
        admin_context: AdminMutationContext,
    ) -> bool:
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")
        conn = self.conn
        self._require_top_level_transaction(conn, action="Admin user deletion")
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                actor, target = self._require_live_admin_actor_can_manage(
                    cursor,
                    admin_context=admin_context,
                    target_user_id=user_id,
                    action="delete",
                )
            except KeyError:
                conn.rollback()
                return False
            self._delete_user_in_transaction(
                cursor,
                target=target,
                actor_user_id=actor.id,
                actor_role=actor.role,
                client_ip=admin_context.client_ip,
                metadata=None,
            )
            conn.commit()
            return True
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    def _delete_user_in_transaction(
        self,
        cursor: sqlite3.Cursor,
        *,
        target: _AdminTargetSnapshot,
        actor_user_id: uuid.UUID,
        actor_role: str,
        client_ip: str | None,
        metadata: dict[str, t.Any] | None,
    ) -> None:
        uid = str(target.id)
        # Write before the cascade so the target snapshot survives deletion.
        self.record_admin_action(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action="user_delete",
            target_user_id=target.id,
            target_label=target.email,
            before={"email": target.email, "role": target.role},
            after=None,
            metadata=metadata,
            client_ip=client_ip,
            commit=False,
        )
        for table in (
            "user_sessions",
            "password_reset_tokens",
            "oauth_login_handoffs",
            "two_factor_recovery_codes",
            "profiles",
        ):
            cursor.execute(f"DELETE FROM {table} WHERE user_id = ?", (uid,))
        # email_verification_tokens is cleaned up by ON DELETE CASCADE.
        cursor.execute("DELETE FROM users WHERE id = ?", (uid,))
        if cursor.rowcount != 1:
            raise KeyError(target.id)

    async def create_profile(self, user_id: str, full_name: str, email: str,
                           phone: str = None, address: str = None,
                           bio: str = None, avatar_url: str = None) -> dict[str, t.Any]:
        return await persistence_profiles.create_profile(
            self, user_id, full_name, email,
            phone=phone, address=address, bio=bio, avatar_url=avatar_url,
        )

    async def create_profile_for_session(
        self,
        *,
        auth_token: str,
        user_id: str,
        full_name: str,
        email: str,
        phone: str | None = None,
        address: str | None = None,
        bio: str | None = None,
        avatar_url: str | None = None,
    ) -> dict[str, t.Any]:
        """Create a profile after live authorization under the writer lock."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Profile creation")
        cursor = conn.cursor()
        now_ts = datetime.now(timezone.utc).timestamp()

        try:
            conn.execute("BEGIN IMMEDIATE")
            _, target = self._require_live_profile_actor_can_access(
                cursor,
                auth_token=auth_token,
                target_user_id=user_id,
                action="create profiles for",
            )
            canonical_user_id = str(target.id)
            cursor.execute(
                """
                INSERT INTO profiles
                (
                    user_id,
                    full_name,
                    email,
                    phone,
                    address,
                    bio,
                    avatar_url,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    canonical_user_id,
                    full_name,
                    email,
                    phone,
                    address,
                    bio,
                    avatar_url,
                    now_ts,
                    now_ts,
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        profile = await self.get_profile_by_user_id(canonical_user_id)
        if profile is None:
            raise RuntimeError("Created profile could not be reloaded")
        return profile

    async def get_profile(self, profile_id: int) -> dict[str, t.Any] | None:
        return await persistence_profiles.get_profile(self, profile_id)

    async def get_profile_by_user_id(self, user_id: str) -> dict[str, t.Any] | None:
        return await persistence_profiles.get_profile_by_user_id(self, user_id)

    async def get_profile_for_session(
        self,
        *,
        auth_token: str,
        user_id: str,
    ) -> dict[str, t.Any] | None:
        """Read a profile from the same snapshot used to authorize its actor."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Profile reads")
        cursor = conn.cursor()

        try:
            conn.execute("BEGIN")
            _, target = self._require_live_profile_actor_can_access(
                cursor,
                auth_token=auth_token,
                target_user_id=user_id,
                action="view profiles for",
            )
            cursor.execute(
                """
                SELECT id, user_id, full_name, email, phone, address, bio,
                       avatar_url, created_at, updated_at
                FROM profiles
                WHERE user_id = ?
                """,
                (str(target.id),),
            )
            row = cursor.fetchone()
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        if row is None:
            return None
        return persistence_profiles._row_to_profile(row)

    async def get_profiles_for_session(
        self,
        *,
        auth_token: str,
    ) -> list[dict[str, t.Any]]:
        """List only profiles the live privileged actor is allowed to manage."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Profile list reads")
        cursor = conn.cursor()

        try:
            conn.execute("BEGIN")
            try:
                _, actor = self.get_valid_session_by_auth_token(auth_token)
            except KeyError as exc:
                raise AdminSessionInvalidError(
                    "Your session is no longer valid."
                ) from exc
            if not check_access("/app/admin", actor.role):
                raise PermissionError(
                    "Only privileged users can view managed profiles."
                )

            cursor.execute(
                """
                SELECT
                    p.id,
                    p.user_id,
                    p.full_name,
                    p.email,
                    p.phone,
                    p.address,
                    p.bio,
                    p.avatar_url,
                    p.created_at,
                    p.updated_at,
                    u.role
                FROM profiles AS p
                JOIN users AS u ON u.id = p.user_id
                ORDER BY p.created_at DESC
                """
            )
            rows = cursor.fetchall()
            visible_rows = [
                row
                for row in rows
                if str(actor.id) == str(row[1])
                or can_manage_role(actor.role, t.cast(str, row[10]))
            ]
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        return [
            persistence_profiles._row_to_profile(row[:10])
            for row in visible_rows
        ]

    async def update_profile(
        self, user_id: str, full_name: str = None, email: str = None,
        phone: str = None, address: str = None,
        bio: str = None, avatar_url: str = None,
    ) -> dict[str, t.Any] | None:
        return await persistence_profiles.update_profile(
            self, user_id, full_name=full_name, email=email,
            phone=phone, address=address, bio=bio, avatar_url=avatar_url,
        )

    async def update_profile_for_session(
        self,
        *,
        auth_token: str,
        user_id: str,
        full_name: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        address: str | None = None,
        bio: str | None = None,
        avatar_url: str | None = None,
    ) -> dict[str, t.Any] | None:
        """Update a profile after live authorization under the writer lock."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Profile updates")
        cursor = conn.cursor()
        fields: list[str] = []
        params: list[t.Any] = []
        for column, value in (
            ("full_name", full_name),
            ("email", email),
            ("phone", phone),
            ("address", address),
            ("bio", bio),
            ("avatar_url", avatar_url),
        ):
            if value is not None:
                fields.append(f"{column} = ?")
                params.append(value)

        try:
            conn.execute("BEGIN IMMEDIATE")
            _, target = self._require_live_profile_actor_can_access(
                cursor,
                auth_token=auth_token,
                target_user_id=user_id,
                action="edit",
            )
            canonical_user_id = str(target.id)
            if fields:
                fields.append("updated_at = ?")
                params.extend(
                    [datetime.now(timezone.utc).timestamp(), canonical_user_id]
                )
                cursor.execute(
                    f"UPDATE profiles SET {', '.join(fields)} WHERE user_id = ?",
                    params,
                )
                profile_exists = cursor.rowcount == 1
            else:
                cursor.execute(
                    "SELECT 1 FROM profiles WHERE user_id = ?",
                    (canonical_user_id,),
                )
                profile_exists = cursor.fetchone() is not None
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        if not profile_exists:
            return None
        return await self.get_profile_by_user_id(canonical_user_id)

    async def delete_profile(self, user_id: str) -> bool:
        return await persistence_profiles.delete_profile(self, user_id)

    async def delete_profile_for_session(
        self,
        *,
        auth_token: str,
        user_id: str,
    ) -> bool:
        """Delete a profile after live authorization under the writer lock."""
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        self._require_top_level_transaction(conn, action="Profile deletion")
        cursor = conn.cursor()

        try:
            conn.execute("BEGIN IMMEDIATE")
            _, target = self._require_live_profile_actor_can_access(
                cursor,
                auth_token=auth_token,
                target_user_id=user_id,
                action="delete profiles for",
            )
            cursor.execute(
                "DELETE FROM profiles WHERE user_id = ?",
                (str(target.id),),
            )
            deleted = cursor.rowcount == 1
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        return deleted

    async def get_profiles(self) -> list[dict[str, t.Any]]:
        return await persistence_profiles.get_profiles(self)
