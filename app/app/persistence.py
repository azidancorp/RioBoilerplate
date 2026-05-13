import secrets
import sqlite3
import threading
import uuid
import typing as t
from datetime import datetime, timezone
from pathlib import Path

from app.data_models import (
    AppUser,
    UserSession,
    ExpirableVerificationToken,
    CurrencyLedgerEntry,
)
from app.validation import SecuritySanitizer
from app.config import config
from app.permissions import (
    can_manage_role,
    get_default_role,
    get_first_user_role,
    validate_role,
    get_all_roles,
)
from app.rate_limits import RateLimitDecision, RateLimitPolicy
import app.persistence_auth as persistence_auth
import app.persistence_currency as persistence_currency
import app.persistence_profiles as persistence_profiles
import app.persistence_rate_limits as persistence_rate_limits
import app.persistence_social as persistence_social
import app.persistence_users as persistence_users
from app.persistence_schema import initialize_schema


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "app.db"


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
        initialize_schema(self)

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

    def generate_recovery_codes(self, user_id: uuid.UUID, count: int = 10) -> list[str]:
        return persistence_auth.generate_recovery_codes(self, user_id, count=count)

    def get_recovery_codes_summary(self, user_id: uuid.UUID) -> dict[str, t.Any]:
        return persistence_auth.get_recovery_codes_summary(self, user_id)

    def get_user_count(self) -> int:
        return persistence_users.get_user_count(self)

    def has_verified_root_user(self) -> bool:
        cursor = self._get_cursor()
        cursor.execute(
            "SELECT 1 FROM users WHERE role = ? AND is_verified = 1 LIMIT 1",
            (get_first_user_role(),),
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
    def _require_admin_actor_can_manage(
        *,
        actor: AppUser,
        target_role: str,
        action: str,
    ) -> None:
        if not can_manage_role(actor.role, target_role):
            raise PermissionError(
                f"User with role {actor.role} cannot {action} users with role {target_role}."
            )

    # Spans users + profiles + currency ledger; must stay transactional.
    async def create_user(self, user: AppUser) -> None:
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
        cursor = conn.cursor()
        now_ts = datetime.now(timezone.utc).timestamp()
        assigned_role = user.role

        try:
            conn.execute("BEGIN IMMEDIATE")

            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            if (
                user_count == 0
                and assigned_role == get_default_role()
                and config.ALLOW_PUBLIC_ROOT_BOOTSTRAP
            ):
                assigned_role = get_first_user_role()

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

    async def admin_create_user(
        self,
        *,
        email: str,
        password: str,
        role: str,
        actor: AppUser,
        username: str | None = None,
        full_name: str | None = None,
        is_verified: bool = False,
    ) -> AppUser:
        """Create a user from the admin surface without public root bootstrap."""
        if not validate_role(role):
            raise ValueError(
                f"Invalid role: {role}. Must be one of: {', '.join(get_all_roles())}"
            )
        self._require_admin_actor_can_manage(
            actor=actor,
            target_role=role,
            action="create",
        )

        if len((password or "").strip()) < 8:
            raise ValueError("Password must be at least 8 characters.")

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
        cursor = conn.cursor()
        now_ts = datetime.now(timezone.utc).timestamp()

        try:
            conn.execute("BEGIN IMMEDIATE")
            self._insert_user_records(
                cursor,
                user=user,
                assigned_role=role,
                now_ts=now_ts,
                profile_full_name=sanitized_full_name,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

        return await self.get_user_by_id(user.id)

    async def admin_update_user_profile(
        self,
        user_id: uuid.UUID,
        *,
        actor: AppUser,
        email: str | None = None,
        username: str | None = None,
        full_name: str | None = None,
    ) -> AppUser:
        """Update admin-managed identity fields and the matching profile row."""
        current_user = await self.get_user_by_id(user_id)
        self._require_admin_actor_can_manage(
            actor=actor,
            target_role=current_user.role,
            action="edit",
        )
        normalized_email = (
            SecuritySanitizer.validate_email_format(
                email,
                require_valid=config.REQUIRE_VALID_EMAIL,
            )
            if email is not None
            else None
        )
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
        email_changed = (
            normalized_email is not None
            and normalized_email != current_user.email
        )

        if normalized_email is None and username is None and full_name is None:
            return current_user

        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        cursor = conn.cursor()
        now_ts = datetime.now(timezone.utc).timestamp()
        uid = str(user_id)

        try:
            conn.execute("BEGIN IMMEDIATE")
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
                            normalized_email or current_user.email,
                            now_ts,
                            now_ts,
                        ),
                    )

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        return await self.get_user_by_id(user_id)

    async def admin_set_user_active(
        self,
        user_id: uuid.UUID,
        is_active: bool,
        *,
        actor: AppUser,
    ) -> AppUser:
        """Activate or deactivate a user, invalidating sessions on deactivation."""
        current_user = await self.get_user_by_id(user_id)
        self._require_admin_actor_can_manage(
            actor=actor,
            target_role=current_user.role,
            action="update account status for",
        )
        self._ensure_connection()
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")

        conn = self.conn
        cursor = conn.cursor()
        uid = str(user_id)

        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "UPDATE users SET is_active = ? WHERE id = ?",
                (1 if is_active else 0, uid),
            )
            if cursor.rowcount == 0:
                raise KeyError(user_id)

            if not is_active:
                cursor.execute(
                    "DELETE FROM user_sessions WHERE user_id = ?",
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

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        return await self.get_user_by_id(user_id)

    async def admin_issue_password_reset(
        self,
        user_id: uuid.UUID,
        *,
        actor: AppUser,
    ) -> ExpirableVerificationToken:
        """Create a reset token for an active password-authenticated user."""
        user = await self.get_user_by_id(user_id)
        self._require_admin_actor_can_manage(
            actor=actor,
            target_role=user.role,
            action="reset password for",
        )
        if not user.is_active:
            raise ValueError("Cannot issue a password reset for an inactive user.")
        if user.auth_provider != "password":
            raise ValueError("Cannot issue a password reset for an external-auth user.")
        return await self.create_reset_token(user_id)

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
        cursor = conn.cursor()
        now_ts = datetime.now(timezone.utc).timestamp()
        root_role = get_first_user_role()

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
        actor_user_id: uuid.UUID | None = None,
    ) -> CurrencyLedgerEntry:
        return await persistence_currency.adjust_currency_balance(
            self, user_id, delta_minor,
            reason=reason, metadata=metadata, actor_user_id=actor_user_id,
        )

    async def set_currency_balance(
        self,
        user_id: uuid.UUID,
        new_balance_minor: int,
        *,
        reason: str | None = None,
        metadata: dict[str, t.Any] | None = None,
        actor_user_id: uuid.UUID | None = None,
    ) -> CurrencyLedgerEntry:
        return await persistence_currency.set_currency_balance(
            self, user_id, new_balance_minor,
            reason=reason, metadata=metadata, actor_user_id=actor_user_id,
        )

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

    # Updates users + sessions; cross-table write stays on façade.
    async def update_user_role(self, user_id: uuid.UUID, new_role: str) -> None:
        if not validate_role(new_role):
            raise ValueError(f"Invalid role: {new_role}. Must be one of: {', '.join(get_all_roles())}")

        cursor = self._get_cursor()
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

    async def create_session(self, user_id: uuid.UUID) -> UserSession:
        return await persistence_auth.create_session(self, user_id)

    async def update_session_duration(self, session: UserSession, new_valid_until: datetime) -> None:
        await persistence_auth.update_session_duration(self, session, new_valid_until)

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

    async def invalidate_all_sessions(self, user_id: uuid.UUID) -> None:
        await persistence_auth.invalidate_all_sessions(self, user_id)

    async def update_password(self, user_id: uuid.UUID, new_password: str) -> None:
        await persistence_auth.update_password(self, user_id, new_password)

    async def upgrade_user_password_hash(self, user_id: uuid.UUID, password: str) -> AppUser:
        return await persistence_auth.upgrade_user_password_hash(self, user_id, password)

    async def consume_reset_token_and_update_password(
        self,
        token: str,
        user_id: uuid.UUID,
        new_password: str,
    ) -> bool:
        return await persistence_auth.consume_reset_token_and_update_password(
            self,
            token,
            user_id,
            new_password,
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
    async def delete_user(self, user_id: uuid.UUID, password: str, two_factor_code: str | None = None) -> bool:
        try:
            user = await self.get_user_by_id(user_id)
        except KeyError:
            return False

        admin_password = config.ADMIN_DELETION_PASSWORD
        admin_override = bool(
            admin_password and secrets.compare_digest(password, admin_password)
        )

        user_password_valid = False
        if user.auth_provider == "password":
            user_password_valid = user.verify_password(password)

        if not (user_password_valid or admin_override):
            return False

        if user.two_factor_enabled and not admin_override:
            result = self.verify_two_factor_challenge(user_id, two_factor_code)
            if not result.ok:
                return False

        cursor = self._get_cursor()
        uid = str(user_id)
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
        self.conn.commit()
        return True

    async def create_profile(self, user_id: str, full_name: str, email: str,
                           phone: str = None, address: str = None,
                           bio: str = None, avatar_url: str = None) -> dict[str, t.Any]:
        return await persistence_profiles.create_profile(
            self, user_id, full_name, email,
            phone=phone, address=address, bio=bio, avatar_url=avatar_url,
        )

    async def get_profile(self, profile_id: int) -> dict[str, t.Any] | None:
        return await persistence_profiles.get_profile(self, profile_id)

    async def get_profile_by_user_id(self, user_id: str) -> dict[str, t.Any] | None:
        return await persistence_profiles.get_profile_by_user_id(self, user_id)

    async def update_profile(
        self, user_id: str, full_name: str = None, email: str = None,
        phone: str = None, address: str = None,
        bio: str = None, avatar_url: str = None,
    ) -> dict[str, t.Any] | None:
        return await persistence_profiles.update_profile(
            self, user_id, full_name=full_name, email=email,
            phone=phone, address=address, bio=bio, avatar_url=avatar_url,
        )

    async def delete_profile(self, user_id: str) -> bool:
        return await persistence_profiles.delete_profile(self, user_id)

    async def get_profiles(self) -> list[dict[str, t.Any]]:
        return await persistence_profiles.get_profiles(self)
