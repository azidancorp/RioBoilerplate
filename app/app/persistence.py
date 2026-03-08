import secrets
import sqlite3
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
from app.permissions import get_first_user_role, validate_role, get_all_roles
import app.persistence_auth as persistence_auth
import app.persistence_currency as persistence_currency
import app.persistence_profiles as persistence_profiles
import app.persistence_users as persistence_users
from app.persistence_schema import initialize_schema


class Persistence:
    """Façade for all database operations. Delegates to persistence_* modules."""

    def __init__(
        self,
        db_path: Path = Path(__file__).resolve().parent / "data" / "app.db",
        *,
        allow_username_login: bool = False,
    ) -> None:
        self.db_path = db_path
        self.allow_username_login = allow_username_login
        self.conn = None
        self._ensure_connection()
        initialize_schema(self)

    def _ensure_connection(self) -> None:
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.execute("PRAGMA foreign_keys = ON")

    def _get_cursor(self):
        self._ensure_connection()
        return self.conn.cursor()

    def close(self) -> None:
        if not self.conn:
            return
        try:
            self.conn.close()
        except sqlite3.ProgrammingError:
            pass  # cross-thread teardown; let GC handle it
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

    # Spans users + profiles + currency ledger; must stay transactional.
    async def create_user(self, user: AppUser) -> None:
        if config.REQUIRE_VALID_EMAIL:
            SecuritySanitizer.validate_email_format(user.email, require_valid=True)

        cursor = self._get_cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        if user_count == 0:
            user.role = get_first_user_role()

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

    async def get_user_by_email(self, email: str) -> AppUser:
        return await persistence_users.get_user_by_email(self, email)

    async def get_user_by_username(self, username: str) -> AppUser:
        return await persistence_users.get_user_by_username(self, username)

    async def get_user_by_identity(self, identifier: str) -> AppUser:
        return await persistence_users.get_user_by_identity(self, identifier)

    async def get_user_by_id(self, id: uuid.UUID) -> AppUser:
        return await persistence_users.get_user_by_id(self, id)

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

    async def consume_reset_token(self, token: str, user_id: uuid.UUID) -> bool:
        return await persistence_auth.consume_reset_token(self, token, user_id)

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
        for table in ("user_sessions", "password_reset_tokens", "two_factor_recovery_codes", "profiles"):
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
