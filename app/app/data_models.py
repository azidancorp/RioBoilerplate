from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import typing as t
import rio
from app import passwords as password_utils
from app.permissions import get_default_role
from app.currency import (
    get_currency_config,
    format_minor_amount,
    get_major_amount,
    attach_currency_name,
)


@dataclass
class UserSettings(rio.UserSettings):
    """
    Model for data persisted on the user's device by Rio.
    """

    # The (possibly expired) authentication token for this user. If this matches
    # the id of any valid `UserSession`, it is safe to consider the user as
    # authenticated being in that session.
    #
    # This prevents users from having to log-in again each time the page is
    # accessed.
    # Keep the bearer credential out of JavaScript-readable local storage.
    auth_token: rio.HttpOnly[str]
    
    # Whether 2FA is enabled for this user
    two_factor_enabled: bool = False


@dataclass
class UserSession:
    # This ID uniquely identifies the session. It also serves as the
    # authentication token for the user.
    id: str
    user_id: uuid.UUID
    created_at: datetime
    valid_until: datetime
    role: str


@dataclass
class AppUser:
    """
    Model for a user of the application.
    """
    id: uuid.UUID
    email: str
    username: str | None
    created_at: datetime

    # The hash and salt of the user's password. By storing these values we can
    # verify that a user entered the correct password without storing the actual
    # password in the database. Google "hashing & salting" for details if you're
    # curious.
    password_hash: bytes | None
    password_salt: bytes | None
    password_scheme: str = password_utils.HASH_SCHEME_PBKDF2_SHA256
    auth_provider: str = "password"
    auth_provider_id: str | None = None
    role: str = get_default_role()  # Dynamically set from permissions.ROLE_HIERARCHY
    is_verified: bool = False
    is_active: bool = True

    # The referral code used during sign-up (if any)
    referral_code: str = ""

    # The secret key for two-factor authentication, None if not enabled
    two_factor_secret: str | None = None

    # Notification preferences
    email_notifications_enabled: bool = True
    sms_notifications_enabled: bool = False
    primary_currency_balance: int = get_currency_config().initial_balance
    primary_currency_updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def two_factor_enabled(self) -> bool:
        """Whether two-factor authentication is enabled for this user."""
        return bool(self.two_factor_secret)

    @property
    def primary_currency_balance_major(self) -> float:
        """Balance in major units for display (float for UI convenience)."""
        return float(get_major_amount(self.primary_currency_balance))

    @property
    def primary_currency_formatted(self) -> str:
        """Formatted balance string using configured symbol/precision."""
        return format_minor_amount(self.primary_currency_balance)

    @property
    def primary_currency_formatted_with_label(self) -> str:
        """Formatted balance string that includes the currency label."""
        return attach_currency_name(
            self.primary_currency_formatted,
            quantity_minor_units=self.primary_currency_balance,
        )

    @classmethod
    def create_new_user_with_default_settings(
        cls,
        email: str,
        password: str,
        username: str | None = None,
        referral_code: str = "",
    ) -> AppUser:
        """
        Create a new user with the given email and password, filling in
        reasonable defaults for the other fields.
        
        Parameters:
            email: The email address for the new user. Acts as the primary identifier.
            password: The password for the new user
            username: Optional username/handle for the user
            referral_code: Optional referral code used during sign-up
        """

        password_hash, password_salt, password_scheme = password_utils.hash_password(password)

        return AppUser(
            id=uuid.uuid4(),
            email=email.lower().strip(),
            username=username,
            created_at=datetime.now(timezone.utc),
            password_hash=password_hash,
            password_salt=password_salt,
            password_scheme=password_scheme,
            auth_provider="password",
            role=get_default_role(),
            is_verified=False,
            referral_code=referral_code,
            primary_currency_balance=get_currency_config().initial_balance,
            primary_currency_updated_at=datetime.now(timezone.utc),
        )

    @classmethod
    def create_social_user(
        cls,
        *,
        email: str,
        provider: str,
        provider_user_id: str,
        username: str | None = None,
        is_verified: bool = True,
    ) -> AppUser:
        """
        Create a user authenticated by an external identity provider.
        """
        return AppUser(
            id=uuid.uuid4(),
            email=email.lower().strip(),
            username=username,
            created_at=datetime.now(timezone.utc),
            password_hash=None,
            password_salt=None,
            password_scheme=password_utils.HASH_SCHEME_PBKDF2_SHA256,
            auth_provider=provider,
            auth_provider_id=provider_user_id,
            role=get_default_role(),
            is_verified=is_verified,
            referral_code="",
            primary_currency_balance=get_currency_config().initial_balance,
            primary_currency_updated_at=datetime.now(timezone.utc),
        )

    @classmethod
    def get_password_hash(cls, password, password_salt: bytes) -> bytes:
        """
        Compute the hash of a password using a given salt.
        """
        return password_utils.legacy_pbkdf2_password_hash(password, password_salt)

    def verify_password_result(
        self,
        password: str,
    ) -> password_utils.PasswordVerificationResult:
        if self.auth_provider != "password":
            return password_utils.PasswordVerificationResult(ok=False)
        return password_utils.verify_password(
            password,
            self.password_hash,
            self.password_salt,
            self.password_scheme,
        )

    def verify_password(self, password: str) -> bool:
        """
        Safely compare a password to the stored hash. This differs slightly from
        the `==` operator in that it is resistant to timing attacks.
        """
        return self.verify_password_result(password).ok


@dataclass
class ExpirableVerificationToken:
    """
    Shared one-time token model for password-reset and email-verification flows.
    """

    token: str
    user_id: uuid.UUID
    created_at: datetime
    valid_until: datetime

    @classmethod
    def create(
        cls,
        user_id: uuid.UUID,
        valid_for: timedelta,
    ) -> ExpirableVerificationToken:
        now = datetime.now(timezone.utc)
        return cls(
            token=uuid.uuid4().hex.upper(),
            user_id=user_id,
            created_at=now,
            valid_until=now + valid_for,
        )

    @property
    def is_valid(self) -> bool:
        """Whether this token is still valid."""
        return datetime.now(timezone.utc) < self.valid_until


@dataclass
class RecoveryCodeRecord:
    """
    Metadata describing a stored two-factor recovery code without revealing the
    underlying secret.
    """

    id: int
    user_id: uuid.UUID
    created_at: datetime
    used_at: datetime | None


@dataclass
class RecoveryCodeUsage:
    """
    Session-scoped flags indicating whether backup codes were recently used.
    """

    used_at_login: bool = False
    used_in_settings: bool = False


@dataclass
class CurrencyLedgerEntry:
    """Record describing a single currency adjustment for a user."""

    id: int
    user_id: uuid.UUID
    delta: int
    balance_after: int
    reason: str | None
    metadata: dict[str, t.Any] | None
    actor_user_id: uuid.UUID | None
    created_at: datetime


@dataclass
class Profile:
    """
    Model for user profile information.

    This stores additional user information beyond authentication data,
    such as display names, contact details, and bio information.
    """
    id: int
    user_id: uuid.UUID
    full_name: str | None
    email: str | None
    phone: str | None
    address: str | None
    bio: str | None
    avatar_url: str | None
    created_at: datetime
    updated_at: datetime
