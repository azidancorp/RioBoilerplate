from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import typing as t
import rio
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
    Model for data stored client-side for each user.
    """

    # The (possibly expired) authentication token for this user. If this matches
    # the id of any valid `UserSession`, it is safe to consider the user as
    # authenticated being in that session.
    #
    # This prevents users from having to log-in again each time the page is
    # accessed.
    auth_token: str
    
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
    auth_provider: str = "password"
    auth_provider_id: str | None = None
    role: str = get_default_role()  # Dynamically set from permissions.ROLE_HIERARCHY
    is_verified: bool = False

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

        password_salt = os.urandom(64)

        return AppUser(
            id=uuid.uuid4(),
            email=email.lower().strip(),
            username=username,
            created_at=datetime.now(timezone.utc),
        password_hash=cls.get_password_hash(password, password_salt),
        password_salt=password_salt,
        auth_provider="password",
        role=get_default_role(),
        is_verified=False,
        referral_code=referral_code,
        primary_currency_balance=get_currency_config().initial_balance,
        primary_currency_updated_at=datetime.now(timezone.utc),
    )

    @classmethod
    def get_password_hash(cls, password, password_salt: bytes) -> bytes:
        """
        Compute the hash of a password using a given salt.
        """
        return hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=password_salt,
            iterations=100000,
        )

    def verify_password(self, password: str) -> bool:
        """
        Safely compare a password to the stored hash. This differs slightly from
        the `==` operator in that it is resistant to timing attacks.
        """
        if self.password_hash is None or self.password_salt is None:
            return False
        if self.auth_provider != "password":
            return False
        return secrets.compare_digest(
            self.password_hash,
            self.get_password_hash(password, self.password_salt),
        )


@dataclass
class PasswordResetCode:
    """
    Model for password reset codes. These are temporary codes that allow users
    to reset their password.
    """

    code: str
    user_id: uuid.UUID
    created_at: datetime
    valid_until: datetime

    @classmethod
    def create_new_reset_code(cls, user_id: uuid.UUID) -> PasswordResetCode:
        """
        Create a new reset code for a user that is valid for 24 hours.

        Reset codes are short-lived numeric tokens intended for one-time use.
        """
        now = datetime.now(timezone.utc)
        numeric_code = f"{secrets.randbelow(1_000_000):06d}"
        return cls(
            code=numeric_code,
            user_id=user_id,
            created_at=now,
            valid_until=now + timedelta(hours=24)
        )

    @property
    def is_valid(self) -> bool:
        """Whether this reset code is still valid."""
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
