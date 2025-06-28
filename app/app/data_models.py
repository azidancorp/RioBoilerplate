from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import rio


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
    username: str
    created_at: datetime

    # The hash and salt of the user's password. By storing these values we can
    # verify that a user entered the correct password without storing the actual
    # password in the database. Google "hashing & salting" for details if you're
    # curious.
    password_hash: bytes
    password_salt: bytes
    role: str = 'user'
    is_verified: bool = False
    
    # The referral code used during sign-up (if any)
    referral_code: str = ""

    # The secret key for two-factor authentication, None if not enabled
    two_factor_secret: str | None = None

    @property
    def two_factor_enabled(self) -> bool:
        """Whether two-factor authentication is enabled for this user."""
        return self.two_factor_secret is not None

    @classmethod
    def create_new_user_with_default_settings(cls, username, password, referral_code="") -> AppUser:
        """
        Create a new user with the given username and password, filling in
        reasonable defaults for the other fields.
        
        Parameters:
            username: The username for the new user
            password: The password for the new user
            referral_code: Optional referral code used during sign-up
        """

        password_salt = os.urandom(64)

        return AppUser(
            id=uuid.uuid4(),
            username=username,
            created_at=datetime.now(timezone.utc),
            password_hash=cls.get_password_hash(password, password_salt),
            password_salt=password_salt,
            role='user',
            is_verified=False,
            referral_code=referral_code,
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
        """
        now = datetime.now(timezone.utc)
        return cls(
            code=secrets.token_urlsafe(32),  # 32 bytes = 43 characters
            user_id=user_id,
            created_at=now,
            valid_until=now + timedelta(hours=24)
        )

    @property
    def is_valid(self) -> bool:
        """Whether this reset code is still valid."""
        return datetime.now(timezone.utc) < self.valid_until