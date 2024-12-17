from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import rio
import pyotp


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

    # The user this session belongs to
    user_id: uuid.UUID

    # When this session was initially created
    created_at: datetime

    # Until when this session is valid
    valid_until: datetime

    # The role of the user in this session
    role: str


@dataclass
class AppUser:
    """
    Model for a user of the application.
    """

    # A unique identifier for this user
    id: uuid.UUID

    # The user's chosen username
    username: str

    # When the user account was created
    created_at: datetime

    # The hash and salt of the user's password. By storing these values we can
    # verify that a user entered the correct password without storing the actual
    # password in the database. Google "hashing & salting" for details if you're
    # curious.
    password_hash: bytes
    password_salt: bytes

    # The role of the user (e.g., 'admin', 'user')
    role: str = 'user'

    # Whether the user's account has been verified
    is_verified: bool = False

    # The secret key for two-factor authentication, None if not enabled
    two_factor_secret: str | None = None

    @property
    def two_factor_enabled(self) -> bool:
        """Whether two-factor authentication is enabled for this user."""
        return self.two_factor_secret is not None

    @classmethod
    def create_new_user_with_default_settings(cls, username, password) -> AppUser:
        """
        Create a new user with the given username and password, filling in
        reasonable defaults for the other fields.
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