"""
Application configuration settings.

This module contains configurable settings for the application behavior,
including authentication, validation, and feature toggles.
"""

import os
import sys
from dataclasses import dataclass


@dataclass
class AppConfig:
    """
    Central configuration for application behavior.

    These settings can be modified to change how the application handles
    authentication, validation, and other core features.
    """

    # Public App URL
    # --------------
    # Used when generating password-reset and email-verification links.
    APP_URL: str = "http://localhost:8000"

    # Email Validation Settings
    # -------------------------
    # If True, enforces strict email validation during signup and profile updates.
    # If False, allows any string as an email (useful for username-based apps).
    REQUIRE_VALID_EMAIL: bool = True

    # Authentication Settings
    # -----------------------
    # If True, users can log in using their username in addition to email.
    # This is already supported in the backend via get_user_by_identity().
    ALLOW_USERNAME_LOGIN: bool = False

    # Primary Identifier
    # ------------------
    # Determines which field is the primary identifier for users.
    # Options: "email" or "username"
    # Note: Even if set to "username", email field is still stored but not validated.
    PRIMARY_IDENTIFIER: str = "email"

    # Currency Settings
    # -----------------
    # Primary currency metadata powering balance features. Naming can be overridden per deployment.
    PRIMARY_CURRENCY_NAME: str = "credit"
    PRIMARY_CURRENCY_NAME_PLURAL: str = "credits"
    PRIMARY_CURRENCY_SYMBOL: str = ""
    PRIMARY_CURRENCY_DECIMAL_PLACES: int = 0
    PRIMARY_CURRENCY_INITIAL_BALANCE: int = 0
    PRIMARY_CURRENCY_ALLOW_NEGATIVE: bool = False

    # Email Verification / Password Reset
    # -----------------------------------
    REQUIRE_EMAIL_VERIFICATION: bool = False
    EMAIL_VERIFICATION_TOKEN_TTL_MINUTES: int = 1440  # 24 hours
    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = 30

    # Password Policy
    # ---------------
    MIN_PASSWORD_STRENGTH: int = 50
    # If True, allows weak passwords with user acknowledgement.
    # If False, prohibits signups with weak passwords entirely.
    ALLOW_WEAK_PASSWORDS: bool = True
    # Recovery codes currently use a very long TTL to behave like "backup codes"
    # while still supporting explicit expiry checks in persistence.
    RECOVERY_CODE_TTL_DAYS: int = 36500  # ~100 years; effectively never expires

    # Admin Deletion Password
    # -----------------------
    # REQUIRED for admin user deletion operations. Set via ADMIN_DELETION_PASSWORD env var.
    ADMIN_DELETION_PASSWORD: str = ""

    # Rate Limiting
    # -------------
    # Non-secret behavior knobs. The HMAC secret below is loaded from env.
    RATE_LIMIT_HMAC_SECRET: str = ""
    RATE_LIMIT_BUCKET_GRACE_SECONDS: int = 120
    RATE_LIMIT_EVENT_RETENTION_SECONDS: int = 7 * 24 * 60 * 60
    RATE_LIMIT_LOGIN_IDENTIFIER_ATTEMPTS: int = 5
    RATE_LIMIT_LOGIN_IDENTIFIER_WINDOW_SECONDS: int = 15 * 60
    RATE_LIMIT_LOGIN_IP_ATTEMPTS: int = 30
    RATE_LIMIT_LOGIN_IP_WINDOW_SECONDS: int = 15 * 60
    RATE_LIMIT_MFA_ATTEMPTS: int = 5
    RATE_LIMIT_MFA_WINDOW_SECONDS: int = 10 * 60
    RATE_LIMIT_SIGNUP_IP_ATTEMPTS: int = 5
    RATE_LIMIT_SIGNUP_IP_WINDOW_SECONDS: int = 60 * 60
    RATE_LIMIT_SIGNUP_EMAIL_ATTEMPTS: int = 3
    RATE_LIMIT_SIGNUP_EMAIL_WINDOW_SECONDS: int = 60 * 60
    RATE_LIMIT_VERIFICATION_EMAIL_ATTEMPTS: int = 3
    RATE_LIMIT_VERIFICATION_EMAIL_WINDOW_SECONDS: int = 60 * 60
    RATE_LIMIT_VERIFICATION_IP_ATTEMPTS: int = 10
    RATE_LIMIT_VERIFICATION_IP_WINDOW_SECONDS: int = 60 * 60
    RATE_LIMIT_PASSWORD_RESET_EMAIL_ATTEMPTS: int = 3
    RATE_LIMIT_PASSWORD_RESET_EMAIL_WINDOW_SECONDS: int = 60 * 60
    RATE_LIMIT_PASSWORD_RESET_IP_ATTEMPTS: int = 10
    RATE_LIMIT_PASSWORD_RESET_IP_WINDOW_SECONDS: int = 60 * 60
    RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_ATTEMPTS: int = 20
    RATE_LIMIT_PASSWORD_RESET_COMPLETION_IP_WINDOW_SECONDS: int = 30 * 60
    RATE_LIMIT_PASSWORD_RESET_TOKEN_ATTEMPTS: int = 5
    RATE_LIMIT_PASSWORD_RESET_TOKEN_WINDOW_SECONDS: int = 30 * 60
    RATE_LIMIT_CONTACT_IP_ATTEMPTS: int = 5
    RATE_LIMIT_CONTACT_IP_WINDOW_SECONDS: int = 10 * 60
    RATE_LIMIT_API_AUTH_IP_ATTEMPTS: int = 30
    RATE_LIMIT_API_AUTH_IP_WINDOW_SECONDS: int = 15 * 60
    RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS: int = 5
    RATE_LIMIT_SENSITIVE_ACTION_WINDOW_SECONDS: int = 10 * 60
    RATE_LIMIT_TRUST_PROXY_HEADERS: bool = False
    RATE_LIMIT_TRUSTED_PROXIES: str = "127.0.0.1,::1"

    # External Services
    # -----------------
    # NTFY notification channel (optional, set via env). If not set, contact notifications
    # are disabled. Priority can also be set: RIO_CONTACT_NTFY_PRIORITY=default

    @classmethod
    def from_env(cls) -> "AppConfig":
        """
        Create configuration from environment variables.

        This allows runtime configuration via .env file or system environment.
        """
        return cls(
            ADMIN_DELETION_PASSWORD=os.getenv("ADMIN_DELETION_PASSWORD", ""),
            RATE_LIMIT_HMAC_SECRET=os.getenv("RATE_LIMIT_HMAC_SECRET", ""),
        )


# Global configuration instance — populated from environment variables
config = AppConfig.from_env()

if not config.ADMIN_DELETION_PASSWORD:
    print("WARNING: ADMIN_DELETION_PASSWORD is not set. User deletion operations will be unavailable.", file=sys.stderr)

if not config.RATE_LIMIT_HMAC_SECRET:
    print("WARNING: RATE_LIMIT_HMAC_SECRET is not set. Rate-limit keys will use a development-only fallback.", file=sys.stderr)

if "localhost" in config.APP_URL or "127.0.0.1" in config.APP_URL:
    print("WARNING: APP_URL is set to a localhost address. Password-reset and email-verification links will not work in production. Update APP_URL in config.py before deploying.", file=sys.stderr)
