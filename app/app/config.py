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
    # If False, allows non-email identifiers but still applies central length and
    # suspicious-pattern checks in SecuritySanitizer.validate_email_format().
    # Keep this True for current email-based apps. Set it False only for a
    # deliberate future anonymous/identifier-only product, with UI copy,
    # reset/verification flows, duplicate checks, and tests updated together.
    REQUIRE_VALID_EMAIL: bool = True

    # Authentication Settings
    # -----------------------
    # If True, users can log in using their username in addition to email.
    # This only affects lookup fallback for usernames already stored on users.
    # The stock signup UI remains email-first.
    ALLOW_USERNAME_LOGIN: bool = False
    # Enables the Google OAuth/OIDC routes when credentials are configured.
    # Keep this in code so deploy behavior is reviewable; credentials remain env-only.
    ENABLE_GOOGLE_LOGIN: bool = True
    # Signed cookie secret used only for OAuth state/nonce during provider redirects.
    SESSION_SECRET_KEY: str = ""
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    OAUTH_COOKIE_SECURE: bool = False
    OAUTH_HANDOFF_TTL_MINUTES: int = 5

    # Session Lifetime
    # ----------------
    # Sessions use a sliding window (extended on each visit), but that window
    # can otherwise renew forever. This is an absolute ceiling measured from
    # session creation: once exceeded, the session expires regardless of recent
    # activity and the user must re-authenticate. Set to 0 to disable the cap.
    SESSION_ABSOLUTE_MAX_DAYS: int = 30

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

    # Email Delivery
    # --------------
    # Non-secret delivery defaults live here so deployments can review behavior
    # in code. Only credential/secret values are loaded from .env.
    DEFAULT_EMAIL_SENDER: str = "no-reply@rio.local"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USE_TLS: bool = True
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""

    # Contact Notifications
    # ---------------------
    # The ntfy channel can act like a secret destination for contact-message PII,
    # so it is loaded from env. Non-secret display behavior stays code-configured.
    CONTACT_NTFY_CHANNEL: str = ""
    CONTACT_NTFY_PRIORITY: str = "default"

    # Rate Limiting
    # -------------
    # Non-secret behavior knobs.
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

    @classmethod
    def from_env(cls) -> "AppConfig":
        """
        Create configuration with secrets loaded from environment variables.

        Non-secret behavior defaults are intentionally edited in this module.
        """
        return cls(
            SESSION_SECRET_KEY=os.getenv("SESSION_SECRET_KEY", ""),
            GOOGLE_CLIENT_ID=os.getenv("GOOGLE_CLIENT_ID", ""),
            GOOGLE_CLIENT_SECRET=os.getenv("GOOGLE_CLIENT_SECRET", ""),
            SMTP_PASSWORD=os.getenv("RIO_SMTP_PASSWORD", ""),
            CONTACT_NTFY_CHANNEL=os.getenv("RIO_CONTACT_NTFY_CHANNEL", ""),
        )


# Global configuration instance with environment-provided secrets applied.
config = AppConfig.from_env()

if "localhost" in config.APP_URL or "127.0.0.1" in config.APP_URL:
    print("WARNING: APP_URL is set to a localhost address. Password-reset and email-verification links will not work in production. Update APP_URL in config.py before deploying.", file=sys.stderr)
