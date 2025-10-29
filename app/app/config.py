"""
Application configuration settings.

This module contains configurable settings for the application behavior,
including authentication, validation, and feature toggles.
"""

import os
from dataclasses import dataclass


@dataclass
class AppConfig:
    """
    Central configuration for application behavior.
    
    These settings can be modified to change how the application handles
    authentication, validation, and other core features.
    """
    
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

    # Password Policy
    # ---------------
    # TODO: Evaluate and tune minimum password strength enforcement for all password updates.
    MIN_PASSWORD_STRENGTH: int = 50

    @classmethod
    def from_env(cls) -> "AppConfig":
        """
        Create configuration from environment variables.
        
        This allows runtime configuration via .env file or system environment.
        """
        return cls(
            REQUIRE_VALID_EMAIL=os.getenv("REQUIRE_VALID_EMAIL", "true").lower() == "true",
            ALLOW_USERNAME_LOGIN=os.getenv("ALLOW_USERNAME_LOGIN", "false").lower() == "true",
            PRIMARY_IDENTIFIER=os.getenv("PRIMARY_IDENTIFIER", "email").lower(),
            PRIMARY_CURRENCY_NAME=os.getenv("RIO_PRIMARY_CURRENCY_NAME", "credit"),
            PRIMARY_CURRENCY_NAME_PLURAL=os.getenv("RIO_PRIMARY_CURRENCY_NAME_PLURAL", "credits"),
            PRIMARY_CURRENCY_SYMBOL=os.getenv("RIO_PRIMARY_CURRENCY_SYMBOL", ""),
            PRIMARY_CURRENCY_DECIMAL_PLACES=int(os.getenv("RIO_PRIMARY_CURRENCY_DECIMAL_PLACES", "0")),
            PRIMARY_CURRENCY_INITIAL_BALANCE=int(os.getenv("RIO_PRIMARY_CURRENCY_INITIAL_BALANCE", "0")),
            PRIMARY_CURRENCY_ALLOW_NEGATIVE=os.getenv("RIO_PRIMARY_CURRENCY_ALLOW_NEGATIVE", "false").lower() == "true",
            MIN_PASSWORD_STRENGTH=int(os.getenv("MIN_PASSWORD_STRENGTH", "50")),
        )


# Global configuration instance
# You can modify these values directly or use environment variables
# config = AppConfig.from_env() #uncomment this line to use environment variables
config = AppConfig()
