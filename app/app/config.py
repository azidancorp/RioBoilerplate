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
        )


# Global configuration instance
# You can modify these values directly or use environment variables
# config = AppConfig.from_env() #uncomment this line to use environment variables
config = AppConfig()
