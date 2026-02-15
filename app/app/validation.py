"""
Input validation and sanitization utilities for API endpoints.

This module provides Pydantic models for request validation and utilities
for sanitizing user input to prevent security vulnerabilities.
"""

import re
import html
from decimal import Decimal
from typing import Optional, Any, Dict
from uuid import UUID
from pydantic import BaseModel, field_validator, Field, model_validator
from fastapi import HTTPException, status

from app.config import config


# Validation Constants
MAX_STRING_LENGTH = 1000
MAX_NAME_LENGTH = 100
MAX_EMAIL_LENGTH = 254
MAX_PHONE_LENGTH = 20
MAX_ADDRESS_LENGTH = 500
MAX_BIO_LENGTH = 2000
MAX_URL_LENGTH = 2048


class SecuritySanitizer:
    """Utility class for sanitizing user input to prevent security vulnerabilities."""
    
    @staticmethod
    def sanitize_string(value: Optional[str], max_length: int = MAX_STRING_LENGTH) -> Optional[str]:
        """
        Sanitize a string input to prevent XSS and other attacks.
        
        Args:
            value: The string value to sanitize
            max_length: Maximum allowed length for the string
            
        Returns:
            Sanitized string or None if input was None
        """
        if value is None:
            return None
            
        # Convert to string and strip whitespace
        sanitized = str(value).strip()
        
        # Check for empty string after stripping
        if not sanitized:
            return None
            
        # Escape HTML entities to prevent XSS
        sanitized = html.escape(sanitized)
        
        # Remove null bytes and other control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        
        # Check length after sanitization
        if len(sanitized) > max_length:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"String too long. Maximum length is {max_length} characters."
            )
        
        # Check for potential SQL injection patterns (basic detection)
        sql_patterns = [
            r'(union\s+select)', r'(insert\s+into)', r'(delete\s+from)',
            r'(update\s+\w+\s+set)', r'(drop\s+table)', r'(alter\s+table)',
            r'(create\s+table)', r'(exec\s*\()', r'(script\s*>)'
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, sanitized.lower()):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Input contains potentially dangerous content."
                )
        
        return sanitized

    @staticmethod
    def sanitize_auth_code(value: Optional[str], max_length: int = 32) -> Optional[str]:
        """
        Sanitize an authentication code (TOTP or recovery code). Preserves hyphens for
        readability but enforces uppercase alphanumeric characters.
        """
        if value is None:
            return None

        sanitized = str(value).strip()
        if not sanitized:
            return None

        # Remove whitespace and normalise casing
        sanitized = sanitized.replace(" ", "").upper()

        if len(sanitized) > max_length:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Authentication code too long. Maximum length is {max_length} characters."
            )

        allowed_characters = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
        if any(char not in allowed_characters for char in sanitized):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Authentication code contains invalid characters."
            )

        return sanitized
    
    @staticmethod
    def validate_email_format(email: str, require_valid: bool | None = None) -> str:
        """
        Additional email validation beyond Pydantic's EmailStr.
        
        Args:
            email: Email address to validate
            require_valid: If True, enforces strict email validation. If False, only checks
                          for dangerous patterns. If None, uses global config setting.
            
        Returns:
            Validated email address
        """
        # Use global config if not explicitly specified
        if require_valid is None:
            require_valid = config.REQUIRE_VALID_EMAIL
        
        # Basic length check
        if len(email) > MAX_EMAIL_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Email too long. Maximum length is {MAX_EMAIL_LENGTH} characters."
            )
        
        # Only enforce email format validation if required
        if require_valid:
            # Basic email format validation using regex
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, email):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Invalid email format. Must be a valid email address."
                )
        
        # Always check for suspicious patterns (security measure)
        suspicious_patterns = [
            r'javascript:', r'data:', r'vbscript:', r'onload=', r'onerror='
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email.lower()):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Email contains invalid characters or patterns."
                )
        
        return email.lower().strip()
    
    @staticmethod
    def validate_phone_number(phone: Optional[str]) -> Optional[str]:
        """
        Validate and sanitize phone number.
        
        Args:
            phone: Phone number to validate
            
        Returns:
            Validated phone number or None
        """
        if phone is None:
            return None
            
        # Remove whitespace
        phone = phone.strip()
        if not phone:
            return None
            
        # Check length
        if len(phone) > MAX_PHONE_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Phone number too long. Maximum length is {MAX_PHONE_LENGTH} characters."
            )
        
        # Allow only digits, spaces, dashes, parentheses, and plus sign
        if not re.match(r'^[\d\s\-\(\)\+]+$', phone):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Phone number contains invalid characters. Only digits, spaces, dashes, parentheses, and plus sign are allowed."
            )
        
        return phone
    
    @staticmethod
    def validate_url(url: Optional[str]) -> Optional[str]:
        """
        Validate URL format and prevent malicious URLs.
        
        Args:
            url: URL to validate
            
        Returns:
            Validated URL or None
        """
        if url is None:
            return None
            
        url = url.strip()
        if not url:
            return None
            
        # Check length
        if len(url) > MAX_URL_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"URL too long. Maximum length is {MAX_URL_LENGTH} characters."
            )
        
        # Basic URL format validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(url):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid URL format. Must be a valid HTTP or HTTPS URL."
            )
        
        # Check for dangerous protocols
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
        for protocol in dangerous_protocols:
            if url.lower().startswith(protocol):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="URL contains dangerous protocol."
                )
        
        return url


# Pydantic Models for Request Validation


class ProfileCreateRequest(BaseModel):
    """Request model for creating a new user profile."""
    
    user_id: str = Field(..., min_length=1, max_length=50, description="User ID")
    full_name: str = Field(..., min_length=1, max_length=MAX_NAME_LENGTH, description="User's full name")
    email: str = Field(..., min_length=1, description="User's email address or username identifier")
    phone: Optional[str] = Field(None, description="User's phone number")
    address: Optional[str] = Field(None, max_length=MAX_ADDRESS_LENGTH, description="User's address")
    bio: Optional[str] = Field(None, max_length=MAX_BIO_LENGTH, description="User's bio")
    avatar_url: Optional[str] = Field(None, description="URL to user's avatar image")
    
    @field_validator('user_id')
    def validate_user_id(cls, v):
        # User ID should be alphanumeric with underscores and hyphens only
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('User ID can only contain letters, numbers, underscores, and hyphens')
        return SecuritySanitizer.sanitize_string(v, 50)
    
    @field_validator('full_name')
    def validate_full_name(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_NAME_LENGTH)
    
    @field_validator('email')
    def validate_email(cls, v):
        return SecuritySanitizer.validate_email_format(v)
    
    @field_validator('phone')
    def validate_phone(cls, v):
        return SecuritySanitizer.validate_phone_number(v)
    
    @field_validator('address')
    def validate_address(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_ADDRESS_LENGTH)
    
    @field_validator('bio')
    def validate_bio(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_BIO_LENGTH)
    
    @field_validator('avatar_url')
    def validate_avatar_url(cls, v):
        return SecuritySanitizer.validate_url(v)


class ProfileUpdateRequest(BaseModel):
    """Request model for updating an existing user profile."""
    
    full_name: Optional[str] = Field(None, min_length=1, max_length=MAX_NAME_LENGTH, description="New full name")
    email: Optional[str] = Field(None, min_length=1, description="New email address or username identifier")
    phone: Optional[str] = Field(None, description="New phone number")
    address: Optional[str] = Field(None, max_length=MAX_ADDRESS_LENGTH, description="New address")
    bio: Optional[str] = Field(None, max_length=MAX_BIO_LENGTH, description="New bio")
    avatar_url: Optional[str] = Field(None, description="New avatar URL")
    
    @field_validator('full_name')
    def validate_full_name(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_NAME_LENGTH) if v is not None else None
    
    @field_validator('email')
    def validate_email(cls, v):
        return SecuritySanitizer.validate_email_format(v) if v is not None else None
    
    @field_validator('phone')
    def validate_phone(cls, v):
        return SecuritySanitizer.validate_phone_number(v)
    
    @field_validator('address')
    def validate_address(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_ADDRESS_LENGTH) if v is not None else None
    
    @field_validator('bio')
    def validate_bio(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_BIO_LENGTH) if v is not None else None
    
    @field_validator('avatar_url')
    def validate_avatar_url(cls, v):
        return SecuritySanitizer.validate_url(v)


# Response Models for API documentation

class ProfileResponse(BaseModel):
    """Response model for profile data."""
    
    id: int
    user_id: str
    full_name: str
    email: str
    phone: Optional[str]
    address: Optional[str]
    bio: Optional[str]
    avatar_url: Optional[str]
    created_at: float
    updated_at: float


class CurrencyConfigResponse(BaseModel):
    """Expose primary currency configuration values to clients."""

    name: str
    name_plural: str
    symbol: str
    decimal_places: int
    allow_negative: bool


class CurrencyBalanceResponse(BaseModel):
    """Response schema for balance lookups."""

    balance_minor: int
    balance_major: float
    formatted: str
    label: str
    formatted_with_label: str
    updated_at: Optional[float]


class CurrencyLedgerEntryResponse(BaseModel):
    """Ledger entry data shaped for API responses."""

    id: int
    delta_minor: int
    delta_major: float
    delta_formatted: str
    delta_with_label: str
    balance_after_minor: int
    balance_after_major: float
    balance_after_formatted: str
    balance_after_with_label: str
    reason: Optional[str]
    metadata: Optional[Dict[str, Any]]
    actor_user_id: Optional[UUID]
    created_at: float


class CurrencyAdjustmentRequest(BaseModel):
    """Payload for adjusting a user's balance by a delta amount."""

    target_user_id: Optional[UUID] = Field(None, description="Explicit user ID to adjust")
    target_identifier: Optional[str] = Field(
        None,
        description="Email or username fallback if user ID is not provided",
        max_length=MAX_EMAIL_LENGTH,
    )
    amount: Decimal = Field(
        ...,
        description=f"Delta amount in major units (e.g. {config.PRIMARY_CURRENCY_NAME_PLURAL})",
    )
    reason: Optional[str] = Field(None, max_length=200, description="Reason for audit trail")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Optional metadata blob recorded in ledger")

    @model_validator(mode="after")
    def _validate_targets(self) -> "CurrencyAdjustmentRequest":
        if not self.target_user_id and not self.target_identifier:
            raise ValueError("Provide either target_user_id or target_identifier")
        return self

    @field_validator("target_identifier")
    def _sanitize_identifier(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        sanitized = SecuritySanitizer.sanitize_string(value, MAX_EMAIL_LENGTH)
        if sanitized is None:
            raise ValueError("Identifier cannot be empty")
        return sanitized

    @field_validator("reason")
    def _sanitize_reason(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return SecuritySanitizer.sanitize_string(value, 200)

    @field_validator("amount")
    def _validate_amount(cls, value: Decimal) -> Decimal:
        if value == 0:
            raise ValueError("Amount must be non-zero")
        return value


class CurrencySetBalanceRequest(BaseModel):
    """Payload for setting a user's balance to a specific amount."""

    target_user_id: Optional[UUID] = Field(None, description="Explicit user ID")
    target_identifier: Optional[str] = Field(
        None,
        description="Email or username fallback",
        max_length=MAX_EMAIL_LENGTH,
    )
    balance: Decimal = Field(..., description="Desired balance in major units")
    reason: Optional[str] = Field(None, max_length=200)
    metadata: Optional[Dict[str, Any]] = Field(None)

    @model_validator(mode="after")
    def _validate_targets(self) -> "CurrencySetBalanceRequest":
        if not self.target_user_id and not self.target_identifier:
            raise ValueError("Provide either target_user_id or target_identifier")
        return self

    @field_validator("target_identifier")
    def _sanitize_identifier(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        sanitized = SecuritySanitizer.sanitize_string(value, MAX_EMAIL_LENGTH)
        if sanitized is None:
            raise ValueError("Identifier cannot be empty")
        return sanitized

    @field_validator("reason")
    def _sanitize_reason(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return SecuritySanitizer.sanitize_string(value, 200)


