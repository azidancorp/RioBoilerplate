"""
Input validation and sanitization utilities for API endpoints.

This module provides Pydantic models for request validation and utilities
for sanitizing user input to prevent security vulnerabilities.
"""

import re
import html
from typing import Optional
from pydantic import BaseModel, validator, Field
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
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Input contains potentially dangerous content."
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
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Email too long. Maximum length is {MAX_EMAIL_LENGTH} characters."
            )
        
        # Only enforce email format validation if required
        if require_valid:
            # Basic email format validation using regex
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, email):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Invalid email format. Must be a valid email address."
                )
        
        # Always check for suspicious patterns (security measure)
        suspicious_patterns = [
            r'javascript:', r'data:', r'vbscript:', r'onload=', r'onerror='
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email.lower()):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Phone number too long. Maximum length is {MAX_PHONE_LENGTH} characters."
            )
        
        # Allow only digits, spaces, dashes, parentheses, and plus sign
        if not re.match(r'^[\d\s\-\(\)\+]+$', phone):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid URL format. Must be a valid HTTP or HTTPS URL."
            )
        
        # Check for dangerous protocols
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
        for protocol in dangerous_protocols:
            if url.lower().startswith(protocol):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
    
    @validator('user_id')
    def validate_user_id(cls, v):
        # User ID should be alphanumeric with underscores and hyphens only
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('User ID can only contain letters, numbers, underscores, and hyphens')
        return SecuritySanitizer.sanitize_string(v, 50)
    
    @validator('full_name')
    def validate_full_name(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_NAME_LENGTH)
    
    @validator('email')
    def validate_email(cls, v):
        return SecuritySanitizer.validate_email_format(v)
    
    @validator('phone')
    def validate_phone(cls, v):
        return SecuritySanitizer.validate_phone_number(v)
    
    @validator('address')
    def validate_address(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_ADDRESS_LENGTH)
    
    @validator('bio')
    def validate_bio(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_BIO_LENGTH)
    
    @validator('avatar_url')
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
    
    @validator('full_name')
    def validate_full_name(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_NAME_LENGTH) if v is not None else None
    
    @validator('email')
    def validate_email(cls, v):
        return SecuritySanitizer.validate_email_format(v) if v is not None else None
    
    @validator('phone')
    def validate_phone(cls, v):
        return SecuritySanitizer.validate_phone_number(v)
    
    @validator('address')
    def validate_address(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_ADDRESS_LENGTH) if v is not None else None
    
    @validator('bio')
    def validate_bio(cls, v):
        return SecuritySanitizer.sanitize_string(v, MAX_BIO_LENGTH) if v is not None else None
    
    @validator('avatar_url')
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




