# Email Validation Configuration Guide

## Overview

The application now supports configurable email validation through a centralized configuration system. This allows you to toggle between strict email validation (for email-based apps) and relaxed validation (for username-based apps).

## Configuration Location

All settings are defined in `app/app/config.py` in the `AppConfig` class.

## Available Settings

### 1. `REQUIRE_VALID_EMAIL` (Default: `True`)

Controls whether strict email format validation is enforced.

- **`True`**: Enforces RFC-compliant email format validation
  - Email must match pattern: `user@domain.tld`
  - Validates in both frontend (real-time) and backend (on submit)
  - Prevents users from signing up with invalid emails
  
- **`False`**: Relaxed validation (only checks for dangerous patterns)
  - Allows any string as an email/identifier
  - Still blocks XSS patterns like `javascript:`, `data:`, etc.
  - Useful for username-based authentication systems

### 2. `ALLOW_USERNAME_LOGIN` (Default: `False`)

Enables username-based login in addition to email.

- **`True`**: Users can log in with either email or username
- **`False`**: Users can only log in with email

### 3. `PRIMARY_IDENTIFIER` (Default: `"email"`)

Defines the primary identifier for users.

- **`"email"`**: Email is the main identifier
- **`"username"`**: Username is the main identifier

## How to Configure

### Method 1: Direct Code Modification

Edit `app/app/config.py`:

```python
@dataclass
class AppConfig:
    REQUIRE_VALID_EMAIL: bool = False  # Change to False to allow any string
    ALLOW_USERNAME_LOGIN: bool = True  # Enable username login
    PRIMARY_IDENTIFIER: str = "username"  # Use username as primary
```

### Method 2: Environment Variables (Recommended)

Create a `.env` file in the project root:

```env
REQUIRE_VALID_EMAIL=false
ALLOW_USERNAME_LOGIN=true
PRIMARY_IDENTIFIER=username
```

Then load it in your application startup (requires `python-dotenv`):

```python
from dotenv import load_dotenv
load_dotenv()

from app.config import AppConfig
config = AppConfig.from_env()
```

## Validation Flow

### Frontend Validation (Real-time)
Located in `app/app/pages/login.py` → `SignUpForm.validate_email()`

- Runs as the user types in the email field
- Updates the "Email is valid" indicator
- Respects `config.REQUIRE_VALID_EMAIL` setting

### Backend Validation (On Submit)
Located in `app/app/pages/login.py` → `SignUpForm.on_sign_up_pressed()`

- Runs when user clicks "Sign up" button
- **Critical security checkpoint** - prevents invalid data from reaching the database
- Enforces validation if `config.REQUIRE_VALID_EMAIL = True`
- Shows error banner if validation fails

### API/Profile Validation
Located in `app/app/validation.py` → `SecuritySanitizer.validate_email_format()`

- Used by Pydantic models for API endpoints
- Can be called with explicit `require_valid` parameter
- Falls back to global config if not specified

## Use Cases

### Use Case 1: Traditional Email-Based App
```python
# config.py
REQUIRE_VALID_EMAIL = True
ALLOW_USERNAME_LOGIN = False
PRIMARY_IDENTIFIER = "email"
```

**Result**: Users must provide valid email addresses. Strict validation enforced.

### Use Case 2: Username-Based App (like Discord/Reddit)
```python
# config.py
REQUIRE_VALID_EMAIL = False
ALLOW_USERNAME_LOGIN = True
PRIMARY_IDENTIFIER = "username"
```

**Result**: Users can sign up with any identifier. Email field becomes optional/flexible.

### Use Case 3: Hybrid System
```python
# config.py
REQUIRE_VALID_EMAIL = True
ALLOW_USERNAME_LOGIN = True
PRIMARY_IDENTIFIER = "email"
```

**Result**: Users must provide valid emails but can log in with either email or username.

## Security Considerations

### Always Enforced (Regardless of Config)

Even with `REQUIRE_VALID_EMAIL = False`, the following security checks are **always active**:

1. **Length validation**: Max 254 characters
2. **Dangerous pattern detection**: Blocks `javascript:`, `data:`, `vbscript:`, `onload=`, `onerror=`
3. **XSS prevention**: HTML escaping in sanitization
4. **SQL injection prevention**: Pattern detection in all inputs

### Important Notes

- Setting `REQUIRE_VALID_EMAIL = False` does **not** disable all validation
- It only relaxes the email format requirement
- Security-critical checks remain active
- The email field is still stored in the database

## Testing Your Configuration

### Test with Valid Email
```
Email: user@example.com
Expected: ✅ Passes with both True/False
```

### Test with Invalid Email (Username-like)
```
Email: john_doe_123
Expected: 
- REQUIRE_VALID_EMAIL = True  → ❌ Fails validation
- REQUIRE_VALID_EMAIL = False → ✅ Passes validation
```

### Test with Dangerous Pattern
```
Email: javascript:alert(1)
Expected: ❌ Always fails (security block)
```

## Migration Guide

### Converting from Email-Based to Username-Based

1. **Update config**:
   ```python
   REQUIRE_VALID_EMAIL = False
   PRIMARY_IDENTIFIER = "username"
   ```

2. **Update UI labels** in `app/app/pages/login.py`:
   ```python
   # Change "Email" to "Username"
   rio.TextInput(label="Username", ...)
   ```

3. **Update validation messages**:
   ```python
   self.error_message = "Invalid username. Please try again."
   ```

4. **Existing users**: No database migration needed - the email field remains but accepts any string

## Troubleshooting

### Issue: Validation still enforced after setting to False
**Solution**: Restart the Rio server (`rio run`) to reload the config module

### Issue: Environment variables not working
**Solution**: Ensure `python-dotenv` is installed and `load_dotenv()` is called before importing config

### Issue: Users can't sign up with valid emails
**Solution**: Check that `REQUIRE_VALID_EMAIL = True` and the email matches the regex pattern

## Code References

- **Config**: `app/app/config.py`
- **Validation Logic**: `app/app/validation.py` (line 82-127)
- **Frontend Validation**: `app/app/pages/login.py` (line 294-308)
- **Backend Validation**: `app/app/pages/login.py` (line 229-237)
- **Pydantic Models**: `app/app/validation.py` (line 209-285)
