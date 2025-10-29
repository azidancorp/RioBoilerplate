# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rio-based web application boilerplate built on the authentication template. It provides a comprehensive starter template for building production-ready web applications with user authentication, MFA support, and a complete component architecture.

## Key Architecture Components

**Authentication System**: Uses SQLite-based persistence with session tokens stored client-side. The authentication flow involves:
- `Persistence` class (`app/persistence.py`) - Handles all database operations including profiles
- `UserSession` and `AppUser` models (`app/data_models.py`) - Core data structures
- Session validation in `on_session_start()` (`app/__init__.py`) - Auto-login via stored tokens
- MFA support with TOTP using `pyotp` library (secrets stored in database)
- Role-based access control with hierarchical permissions (root > admin > user)
- Referral code support for user onboarding

**Component Structure**:
- `RootComponent` - Always-visible wrapper containing navbar, footer, and page content
- Pages organized in `app/pages/` with nested structure for authenticated areas (`app_page/`)
- Reusable components in `app/components/` including navbar, sidebar, footer
- FastAPI integration with routers in `app/api/`

**Data Layer**:
- Single SQLite database (`app.db`) in `app/data/` directory containing all application data
- Profiles table integrated into the main app database (consolidated from separate profiles.db)
- CSV data files for charts/analytics

## Development Commands

**Running the application**:
```bash
# Navigate to app directory
cd app

# Run development server
rio run
```

**Environment Setup**:
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

## Important Development Rules

From `.windsurfrules`:
- Always refer to Rio documentation for component constructors and arguments
- Apply `update_layout(template='plotly_dark')` to all Plotly charts
- Never use "children" as argument in Rio components - place components directly
- Change only what's required, nothing more

## Key Files and Patterns

**App Initialization** (`app/__init__.py`):
- Sets up persistence layer and attaches to all sessions
- Handles automatic session validation and user login
- Configures FastAPI routers and themes

**Database Models** (`app/data_models.py`):
- `AppUser` - User account with password hashing and MFA support
- `UserSession` - Authentication sessions with expiration
- `UserSettings` - Client-side stored settings including auth tokens

**Authentication Flow**:
1. Users authenticate via login page
2. Session token stored in `UserSettings` (client-side)
3. `on_session_start()` validates token and attaches user info
4. Protected pages use Rio's guard mechanism

**Component Architecture**:
- Root component contains navbar, page view, and footer
- Authenticated pages nested under `app_page/`
- Sidebar navigation for authenticated users
- Responsive design with theme support (light/dark)

## Database Schema

The application uses SQLite with these main tables in `app.db`:
- `users` - User accounts with password hashes, MFA secrets, roles, referral codes
- `user_sessions` - Authentication sessions with expiration and role information
- `password_reset_codes` - Temporary password reset tokens
- `profiles` - User profile information (id, user_id, full_name, email, phone, address, bio, avatar_url, created_at, updated_at)

Profile Management:
- One-to-one mapping between users and profiles
- Automatic profile creation when new users register
- Profile data integrated into main app database for consistency
- Foreign key constraints ensure data integrity

## Dependencies

Core dependencies include:
- `rio-ui` - Main framework
- `qrcode[pil]`, `pillow` - QR code generation for MFA
- `pyotp` - TOTP implementation for 2FA
- `numpy`, `pandas`, `plotly`, `matplotlib` - Data visualization
- `fastapi` - API framework for REST endpoints
- `pydantic` - Data validation and settings management
- `python-dotenv` - Environment variable management

## Security Features

**Input Validation & Sanitization** (`app/validation.py`):
- Comprehensive SecuritySanitizer class preventing XSS, SQL injection, and control character attacks
- Email, phone, and URL validation with length restrictions
- Pydantic models for API request validation with automatic sanitization

**Administrative Security**:
- Environment variable `ADMIN_DELETION_PASSWORD` required for user deletion operations
- Role-based permissions system with hierarchical access control (root > admin > user)
- First registered user automatically gets root privileges

**Authentication Security**:
- Session management with automatic expiration
- 2FA integration with database-stored secrets
- Password strength validation and automatic session invalidation on changes
- Secure password reset flow with time-limited codes

**API Security**:
- All endpoints include input validation and sanitization
- Proper HTTP status codes and error handling
- SQLite integrity constraint handling

## Role Management & Customization

**Centralized Role System** (`app/permissions.py`):
The application uses a fully centralized role management system where **all role definitions** live in a single file: `app/permissions.py`. This is the **single source of truth** for roles throughout the entire application.

**Key Principle**: To customize roles for your application, you only need to edit the `ROLE_HIERARCHY` dictionary in `permissions.py`. All other components automatically adapt to your role definitions.

**Role Hierarchy**:
```python
# In app/permissions.py
ROLE_HIERARCHY = {
    "root": 1,    # Highest privilege (lowest number)
    "admin": 2,   # Medium privilege
    "user": 3     # Lowest privilege (highest number)
}
```

**Customization Example**:
To create a custom role hierarchy for your application (e.g., a forum):
```python
ROLE_HIERARCHY = {
    "owner": 1,
    "moderator": 2,
    "member": 3,
    "guest": 4
}
```

**Helper Functions Available**:
- `get_all_roles()` - Returns list of all valid roles
- `get_default_role()` - Returns the default role for new users (lowest privilege)
- `get_first_user_role()` - Returns role for first registered user (highest privilege)
- `get_highest_privilege_role()` - Returns the highest privilege role name
- `get_manageable_roles(user_role)` - Returns roles that a user can manage
- `validate_role(role)` - Checks if a role is valid
- `is_privileged_role(role, min_level)` - Checks if role meets privilege threshold
- `can_manage_role(manager_role, target_role)` - Permission checks for role changes
- `get_role_level(role)` - Returns hierarchy level number

**Components Using Centralized Roles**:
- `app/data_models.py` - Default role for new AppUser instances
- `app/persistence.py` - Database operations, first user assignment, role validation
- `app/pages/app_page/admin.py` - Role dropdown dynamically generated from manageable roles
- `app/components/sidebar.py` - Link visibility based on highest privilege role
- `app/api/auth_dependencies.py` - Privilege checks without hardcoded role names

**Page Access Control**:
Page-level permissions are defined in `PAGE_ROLE_MAPPING` (also in `permissions.py`):
```python
PAGE_ROLE_MAPPING = {
    "/app/dashboard": ["root", "admin", "user"],
    "/app/admin": ["root", "admin"],
    "/app/news": ["root", "admin"],
    ...
}
```

Update these mappings when you customize your roles. The highest privilege role automatically has access to all pages.

**Role Validation**:
- All role changes are validated against `ROLE_HIERARCHY` in the persistence layer
- Invalid roles are rejected with helpful error messages
- Database schema stores roles as TEXT for flexibility

**Best Practices**:
1. Always use helper functions instead of hardcoding role names
2. Use privilege level checks (`is_privileged_role()`) instead of exact role matches
3. Update `PAGE_ROLE_MAPPING` when adding new protected pages
4. Keep the hierarchy numbering consistent (lower = higher privilege)

## Configuration (`app/config.py`)

The application uses a centralized configuration system that can be controlled via the `AppConfig` class or environment variables:

**Email Validation Settings**:
- `REQUIRE_VALID_EMAIL` (default: `True`) - Controls whether strict email format validation is enforced
  - `True`: Enforces RFC-compliant email validation in both frontend and backend
  - `False`: Allows any string as email (useful for username-based apps)
  - Environment variable: `REQUIRE_VALID_EMAIL=true|false`
  - **Security Note**: Even when disabled, XSS and injection patterns are still blocked

**Authentication Settings**:
- `ALLOW_USERNAME_LOGIN` (default: `False`) - Enables username-based login in addition to email
  - Environment variable: `ALLOW_USERNAME_LOGIN=true|false`
  - Works with `get_user_by_identity()` method in Persistence class

**Primary Identifier**:
- `PRIMARY_IDENTIFIER` (default: `"email"`) - Indicates which field is the primary user identifier
  - Options: `"email"` or `"username"`
  - Environment variable: `PRIMARY_IDENTIFIER=email|username`

**Configuration Methods**:
```python
# Direct modification (for hardcoded settings)
from app.config import config
config.REQUIRE_VALID_EMAIL = False

# Environment variable (recommended for deployment)
# In .env file:
REQUIRE_VALID_EMAIL=false
ALLOW_USERNAME_LOGIN=true
```

**Defense-in-Depth Validation**:
Email validation is enforced at multiple layers when `REQUIRE_VALID_EMAIL=True`:
1. **Frontend**: Real-time validation in `SignUpForm.validate_email()` (app/pages/login.py:294)
2. **Form Submission**: Pre-submission check in `on_sign_up_pressed()` (app/pages/login.py:229)
3. **Backend**: Database-level validation in `Persistence.create_user()` (app/persistence.py:228)
4. **API Layer**: Pydantic model validation in API endpoints (app/validation.py:163)

This multi-layer approach ensures email validation cannot be bypassed even if users manipulate client-side code or directly call APIs.

## Environment Variables

Required environment variables (see `.env.example`):
- `ADMIN_DELETION_PASSWORD` - Secure password for administrative user deletion operations
- `REQUIRE_VALID_EMAIL` - Enable/disable strict email validation (default: `true`)
- `ALLOW_USERNAME_LOGIN` - Enable username-based login (default: `false`)
- `PRIMARY_IDENTIFIER` - Primary user identifier type: `email` or `username` (default: `email`)

## API Documentation

**Profile Management API** (`app/api/profiles.py`):
- `GET /api/profile` - Get all user profiles
- `GET /api/profile/{user_id}` - Get specific user profile
- `POST /api/profile` - Create new user profile
- `PUT /api/profile/{user_id}` - Update user profile
- `DELETE /api/profile/{user_id}` - Delete user profile

**Request/Response Models** (`app/validation.py`):
- `ProfileCreateRequest` - Validation for profile creation
- `ProfileUpdateRequest` - Validation for profile updates
- `ProfileResponse` - Standardized profile response format

**API Security Features**:
- Input validation and sanitization using Pydantic models
- SQL injection protection with parameterized queries
- XSS prevention through HTML escaping
- Length validation and control character filtering
- Comprehensive error handling with appropriate HTTP status codes
- Database integrity constraint handling

## Security Implementation Details

**Input Validation & Sanitization** (`app/validation.py`):
- `SecuritySanitizer` class with comprehensive validation methods
- Length limits: Names (100), Email (254), Phone (20), Address (500), Bio (2000), URL (2048)
- Pattern matching for SQL injection prevention
- HTML entity escaping for XSS protection
- Control character removal (null bytes, etc.)
- Email format validation with suspicious pattern detection
- Phone number validation (digits, spaces, dashes, parentheses, plus only)
- URL validation with protocol security checks

**Database Context Management**:
- `Persistence` class implements context manager pattern (`__enter__`/`__exit__`)
- Automatic connection management and cleanup
- Proper cursor handling with connection verification

## File Structure Notes

- `app/app/` contains the main application code
- `RioDocumentation/` contains extensive Rio framework reference docs
- Static assets in `app/assets/`
- Database files in `app/data/` (consolidated into single app.db)
- API endpoints in `app/api/`
- Security utilities in `app/validation.py`
- Permission management in `app/permissions.py`

---

 # Using Gemini CLI for Large Codebase Analysis

  When analyzing large codebases or multiple files that might exceed context limits, use the Gemini CLI with its massive
  context window. Use `gemini -p` to leverage Google Gemini's large context capacity.

  ## File and Directory Inclusion Syntax

  Use the `@` syntax to include files and directories in your Gemini prompts. The paths should be relative to WHERE you run the
   gemini command:

  ### Examples:

  **Single file analysis:**
  ```bash
  gemini -p "@src/main.py Explain this file's purpose and structure"

  Multiple files:
  gemini -p "@package.json @src/index.js Analyze the dependencies used in the code"

  Entire directory:
  gemini -p "@src/ Summarize the architecture of this codebase"

  Multiple directories:
  gemini -p "@src/ @tests/ Analyze test coverage for the source code"

  Current directory and subdirectories:
  gemini -p "@./ Give me an overview of this entire project"

#
 Or use --all_files flag:
  gemini --all_files -p "Analyze the project structure and dependencies"

  Implementation Verification Examples

  Check if a feature is implemented:
  gemini -p "@src/ @lib/ Has dark mode been implemented in this codebase? Show me the relevant files and functions"

  Verify authentication implementation:
  gemini -p "@src/ @middleware/ Is JWT authentication implemented? List all auth-related endpoints and middleware"

  Check for specific patterns:
  gemini -p "@src/ Are there any React hooks that handle WebSocket connections? List them with file paths"

  Verify error handling:
  gemini -p "@src/ @api/ Is proper error handling implemented for all API endpoints? Show examples of try-catch blocks"

  Check for rate limiting:
  gemini -p "@backend/ @middleware/ Is rate limiting implemented for the API? Show the implementation details"

  Verify caching strategy:
  gemini -p "@src/ @lib/ @services/ Is Redis caching implemented? List all cache-related functions and their usage"

  Check for specific security measures:
  gemini -p "@src/ @api/ Are SQL injection protections implemented? Show how user inputs are sanitized"

  Verify test coverage for features:
  gemini -p "@src/payment/ @tests/ Is the payment processing module fully tested? List all test cases"

  When to Use Gemini CLI

  Use gemini -p when:
  - Analyzing entire codebases or large directories
  - Comparing multiple large files
  - Need to understand project-wide patterns or architecture
  - Current context window is insufficient for the task
  - Working with files totaling more than 100KB
  - Verifying if specific features, patterns, or security measures are implemented
  - Checking for the presence of certain coding patterns across the entire codebase

  Important Notes

  - Paths in @ syntax are relative to your current working directory when invoking gemini
  - The CLI will include file contents directly in the context
  - No need for --yolo flag for read-only analysis
  - Gemini's context window can handle entire codebases that would overflow Claude's context
  - When checking implementations, be specific about what you're looking for to get accurate results # Using Gemini CLI for Large Codebase Analysis


  When analyzing large codebases or multiple files that might exceed context limits, use the Gemini CLI with its massive
  context window. Use `gemini -p` to leverage Google Gemini's large context capacity.


  ## File and Directory Inclusion Syntax


  Use the `@` syntax to include files and directories in your Gemini prompts. The paths should be relative to WHERE you run the
   gemini command:


  ### Examples:


  **Single file analysis:**
  ```bash
  gemini -p "@src/main.py Explain this file's purpose and structure"


  Multiple files:
  gemini -p "@package.json @src/index.js Analyze the dependencies used in the code"


  Entire directory:
  gemini -p "@src/ Summarize the architecture of this codebase"


  Multiple directories:
  gemini -p "@src/ @tests/ Analyze test coverage for the source code"


  Current directory and subdirectories:
  gemini -p "@./ Give me an overview of this entire project"
  # Or use --all_files flag:
  gemini --all_files -p "Analyze the project structure and dependencies"


  Implementation Verification Examples


  Check if a feature is implemented:
  gemini -p "@src/ @lib/ Has dark mode been implemented in this codebase? Show me the relevant files and functions"


  Verify authentication implementation:
  gemini -p "@src/ @middleware/ Is JWT authentication implemented? List all auth-related endpoints and middleware"


  Check for specific patterns:
  gemini -p "@src/ Are there any React hooks that handle WebSocket connections? List them with file paths"


  Verify error handling:
  gemini -p "@src/ @api/ Is proper error handling implemented for all API endpoints? Show examples of try-catch blocks"


  Check for rate limiting:
  gemini -p "@backend/ @middleware/ Is rate limiting implemented for the API? Show the implementation details"


  Verify caching strategy:
  gemini -p "@src/ @lib/ @services/ Is Redis caching implemented? List all cache-related functions and their usage"


  Check for specific security measures:
  gemini -p "@src/ @api/ Are SQL injection protections implemented? Show how user inputs are sanitized"


  Verify test coverage for features:
  gemini -p "@src/payment/ @tests/ Is the payment processing module fully tested? List all test cases"


  When to Use Gemini CLI


  Use gemini -p when:
  - Analyzing entire codebases or large directories
  - Comparing multiple large files
  - Need to understand project-wide patterns or architecture
  - Current context window is insufficient for the task
  - Working with files totaling more than 100KB
  - Verifying if specific features, patterns, or security measures are implemented
  - Checking for the presence of certain coding patterns across the entire codebase


  Important Notes


  - Paths in @ syntax are relative to your current working directory when invoking gemini
  - The CLI will include file contents directly in the context
  - No need for --yolo flag for read-only analysis
  - Gemini's context window can handle entire codebases that would overflow Claude's context
  - When checking implementations, be specific about what you're looking for to get accurate results

  If you have made any changes to the rio frontend, then smoke test using `rio run --port 8XXX` from the first app directory that contains rio.toml - with a 5s timeout, and then fix errors until it runs fine.
