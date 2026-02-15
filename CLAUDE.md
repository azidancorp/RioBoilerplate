# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rio-based web application boilerplate with user authentication, MFA, mobile-responsive UI, role-based access control, and a virtual currency system. Uses SQLite, FastAPI, and Pydantic v2.

## Development Commands

```bash
cd app && rio run                # Run dev server (must run from app/ where rio.toml lives)
cd app && rio run --port 8XXX    # Smoke test after modifying any frontend component
# Verify app boots without errors within ~5 seconds

pytest                           # Run tests (from root or app/ directory)
```

## Important Development Rules

- Refer to `RioDocumentation/` for Rio component constructors and arguments
- Apply `update_layout(template='plotly_dark')` to all Plotly charts
- Never use "children" as argument in Rio components - place components directly
- Change only what's required, nothing more
- After modifying any Rio component, run a smoke test from the outer `app/` directory (where `rio.toml` resides) using `rio run --port 8XXX` with a 5s timeout to ensure the app boots with correct arguments
- Review each component instantiation against the references in the top-level `RioDocumentation/` folder and align constructor usage exactly with what the docs specify
- Any component calling `is_mobile()` **must** inherit from `ResponsiveComponent` (enforced by `test_responsive_inheritance.py`)
- Add new authenticated pages to `APP_ROUTES` in `app/navigation.py` (not `permissions.py`)
- Add new public pages to `PUBLIC_NAV_ROUTES` in `app/navigation.py`

## Conventions

- Python: 4-space indent, type hints, dataclasses where it fits
- Naming: modules/functions `snake_case`; Rio components `PascalCase`; assets `lowercase-with-hyphens`
- Rio UI: avoid hidden state mutation inside `build()`; prefer explicit helper methods updating component attributes
- SQLite: FK enforcement is on (`PRAGMA foreign_keys = ON` in `persistence.py`); keep multi-step writes transactional
- Currency invariant: stored balance must always match sum of ledger deltas (tested by `test_currency_reconciliation.py`)
- 2FA: use the centralized verifier `Persistence.verify_two_factor_challenge`; don't duplicate verification logic

## Architecture Overview

### Centralized Navigation (`app/navigation.py`)
Single source of truth for all routes. Defines `AppRoute` (authenticated, with roles + sidebar metadata) and `PublicNavRoute` (public pages). `permissions.py` derives `PAGE_ROLE_MAPPING` automatically via `get_page_role_mapping()`. Route validation runs at import time.

### Responsive Design (`app/components/responsive.py`)
`ResponsiveComponent` base class detects mobile/desktop breakpoint crossings (rebuilds only on threshold crossing, not every pixel). Constants: `MOBILE_BREAKPOINT=40`, width presets (`WIDTH_NARROW=30` for auth, `WIDTH_COMFORTABLE=70` for forms/content, `WIDTH_FULL=90` for dashboards), `MOBILE_CONTENT_WIDTH_PERCENT=95` (default for `CenterComponent.mobile_width_percent`). `CenterComponent` provides transitive responsive refresh for children.

### Authentication Flow
1. Login via email (username fallback if `ALLOW_USERNAME_LOGIN=true`) using `get_user_by_identity()`
2. If 2FA enabled, verify TOTP or recovery code
3. Session token stored client-side in `UserSettings`
4. `on_session_start()` validates token, attaches user info (7-day sessions)
5. Protected pages guarded via `check_access()` in `permissions.py`

### Role System (`app/permissions.py`)
Hierarchical roles defined in `ROLE_HIERARCHY` dict (lower number = higher privilege). Default: root(1) > admin(2) > user(3). Edit only this dict to customize. Use helper functions (`get_manageable_roles()`, `can_manage_role()`, `is_privileged_role()`, `check_access()`) instead of hardcoding role names.

### Component Architecture
- `RootComponent` - App shell: navbar + drawer (mobile) / sidebar (desktop) + footer
- `CenterComponent` - Responsive centering wrapper
- `PublicNav` - Mobile drawer nav for logged-out users
- Desktop: sidebar inline + navbar with currency balance
- Mobile: hamburger menu + drawer (Sidebar if logged in, PublicNav if not), drawer auto-closes on navigation

### Currency System (`app/currency.py`, `app/api/currency.py`)
Configurable virtual currency (credits/tokens/points). Config in `app/config.py`. API endpoints: `GET /api/currency/{config,balance,ledger}`, `POST /api/currency/{adjust,set}` (admin only). Uses integer minor units with `Decimal` conversion. Test harness at `app/pages/app_page/currency_playground.py`.

## Database Models (`app/data_models.py`)

- `AppUser` - User account with password hashing, MFA support, currency balance properties
- `UserSession` - Authentication sessions with expiration
- `UserSettings` - Client-side stored settings including auth tokens
- `PasswordResetCode` - 24-hour temporary reset codes
- `RecoveryCodeRecord` - 2FA backup code metadata (total, remaining, last_generated)
- `RecoveryCodeUsage` - Session-scoped tracking for recovery code consumption
- `CurrencyLedgerEntry` - Transaction history record
- `Profile` - User profile information

## Database Schema

The application uses SQLite with these main tables in `app.db`:
- `users` - User accounts with password hashes, MFA secrets, roles, referral codes
- `user_sessions` - Authentication sessions with expiration and role information
- `password_reset_codes` - Temporary password reset tokens
- `profiles` - User profile information (id, user_id, full_name, email, phone, address, bio, avatar_url, created_at, updated_at)
- `currency_balances` - User currency balance tracking (user_id, balance_minor, updated_at)
- `currency_ledger` - Transaction history (id, user_id, delta, balance_after, reason, metadata, actor_user_id, created_at)

Profile Management:
- One-to-one mapping between users and profiles
- Automatic profile creation when new users register
- Profile data integrated into main app database for consistency
- Foreign key constraints ensure data integrity

## Key Files

| File | Purpose |
|------|---------|
| `app/__init__.py` | App setup, session management, router registration |
| `app/navigation.py` | Route definitions (single source of truth) |
| `app/permissions.py` | Role hierarchy, `PAGE_ROLE_MAPPING`, access checks |
| `app/persistence.py` | SQLite operations, user/session/currency CRUD |
| `app/data_models.py` | `AppUser`, `UserSession`, `UserSettings`, `Profile`, `RecoveryCodeRecord`, `CurrencyLedgerEntry` |
| `app/config.py` | `AppConfig` - edit file directly to customize |
| `app/validation.py` | `SecuritySanitizer`, Pydantic v2 request/response models |
| `app/currency.py` | Currency formatting and conversion utilities |
| `app/theme.py` | Light/dark theme definitions (HSV-based) |
| `app/components/responsive.py` | `ResponsiveComponent` base class, breakpoints, width presets |
| `app/components/root_component.py` | App shell with responsive drawer support |
| `app/components/navbar.py` | Responsive navbar with hamburger toggle |
| `app/components/sidebar.py` | Role-filtered sidebar (driven by `navigation.py`) |
| `app/components/center_component.py` | Responsive centering wrapper |
| `app/components/public_nav.py` | Mobile drawer nav for logged-out users |
| `app/scripts/utils.py` | `load_from_html()` for inlining CSS/JS into HTML pages |

## Configuration (`app/config.py`)

Key settings (hardcoded in `config.py`, edit file directly):
- `REQUIRE_VALID_EMAIL` (default: `True`) - strict email validation (multi-layer: frontend, form, backend, API)
- `ALLOW_USERNAME_LOGIN` (default: `False`) - enable username-based login
- `PRIMARY_IDENTIFIER` (default: `"email"`) - `"email"` or `"username"`
- `PRIMARY_CURRENCY_*` - currency name, symbol, decimal places, initial balance, allow negative
- `MIN_PASSWORD_STRENGTH` (default: 50)

Secrets (set via `.env`):
- `ADMIN_DELETION_PASSWORD` - required for user deletion operations

## Security

- `SecuritySanitizer` in `app/validation.py` handles XSS, SQL injection, control characters, length limits
- `sanitize_auth_code()` for TOTP/recovery code input
- Pydantic v2 models for all API request validation
- Parameterized SQL queries throughout `persistence.py`
- 2FA with recovery codes (generation, consumption, regeneration)
- Password strength validation with real-time feedback

## API Endpoints

- `GET/POST/PUT/DELETE /api/profile[/{user_id}]` - Profile CRUD
- `GET /api/currency/{config,balance,ledger}` - Currency reads
- `POST /api/currency/{adjust,set}` - Currency writes (admin only)
- `GET /api/test` - Health check
- `POST /api/contact` - Contact form

## Testing

Tests in `app/tests/` (both root and `app/` have `conftest.py` for `sys.path`):
- `test_navigation.py` - navigation/permissions integration consistency
- `test_responsive_inheritance.py` - AST-based enforcement of `ResponsiveComponent` inheritance
- `test_two_factor_verification.py` - 2FA verification flow regression
- `test_currency_*.py` - Currency API, persistence, and reconciliation

## Pages

**Public**: `home.py` (landing), `about.py`, `faq.py`, `pricing.py`, `contact.py`, `login.py` (login/signup/2FA)

**Authenticated** (`app/pages/app_page/`): `dashboard.py`, `admin.py` (user/role/currency management), `settings.py` (profile/password/2FA/account), `news.py`, `notifications.py`, `enable_mfa.py`, `disable_mfa.py`, `recovery_codes.py`, `currency_playground.py` (currency QA harness)

## Dependencies

`rio-ui==0.10.9`, `qrcode[pil]`, `pillow`, `pyotp`, `pydantic[email]`, `python-dotenv`, `numpy`, `pandas`, `plotly`, `matplotlib`, `requests`, `pytest`, `httpx`

## File Structure

```
app/
├── app/                    # Main application code
│   ├── api/                # FastAPI routers (auth_dependencies, currency, example, profiles)
│   ├── components/         # UI components (responsive, root, navbar, sidebar, center, public_nav, footer, etc.)
│   ├── pages/              # Public pages + app_page/ (authenticated pages behind guard)
│   ├── scripts/            # Utilities (HTML inlining, currency admin, datagen)
│   ├── navigation.py, permissions.py, persistence.py, config.py, data_models.py, validation.py, currency.py, theme.py
├── assets/, data/, JSPages/
├── tests/                  # Test suite
├── conftest.py, rio.toml
conftest.py                 # Root-level pytest config
requirements.txt
RioDocumentation/           # Rio framework reference docs
```
