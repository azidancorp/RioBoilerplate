# Repository Guidance (LLM Agents)

This file is a map of where things live and the “house rules” that prevent breakage. Keep edits small and consistent with existing patterns.

## Project Overview

Rio-based web application boilerplate with user authentication, MFA, mobile-responsive UI, role-based access control, and a virtual currency system. Uses SQLite, FastAPI, and Pydantic v2.

## Where Things Live
- Rio entrypoint + FastAPI bridge: `app/app/__init__.py`
- Routable pages: `app/app/pages/` (public) and `app/app/pages/app_page/` (authenticated `/app/*`)
- Reusable UI components: `app/app/components/`
- Responsive/layout utilities: `app/app/components/responsive.py`
- Navigation + page role mapping: `app/app/navigation.py`
- Role hierarchy + access checks (single source of truth): `app/app/permissions.py`
- Persistence (SQLite, sessions, 2FA, currency ledger): `app/app/persistence.py`
- FastAPI routers + auth deps: `app/app/api/` (notably `app/app/api/auth_dependencies.py`)
- Validation (Pydantic v2 models + sanitizers): `app/app/validation.py`
- Currency helpers + endpoints: `app/app/currency.py`, `app/app/api/currency.py`
- Currency configuration: `app/app/config.py` (`PRIMARY_CURRENCY_*` settings)
- Currency test harness: `app/app/pages/app_page/currency_playground.py`
- Utilities/scripts (2FA + QR tests, admin helpers): `app/app/scripts/`
- Tests (pytest): `app/tests/`
- Prototype HTML/JS pages: `app/JSPages/` (included in `app/rio.toml` project files)
- Docs/playbooks: `README.md`, `DEPLOYMENT_INSTRUCTIONS.md`, `UPSTREAM_MERGE_GUIDE.md`, `RioDocumentation/`

## Run / Test
- Install deps: `python -m venv venv && source venv/bin/activate && pip install -r requirements.txt`
- Run dev server (from outer `app/` containing `rio.toml`): `cd app && rio run`
- Release smoke test (recommended before deployment): `cd app && rio run --port 8000 --release`
- Pytest:
  - From repo root: `pytest`
  - Or from `app/`: `cd app && pytest`

If you changed Rio components/pages, do a quick boot check from `app/` (where `rio.toml` lives), e.g. `cd app && timeout 5 rio run --port 8001` (adjust port as needed).

## Development Rules

- **Refer to `RioDocumentation/`** for Rio component constructors and arguments.
- **Apply `update_layout(template="plotly_dark")`** to all Plotly charts.
- **Never use `children=`** as an argument in Rio components — place components directly.
- **Change only what's required, nothing more.**
- **After modifying any Rio component, run page-level smoke tests:** `pytest app/tests/test_smoke_pages.py -x`. Also run a boot check from the outer `app/` directory using `rio run --port 8XXX` with a 5s timeout to ensure the app boots with correct arguments.
- **Review each component instantiation** against the references in the top-level `RioDocumentation/` folder and align constructor usage exactly with what the docs specify.
- **Any component calling `is_mobile()` must inherit from `ResponsiveComponent`** (enforced by `test_responsive_inheritance.py`).
- **Add new authenticated pages to `APP_ROUTES`** in `app/navigation.py` (not `permissions.py`).
- **Add new public pages to `PUBLIC_NAV_ROUTES`** in `app/navigation.py`.

## Conventions
- Python: 4-space indent, type hints, dataclasses where it fits.
- Naming: modules/functions `snake_case`; Rio component classes `PascalCase`; assets `lowercase-with-hyphens`.
- Rio UI: avoid hidden state mutation inside `build()`; prefer explicit helper methods updating component attributes.
- Rio UI: don’t use `children=` kwargs in component constructors; pass child components directly.
- Responsive UI: any component that directly calls `is_mobile()` should inherit `ResponsiveComponent` (`app/app/components/responsive.py`) so it refreshes across breakpoints.
- Plotly: apply `update_layout(template="plotly_dark")` to Plotly charts for consistent styling.

## Auth, Roles, APIs
- Roles: edit `ROLE_HIERARCHY` in `app/app/permissions.py`; page access is driven by `app/app/navigation.py` (supports wildcard role `"*"`).
- Routes: add new authenticated pages to `APP_ROUTES` and new public pages to `PUBLIC_NAV_ROUTES` in `app/app/navigation.py` (not `app/app/permissions.py`).
- FastAPI auth: endpoints expect `Authorization: Bearer <token>`; dependencies live in `app/app/api/auth_dependencies.py`. Token originates from `UserSettings.auth_token` (Rio client storage).
- Validation: use Pydantic v2 models from `app/app/validation.py` for API payloads; keep sanitization/constraints centralized there.

## Persistence & Currency Gotchas
- SQLite FK enforcement is enabled in `app/app/persistence.py` (`PRAGMA foreign_keys = ON`). Keep multi-step writes transactional.
- Currency invariant: stored balance must match ledger deltas. Relevant tests/docs: `app/tests/test_currency_reconciliation.py`, `app/tests/RECONCILIATION_QUICK_START.md`.
- Currency storage: uses integer minor units with `Decimal` conversion. Config in `app/app/config.py` via `PRIMARY_CURRENCY_*` settings (name, symbol, decimal places, initial balance, allow negative).
- 2FA: prefer the centralized verifier (`Persistence.verify_two_factor_challenge`); regression tests exist in `app/tests/test_two_factor_verification.py`.
- Currency tests: `test_currency_*.py` covers API, persistence, and reconciliation tests.

## Secrets / Config
- Secrets live in untracked `.env` (loaded via `python-dotenv`); use `.env.example` as the starting point.
- App defaults live in `app/app/config.py`. Edit the file directly to customize behavior. Only true secrets (e.g., `ADMIN_DELETION_PASSWORD`) belong in `.env`.
- Non-secret behavior flags must stay code-configured in `app/app/config.py` (for example: email verification requirement/token TTLs and currency display/precision knobs). Do not add non-secret toggles to `.env` or `AppConfig.from_env`.