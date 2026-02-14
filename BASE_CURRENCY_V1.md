# Base Currency V1 Implementation Plan

This document defines the first iteration of the single primary currency feature that will ship with the Rio boilerplate. The goal is to ensure every user record can track a configurable balance (credits, tokens, remaining days, etc.), expose management surfaces, and keep the feature easy to retheme for downstream SaaS builds.

---

## Objectives
- Store one authoritative numeric balance per user with full CRUD support.
- Make the currency’s name, pluralization, symbol, and precision configurable per deployment.
- Surface the balance in the authenticated UI (dashboard, settings, admin tools) and expose simple APIs/scripts to query and mutate balances.
- Provide guard rails (role checks, ledger history, tests) so downstream teams can trust and extend the feature safely.

---

## Current State & Gaps

### Data & Persistence
- `users` table (`app/app/data/app.db`, schema defined in `app/app/persistence.py`) holds authentication and notification flags but no balance fields.
- No ledger/history table exists, so there is no audit trail for balance changes.
- `AppUser` dataclass in `app/app/data_models.py` mirrors the table columns and will need to carry the new balance fields for session access.
- `Persistence` class already centralizes DB access; it needs new helpers to read/write balances atomically and to manage ledger entries.

### Configuration
- `app/app/config.py` exposes toggles for auth and validation. There is no way to describe product-specific currency naming, decimals, or defaults.
- There is no helper for formatting a balance consistently across UI/API responses.

### API & UI
- FastAPI routers (`app/app/api`) do not mention balances. Admin tooling lives in `app/app/pages/app_page/admin.py` and directly uses `Persistence`, so new actions must plug in there.
- Dashboard (`app/app/pages/app_page/dashboard.py`) and settings (`app/app/pages/app_page/settings.py`) do not surface any usage or balance information.
- Marketing copy (e.g., `app/app/pages/pricing.py`) hard codes “Buzzcoins,” so the name must become dynamic.
- Notifications (`app/app/pages/app_page/notifications.py`) contain copy referencing “synergy tokens” and should adapt to the configured currency.

### Tooling
- No seed or migration scripts set up the new column/table.
- No tests cover balance flows; `app/tests/` is currently empty.

---

## Design Overview

### Domain Model
- **Balance storage**: persist as an integer number of “minor units” (e.g., cents, tokens, days). Precision (decimal places) will be a configurable multiplier so apps can display fractional values when needed.
- **Ledger**: append-only table that captures `user_id`, `delta`, `balance_after`, `reason`, optional JSON metadata, actor, and timestamp to audit changes.
- **Config helper**: central class/utility to expose `currency_name`, `currency_name_plural`, `currency_symbol`, `decimal_places`, `initial_balance`, and derived helpers (display label, formatting).

### Configuration Flow
- Extend `AppConfig` with currency fields. These are hardcoded defaults in `app/app/config.py`—edit the file directly to customize.
- Add a lightweight helper module (e.g., `app/app/currency.py`) that wraps config access, handles pluralization, and formatting (using `decimal.Decimal` for display only).

### Database Changes
- Add columns to `users`:
  - `primary_currency_balance INTEGER NOT NULL DEFAULT 0`
  - `primary_currency_updated_at REAL NOT NULL DEFAULT (strftime('%s','now'))`
- Create `user_currency_ledger` table with FK to `users(id)` and indexes on `user_id` and `created_at`.
- Breaking-change expectation: bumping the schema requires regenerating the SQLite database (drop/reseed) when upgrading pre-1.0 builds.

### Persistence Layer
- Update `_create_user_table`, `_row_to_app_user`, and all `SELECT` statements to include the new columns.
- Add dataclass for ledger rows (e.g., `CurrencyLedgerEntry`) in `app/app/data_models.py`.
- Implement methods in `Persistence`:
  - `get_currency_balance(user_id)` / `get_currency_overview(user_id)`
  - `adjust_currency_balance(user_id, delta, *, reason, metadata, actor_id=None)`
  - `set_currency_balance(user_id, amount, ...)`
  - `list_currency_ledger(user_id, limit=50, before=None, after=None)`
  - Ensure adjustments run inside transactions, update both `users` balance and ledger atomically, and return the new ledger entry.
- Ensure `create_user` seeds `primary_currency_balance` using config’s initial value and writes initial ledger entry if non-zero.

### API Layer
- Introduce a new FastAPI router `app/app/api/currency.py` and register it in `app/app/__init__.py`.
- Planned endpoints:
  - `GET /api/currency/config`: public metadata (names, decimals) for client-side display.
  - `GET /api/currency/balance`: authenticated user’s current balance plus formatted label.
  - `GET /api/currency/ledger`: paginated ledger for the current user; admin/root may pass a `user_id` query param to inspect others.
  - `POST /api/currency/adjust`: admin/root only, accepts Pydantic model with target identifier, delta, reason, metadata.
  - `POST /api/currency/set`: admin/root only, for absolute overrides (uses the same validation).
- Add Pydantic schemas to `app/app/validation.py` for the request/response bodies and shared sanitation (e.g., maximum delta size, reason text length).
- Apply existing role helpers (`app/app/api/auth_dependencies.py`) to enforce access control.

### Rio UI Updates
- **Shared component**: create `app/app/components/currency_summary.py` that renders the balance with icon, handles positive/negative styling, and accepts data + optional admin actions.
- **Navbar / Sidebar**: expose current balance in the authenticated chrome (e.g., add a compact badge when `AppUser.primary_currency_balance` is available).
- **Dashboard** (`app/app/pages/app_page/dashboard.py`):
  - Replace one of the placeholder `DeltaCard`s with a currency-specific card showing the formatted balance and recent change (pulling from ledger or last adjustment).
  - Use config helper to inject the correct currency name.
- **Settings** (`app/app/pages/app_page/settings.py`):
  - Add a “Balance” section showing current amount, last updated timestamp, and (optional) request-top-up CTA linking to support or opening a modal to submit a form.
- **Admin page** (`app/app/pages/app_page/admin.py`):
  - Add balance column to the DataFrame shown in the table.
  - Provide admin controls to grant/deduct currency, along with an inline ledger preview (pull via new persistence methods).
- **Notifications** (`app/app/pages/app_page/notifications.py`) & marketing pages (`app/app/pages/pricing.py`):
  - Replace hard-coded “Buzzcoins” / “synergy tokens” strings with helper calls that use the configured name/plural.

### Tooling & Scripts
- Add CLI script `app/app/scripts/currency_admin.py` with commands to:
  - List balances for all users.
  - Adjust/set balances for a specific user.
  - Export ledger to CSV.
- Optional seed utility to assign demo balances for sample users during local setup.

### Testing
- Create `app/tests/test_currency_persistence.py` covering:
  - Balance retrieval defaults for new/legacy users.
  - Adjustments updating both users table and ledger atomically.
  - Handling of invalid deltas (e.g., overflow, negative balance if not allowed).
- Create `app/tests/test_currency_api.py` for endpoint authorization, validation, and responses.
- Consider lightweight integration test for the admin page action (fast check that persistence methods wire up).

### Documentation & Environment
- Update `README.md` and `DEPLOYMENT_INSTRUCTIONS.md` with:
  - New env vars and defaults.
  - Notes on how to rename the currency for downstream apps.
- Add an entry to `RioDocumentation` summarizing currency helpers for component authors.
- Update `.env.example` (or create one if missing) with currency variables.

---

## Implementation Checklist (Suggested Order)
1. **Config groundwork**
   - Extend `AppConfig` (`app/app/config.py`) with currency fields and environment overrides.
   - Add helper module for display formatting.
2. **Database schema**
   - Implement `_create_currency_tables` in `Persistence`.
3. **Data model updates**
   - Update `AppUser` and add `CurrencyLedgerEntry`.
4. **Persistence methods**
   - Update existing CRUD methods to include the balance.
   - Add adjustment/ledger helpers with thorough docstrings.
5. **API surface**
   - Add new router, schemas, and register routes.
6. **UI integration**
   - Build shared currency component and thread it through navbar, dashboard, settings, admin, notifications, pricing.
7. **Scripts & seeds**
   - Ship admin CLI and sample data script.
8. **Testing**
   - Add pytest coverage for persistence and API, update CI instructions if applicable.
9. **Docs & comms**
   - Refresh README / deployment docs / RioDocumentation.
10. **Manual QA**
   - Stand up a fresh database snapshot and validate balance workflows end-to-end.
   - Smoke test UI on `rio run --release`, ensure balance updates propagate in real time.

---

## Rollout Strategy
- **Pre-deploy**: prepare a fresh database (or wipe existing SQLite files) when rolling the feature into older environments.
- **Deploy**: release code changes with updated configuration defaults; confirm environment variables match desired currency naming.
- **Post-deploy**: verify admin can adjust balances, ledger entries appear, and UI displays correctly. Monitor logs for SQLite constraint errors or missing columns.

---

## Security & Privacy Considerations
- Protect adjustment endpoints with `admin`/`root` role checks (`require_self_or_admin` is insufficient—use explicit privileged role guard).
- Log adjustments via ledger with optional metadata for auditability (actor, reason, request id).
- Sanitize free-form reason/metadata fields to avoid script injection in admin UI.
- Ensure API responses do not leak other users’ balances unless caller has explicit permissions.

---

## Risks & Mitigations
- **Schema drift**: upgrading pre-1.0 installs requires rebuilding the SQLite database; communicate this explicitly in release notes.
- **Race conditions on balance updates**: use `BEGIN IMMEDIATE` transactions and a single UPDATE statement with the new balance to guarantee atomicity.
- **Floating point errors**: store integers internally, only format as decimal on output.
- **UI staleness**: after adjustments, refresh `AppUser` in session or trigger re-fetch to ensure displayed balance matches DB.
- **Config drift**: default to sensible values, document environment variables, and add unit test that config loads as expected.

---

## Open Questions / Next Iterations
- Should negative balances ever be allowed? (Plan ships with overdrafts disabled by default; evaluate per-product.)
- Do we need automated expirations or scheduled deductions (e.g., subscription days countdown)?
- Should ledger store external reference ids (invoice, webhook) for reconciliation?
- Future idea: expose webhook/events when balances change to integrate with billing providers.
