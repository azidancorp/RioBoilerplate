# Primary Currency System

Rio Boilerplate now includes a first-class, per-user currency with configurable naming, precision, and admin tools.

## Configuration
- `RIO_PRIMARY_CURRENCY_NAME` / `_PLURAL`: singular/plural labels used across UI components and API responses.
- `RIO_PRIMARY_CURRENCY_SYMBOL`: optional prefix (e.g. `$`).
- `RIO_PRIMARY_CURRENCY_DECIMAL_PLACES`: stored precision (0 for whole units).
- `RIO_PRIMARY_CURRENCY_INITIAL_BALANCE`: starting balance assigned to new accounts.
- `RIO_PRIMARY_CURRENCY_ALLOW_NEGATIVE`: defaults to `false`; enable to allow overdrafts.

All settings live in `app/app/config.py` and can be overridden via environment variables.

## Database Schema
- `users.primary_currency_balance` stores the balance as an integer number of minor units.
- `users.primary_currency_updated_at` records the last update timestamp.
- `user_currency_ledger` is an append-only table providing a full audit trail (`delta`, `balance_after`, `reason`, optional `metadata`).


## Persistence Helpers
`app/app/persistence.py` now exposes:
- `get_currency_overview(user_id)` → balance, formatted string, last updated time.
- `adjust_currency_balance(user_id, delta_minor, reason, metadata)` → atomic delta update plus ledger entry.
- `set_currency_balance(user_id, new_balance_minor, reason, metadata)` → absolute override.
- `list_currency_ledger(user_id, limit, before, after)` → paginated ledger history.

## API Surface
FastAPI provides:
- `GET /api/currency/config` – metadata for client-side formatting.
- `GET /api/currency/balance` – authenticated user's balance.
- `GET /api/currency/ledger` – history (admin/root can view other users).
- `POST /api/currency/adjust` – admin/root delta updates.
- `POST /api/currency/set` – admin/root absolute overrides.

## UI Integrations
- Navbar/sidebar badges expose the current balance after login.
- Dashboard and Settings pages include a `CurrencySummary` card.
- Admin screen offers balance adjustments with success/error feedback in-line.
- Notifications and pricing pages source currency names dynamically.

## CLI Utilities
`python app/app/scripts/currency_admin.py` supports balance inspection (`list`), history (`ledger`), and state changes (`adjust`, `set`).

## Testing
See `app/tests/test_currency_persistence.py` and `app/tests/test_currency_api.py` for reference integration tests that exercise persistence and endpoint behaviour.
