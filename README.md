# Rio Boilerplate

Production-ready Rio web application template featuring session-based authentication, optional TOTP multi-factor security, FastAPI endpoints, and a reusable component library.

## Highlights
- Auth & security: login, password reset, role-based guards, MFA toggles, recovery codes, admin-only operations.
- API layer: FastAPI routers for profile data, shared validation in `app/app/validation.py`, persistence helpers for SQLite.
- UI experience: Rio pages for public marketing routes and protected app area, shared layout elements, Plotly/Matplotlib chart support.
- Built-in primary currency system with configurable naming, precision, admin tooling, and ledger history.
- Developer ergonomics: Example scripts, bundled Rio documentation, and deployment playbooks for quick onboarding.

## Using as a Template

There are two ways to use this boilerplate:

### Option A: Clone (simple, no upstream updates)
```bash
git clone git@github.com:azidancorp/RioBoilerplate.git my-project
cd my-project
rm -rf .git && git init  # Start fresh git history
```

### Option B: Add as Remote (recommended - enables upstream updates)

If you already have a git project and want to pull in this boilerplate while keeping the ability to get future updates:

```bash
# From your existing project directory
git remote add boilerplate git@github.com:azidancorp/RioBoilerplate.git
git fetch boilerplate
git merge boilerplate/main --allow-unrelated-histories -m "Merge RioBoilerplate template"
```

This merges the boilerplate into your project. Later, to pull updates:
```bash
git fetch boilerplate
git merge boilerplate/main
```

For detailed merge instructions and conflict resolution, see `UPSTREAM_MERGE_GUIDE.md`.

## Quick Start
1. Set up the boilerplate using Option A or B above.
2. Create and activate a virtual environment: `python -m venv venv` then `source venv/bin/activate` (or `venv\Scripts\activate` on Windows).
3. Install dependencies: `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` and set secrets such as `ADMIN_DELETION_PASSWORD`.
5. Run the app from `app/`: `rio run`. The first registered user is promoted to the `root` role.
6. On first run, the app creates a local SQLite database at `app/app/data/app.db`. This file is ignored by git and should remain a local runtime artifact.

Access the dev server at `http://localhost:8000`. Use `rio run --port 8000 --release` to mirror production settings.

## Everyday Development
- `rio run` – hot-reloading dev server.
- `rio run --port 8000 --release` – release-mode smoke test.

## Configuration
- `.env` is for secrets only. In the stock boilerplate, the main secret is `ADMIN_DELETION_PASSWORD`.
- Non-secret behavior stays code-configured in `app/app/config.py`. Edit that file directly for app-specific defaults such as email validation, username login, password policy, and currency naming/precision.
- The runtime SQLite database file `app/app/data/app.db` is created locally on first run and is ignored by git.

## Currency System
- SQLite schema stores a single minor-unit balance per user plus an audited `user_currency_ledger`.
- Admin UI (`/app/admin`) now surfaces balances, allows grants/deductions, and shows success/error feedback.
- FastAPI endpoints (`/api/currency/*`) expose balance, ledger, and privileged adjustment APIs.
- CLI helper `python app/app/scripts/currency_admin.py` supports `list`, `ledger`, `adjust`, and `set` operations from the terminal.


## Project Layout
```text
RioBoilerplate/
├── app/
│   ├── rio.toml               # Rio app configuration
│   ├── JSPages/               # Prototype HTML/JS demos
│   └── app/
│       ├── __init__.py        # App bootstrap + FastAPI bridge
│       ├── api/               # FastAPI routers (profiles, examples)
│       ├── assets/            # Static assets
│       ├── components/        # Reusable Rio UI widgets
│       ├── data/              # Runtime SQLite DB (local/ignored) and sample data
│       ├── pages/             # Public pages
│       │   └── app_page/      # Protected app pages
│       ├── scripts/           # Utilities and MFA helper scripts
│       ├── permissions.py     # Role checks and guard helpers
│       ├── persistence.py     # Database access layer
│       └── validation.py      # Input validation & Pydantic models
├── RioDocumentation/          # Bundled Rio reference material
├── DEPLOYMENT_INSTRUCTIONS.md # Production rollout guide
├── requirements.txt
└── README.md
```

## Testing & QA
Focus release verification on:
- Registration, login, and role-based routing.
- Enabling/disabling MFA and using recovery codes.
- Profile CRUD via the UI and `/api/profiles`.
- Error handling across contact flows and API responses.
- Currency adjustments: verify admin operations, ledger history, and `/api/currency/*` behaviour (positive & negative paths).

## Further Reading
- `AGENTS.md` – contributor workflow and coding standards.
- `CLAUDE.md` – extended architecture and assistant notes.
- `DEPLOYMENT_INSTRUCTIONS.md` – step-by-step deployment guidance.
- `RioDocumentation/` – offline Rio framework reference.

## License
Distributed under the terms of the included `LICENSE`.
