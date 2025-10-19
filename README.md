# Rio Boilerplate

Production-ready Rio web application template featuring session-based authentication, optional TOTP multi-factor security, FastAPI endpoints, and a reusable component library.

## Highlights
- Auth & security: login, password reset, role-based guards, MFA toggles, recovery codes, admin-only operations.
- API layer: FastAPI routers for profile data, shared validation in `app/app/validation.py`, persistence helpers for SQLite.
- UI experience: Rio pages for public marketing routes and protected app area, shared layout elements, Plotly/Matplotlib chart support.
- Developer ergonomics: Example scripts, bundled Rio documentation, and deployment playbooks for quick onboarding.

## Quick Start
1. Clone the repository and enter the project directory.
2. Create and activate a virtual environment: `python -m venv venv` then `source venv/bin/activate` (or `venv\Scripts\activate` on Windows).
3. Install dependencies: `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` and set secrets such as `ADMIN_DELETION_PASSWORD`.
5. Run the app from `app/`: `rio run`. The first registered user is promoted to the `root` role.

Access the dev server at `http://localhost:8000`. Use `rio run --port 8000 --release` to mirror production settings.

## Everyday Development
- `rio run` – hot-reloading dev server.
- `rio run --port 8000 --release` – release-mode smoke test.

## Configuration
- Environment variables live in `.env`. Common toggles: `ADMIN_DELETION_PASSWORD`, `REQUIRE_VALID_EMAIL`, `ALLOW_USERNAME_LOGIN`, `PRIMARY_IDENTIFIER`.
- Runtime defaults live in `app/app/config.py`; adjust there for build-time overrides.


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
│       ├── data/              # SQLite database and dummy data
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

Capture additional coverage with pytest modules in `app/tests/`.

## Further Reading
- `AGENTS.md` – contributor workflow and coding standards.
- `CLAUDE.md` – extended architecture and assistant notes.
- `DEPLOYMENT_INSTRUCTIONS.md` – step-by-step deployment guidance.
- `RioDocumentation/` – offline Rio framework reference.

## License
Distributed under the terms of the included `LICENSE`.
