# Repository Guidelines

## Project Structure & Module Organization
The Rio app lives in `app/app`. `pages/` registers routeable components via `@rio.page`; `components/` contains reusable UI widgets; `scripts/` stores helpers such as HTML loaders and OTP utilities; `data/` and `assets/` house seed content and static files. Authentication and persistence glue sits in `permissions.py` and `persistence.py`. Prototype HTML/JS lives in `app/JSPages`. Reference material and deployment playbooks are in `RioDocumentation/` and `DEPLOYMENT_INSTRUCTIONS.md`. Manage dependencies through `requirements.txt`; keep the committed `venv/` aligned with that file.

## Build, Test, and Development Commands
Create a clean environment with `python -m venv venv && source venv/bin/activate` (or `venv\\Scripts\\activate` on Windows) and install deps via `pip install -r requirements.txt`. From the outer `app/` directory (the first one containing `rio.toml`), run `rio run` for the auto-reloading dev server. Use `rio run --port 8000 --release` from that same directory to mirror production, especially before deployment. Utility scripts like `server_sync.py` and `split_documentation.py` help sync assets and docs when packaging.

## Coding Style & Naming Conventions
Use 4-space indentation, type hints, and dataclass-friendly patterns (`app/pages/home.py`). Modules, dirs, and functions are snake_case; Rio component classes are `PascalCase`. Keep asset filenames lowercase-with-hyphens. Document any non-obvious script with a short docstring explaining its side effects. Avoid inline state mutation inside builders—prefer explicit helper methods that update component attributes.

## Testing Guidelines
Automated coverage is light today. Add new tests under `app/tests/` (create if missing) using `pytest` with files named `test_<feature>.py`; run them with `pytest`. Exercise interactive flows by launching `rio run --release` and walking through login, persistence, and 2FA utilities (see `scripts/test2fa.py` and `scripts/test_qr.py`). Record edge cases such as failed authentication or expired tokens in your test notes.

If you have made any changes to the rio frontend or touched Rio components, smoke test from the outer `app/` directory (where `rio.toml` lives) using `rio run --port 8XXX` with a 5s timeout to confirm the app boots with the right arguments, then fix errors until it runs cleanly. For every component you modify or add, cross-check its constructor and usage against the references in `RioDocumentation/` to ensure it is instantiated exactly as documented.

## Commit & Pull Request Guidelines
Follow the existing concise imperative style (`remove redundant reset password page`). Each commit should bundle one logical change with related docs or data updates. PRs must explain user-facing impact, enumerate tests run (`rio run --release`, `pytest`), link issues, and attach screenshots/GIFs for UI changes. Request a maintainer review before merge.

## Security & Configuration Tips
Load secrets from an untracked `.env` (supported via `python-dotenv`) and never commit credentials. Re-check guards whenever updating `permissions.py`, and audit persistence changes for SQL injection and session leakage. After upgrading packages, regenerate `requirements.txt` (`pip freeze > requirements.txt`) so deployment stays reproducible.
