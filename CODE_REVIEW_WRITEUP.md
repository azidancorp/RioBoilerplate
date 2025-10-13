# Rio Boilerplate Code Review

## Executive Summary
- Multiple critical authentication and data-handling bugs currently prevent core flows (sign-up, account deletion) and expose sensitive profile data.
- Persistence layer design issues (sync DB usage inside async API, ad-hoc connection creation, committed SQLite file) create reliability and security risks.
- Several features are placeholders (notifications, reset password, contact), and there is no automated test coverage to protect existing behaviour.
- Frontend components contain unfinished UX details (hard-coded marketing filler, inactive nav highlighting, unused heavy dependencies) that increase polish debt.

## Critical / Stop-Ship Issues
1. **Sign-up breaks after the first user due to unique email constraint collisions.**
   - `create_user` inserts a default profile with an empty string email for every new user, violating the `profiles.email UNIQUE` constraint on the second registration, causing an IntegrityError and blocking onboarding.
   - References: `app/app/persistence.py:160`, `app/app/persistence.py:214-219`.

2. **Self-service account deletion is unusable and insecure.**
   - The settings page awaits the synchronous `Persistence.delete_user`, triggering `TypeError: object bool can't be used in 'await' expression`, so the UI always surfaces a generic failure.
   - `delete_user` itself never awaits `get_user_by_id`, ignores the provided `two_factor_code`, and demands the admin-only `ADMIN_DELETION_PASSWORD`, meaning even correct user credentials can never pass.
   - References: `app/app/pages/app_page/settings.py:170-183`, `app/app/persistence.py:606-666`.

3. **Profile REST API endpoints lack authentication and leak PII.**
   - `/api/profile` and related operations are publicly accessible and return full profile records (email, phone, address) without verifying the caller, enabling trivial data exfiltration.
   - References: `app/app/api/profiles.py:15-200`.

4. **Login guard redirects to a non-existent route.**
   - Authenticated users hitting `/login` are sent to `/home`, but only the root `/` is registered; this yields a 404 or loop depending on router configuration.
   - Reference: `app/app/pages/login.py:22-33`.

5. **Committed SQLite database contains live data.**
   - Shipping `app/app/data/app.db` exposes whatever credentials or profile data were used locally. This must be removed and regenerated per environment.
   - Reference: `app/app/data/app.db`.

## Major Issues
- **Persistence lifetime & resource management flaws.**
  - API dependency `get_persistence` creates a fresh `Persistence()` per request without closing; several UI pages (`settings`, `enable_mfa`, `disable_mfa`) also instantiate raw connections instead of using the session attachment, risking leaked file handles and cross-thread SQLite misuse.
  - References: `app/app/api/profiles.py:15-16`, `app/app/pages/app_page/settings.py:48-51`, `app/app/pages/app_page/enable_mfa.py:31-35`, `app/app/pages/app_page/disable_mfa.py:17-25`.

- **`Persistence.delete_user` ignores 2FA and password verification.**
  - Even if the earlier await bug is fixed, the method never checks `two_factor_code`, and it validates only against an env-based admin password rather than the user's password, defeating the purpose of multi-factor confirmation.
  - Reference: `app/app/persistence.py:606-666`.

- **Unfinished nav/UX behaviour.**
  - Sidebar and navbar try to highlight active routes by hard-coding `active_page_instances[1]`, which fails for top-level pages and nested segments; active styling is effectively broken.
  - References: `app/app/components/sidebar.py:21-41`, `app/app/components/navbar.py:66-154`.

- **`load_from_html` uses raw relative paths.**
  - Packaging or running from another working directory will break the JS demo embed because it calls `open("JSPages/test.html")` relative to process cwd instead of module resources.
  - Reference: `app/app/scripts/utils.py:130-167`.

- **Deployment tooling depends on unlisted packages.**
  - `server_sync.py` imports `paramiko`, but `requirements.txt` omits it, so deployment scripts fail in clean environments.
  - References: `server_sync.py:1-29`, `requirements.txt`.

## Moderate Issues & Code Quality Gaps
- **Async facade over blocking SQLite.** All async methods in `Persistence` perform synchronous `sqlite3` calls, which can starve the event loop under load; consider moving DB work into threads or using an async driver.
- **Repeated ad-hoc warnings in sidebar render loop.** Importing `warnings` inside the render path (`app/app/components/sidebar.py:142-152`) spams runtime warnings and should be replaced with validation at startup/tests.
- **Heavy, unused dependencies.** `app/app/pages/app_page/dashboard.py` imports `matplotlib` and other modules that are never used at runtime, bloating the dependency footprint (`dashboard.py:1-15`).
- **Typo/placeholder content** on key marketing sections (hero text like "<Desired Outcome>") reduces credibility (`app/app/pages/home.py:18-74`).
- **Committed `venv/` directory** adds ~tens of thousands of files and risks dependency drift; prefer `.gitignore`ing environments.
- **`CenterComponent` houses a known bug in comments but relies on state set inside `build`, so external callers of `wrap_horizontally/vertically` would still crash (`app/app/components/center_component.py:8-84`).**
- **`Sidebar` icons use bare strings** like `'dashboard'`; verify valid Rio icon identifiers to avoid runtime missing-icon errors (`app/app/components/sidebar.py:131-139`).

## Missing / Incomplete Features
- **Password reset flow is a stub.** UI only displays a banner; no token email or persistence update exists (`app/app/pages/login.py:318-362`).
- **Contact form lacks submission backend**—pressing "Send Message" just shows a message locally; no API integration or rate limiting (`app/app/pages/contact.py:17-82`).
- **Notifications page uses static sample data** and never touches persistence (`app/app/pages/app_page/notifications.py:18-120`).
- **Two-factor enable/disable pages skip rate limiting & secret confirmation flows** (e.g., no step to re-enter password before toggling).
- **No automated tests** (`app/tests/` missing), so regressions go unnoticed.

## Recommendations / Next Steps
1. **Fix persistence bugs first.** Allow `create_user` to insert `NULL` email defaults, rework `delete_user` to be async-friendly, verify true user credentials/2FA, and reuse the session-level `Persistence` instance.
2. **Lock down the API.** Add authentication/authorization dependencies to all profile routes and ensure only role-appropriate data is exposed.
3. **Clean repository state.** Remove committed database and virtualenv artefacts, add ignores, and ensure deployment scripts list their dependencies.
4. **Improve navigation logic.** Use `self.session.active_page_instances[-1]` or provided helpers, and actually apply active styling to navbar/sidebar buttons.
5. **Replace placeholders with production-ready content and feature implementations.** Implement contact submission, notification persistence, password reset emails, and realistic marketing copy.
6. **Add automated tests.** Start with persistence unit tests (user creation/deletion, session lifecycle) and API contract tests for profile endpoints.

## Observability & Tooling Suggestions
- Introduce logging around authentication flows to trace failures.
- Consider wrapping SQLite access in a repository layer that can be swapped for tests and future databases.
- Add linting (e.g., `ruff` or `flake8`) to catch unused imports (`matplotlib`, `re`) and wildcard imports before they land.

