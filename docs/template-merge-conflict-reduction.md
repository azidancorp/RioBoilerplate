# Reducing Template Merge Conflicts

Date: 2026-07-04

Context: review of an in-progress merge of RioBoilerplate into `/home/azidan/AQL/AQLChat`.

The AQLChat merge had 44 conflicted files and about 227 individual conflict hunks. The merge was especially noisy because the template history was kept separately/squashed, producing many add/add conflicts. Even so, the conflict contents show useful patterns for making future RioBoilerplate-based projects easier to update.

## Quick Tally

Rough bucket counts from the AQLChat conflict set:

- 14-17 hunks were truly trivial name/string differences.
- 25-30 hunks were broader branding, copy, route-label, or default-route differences.
- The remaining hunks were real behavioral conflicts involving auth policy, admin flows, persistence/schema, currency APIs, tests, routers, and startup tasks.

The trivial/name-ish examples were:

- `AQLChat` vs `Buzzwordz Inc.` footer text.
- `AQLChat` vs `RioBase` MFA issuer name.
- `Energy` vs `credit` / `credits` currency naming.
- `/app/chat` vs `/app/dashboard` post-login destination.
- App/boilerplate wording in docs.
- `Contact AQLChat` vs `Contact Us`.

These are not worth manual merge pain. They should be moved behind a project-local configuration seam.

## Main Lesson

RioBoilerplate currently hardcodes too much project identity and app topology in template-owned files. That makes every downstream project edit the same central files:

- `app/app/__init__.py`
- `app/app/navigation.py`
- `app/app/pages/login.py`
- `app/app/config.py`
- `app/app/theme.py`
- `app/app/components/footer.py`
- `app/app/pages/app_page/enable_mfa.py`
- public pages and docs

Those files then conflict whenever RioBoilerplate receives upstream improvements.

## Recommended Template Changes

1. Add a project-local config layer.

   Track an example file such as `app/app/project_config.example.py`, but have core optionally import an untracked or project-owned `app/project_config.py`.

   The project layer should own:

   - `APP_NAME`
   - `APP_DESCRIPTION`
   - `APP_URL`
   - `MFA_ISSUER_NAME`
   - footer title/subtitle
   - OG/meta title and description
   - default authenticated landing route
   - primary currency display names
   - optional theme palette

2. Add a project hooks module.

   Track an example like `app/app/project_hooks.example.py`, and have core optionally import `app/project_hooks.py`.

   Useful hook surfaces:

   - `extra_fastapi_routers()`
   - `on_app_start(app, persistence)`
   - `on_app_close(app)`
   - `extra_schema_initializers()`
   - `after_user_created(persistence, user)`
   - `before_user_deleted(persistence, user)`
   - `extra_app_routes()`
   - `extra_public_routes()`
   - `post_login_route(user)`

3. Stop using one central route tuple as the only extension point.

   Keep RioBoilerplate's built-in routes in a stable core tuple, then append project-provided routes from hooks. This prevents downstream apps from editing `APP_ROUTES` and `PUBLIC_NAV_ROUTES` directly just to add product pages.

4. Move post-login navigation behind config.

   `login.py` should not hardcode `/app/dashboard`. Use something like `config.AUTHENTICATED_HOME_ROUTE`, defaulting to `/app/dashboard`, so AQLChat can set `/app/chat` without editing login logic or tests.

5. Move MFA issuer and currency fallback names behind config.

   `enable_mfa.py` should read `config.MFA_ISSUER_NAME`.

   `currency.py` should not have fallback strings that downstream projects need to edit. The fallback can be generic, but real naming should come from project config.

6. Split the admin monolith.

   `app/app/pages/app_page/admin.py` was the largest conflict hotspot by far. Break it into smaller components/panels:

   - role management
   - user creation
   - profile editing
   - active/inactive controls
   - user deletion
   - currency admin
   - shared step-up UI

   This will not eliminate all conflicts, but it keeps unrelated upstream security changes from colliding with every downstream admin customization.

7. Make sensitive-action auth policy explicit.

   RioBoilerplate moved toward per-action step-up re-auth. AQLChat had sudo/elevation-window behavior. That is a real product/security policy difference, so hide it behind a `SensitiveActionVerifier` or similar abstraction instead of making projects patch `session_validation.py`, `persistence_auth.py`, `data_models.py`, and admin UI together.

8. Add persistence/schema registration hooks.

   AQLChat had to add bots, chats, research jobs, Energy holds, and sidecar directories. RioBoilerplate should let projects register schema initializers and lifecycle cleanup hooks without editing `persistence_schema.py` or `persistence.py`.

9. Layer project dependencies.

   Use a stable core requirements file plus a project requirements include, for example:

   ```text
   requirements-core.txt
   requirements-project.txt
   requirements.txt
   ```

   Keep `requirements.txt` stable and have it include both. That avoids conflicts when downstream apps add product libraries such as LLM providers.

10. Update the upstream merge guide.

   The guide should distinguish between:

   - ongoing upstream-friendly projects that preserve template ancestry, and
   - squashed/product forks that accept more manual conflict work.

   AQLChat's add/add conflict storm was partly a history-shape issue, not only a code organization issue.

## Expected Impact

The brand/config/hook changes should remove roughly 20-30 future conflict hunks of low-value noise from AQLChat-like projects. They will not remove the hard conflicts around security, persistence, and product behavior, but they will make those remaining conflicts easier to see and reason about.

The target state is simple: future merges should only stop for real decisions, not because the footer says a different name.
