# Implementation Plan — Sudo Mode (Step-Up Re-Auth) for Role Escalation

## Objective

Require an admin to **re-authenticate (their own password, plus their own TOTP
if 2FA is enabled)** before changing another user's role, and grant a short
"elevated" window so a batch of changes doesn't demand a prompt per click.

This defends the realistic threat: a **passively hijacked or left-open admin
session**. Sessions in this app are long-lived with no absolute lifetime cap
(created `+1 day`, slid to `+7 days` on every visit, forever —
`persistence_auth.py:316`, `__init__.py:88-91`), so a stolen session token is
both durable and, today, able to escalate roles with a single click
(`admin.py:_update_role`, persistence `update_user_role` at `persistence.py:776`).

### Why the admin's OWN password, not the shared `ADMIN_DELETION_PASSWORD`

- The own-password binds the action to a **specific human** and is **per-user
  rotatable**. The shared `ADMIN_DELETION_PASSWORD` (`config.py:86`) is a static
  secret common to all admins; spreading it onto a *frequent* code path like
  role changes increases its leak surface and it is painful to rotate (env var +
  restart). It also gives no attribution.
- Re-auth is the standard "sudo mode" pattern (GitHub sudo mode, AWS re-auth,
  Google sensitive-action re-prompt) and **already exists in this codebase** for
  self-service security actions — `settings.py:_on_confirm_password_change_pressed`
  (`settings.py:189`) does exactly `verify_password` + `verify_two_factor_challenge`.
  We mirror that, so the model stays consistent.
- Attribution ("who did it") is handled by the separate audit-log plan, **not**
  by this re-auth. These two changes are complementary: audit = who, sudo = was
  it really them.

This plan is **independent of** the audit-log plan but composes with it: a
successful elevation and each elevated action should also write an audit row.

## Design Decisions (and why)

1. **Elevation state lives server-side, on the `user_sessions` row.** Add an
   `elevated_until REAL` column. Re-auth sets `elevated_until = now + N minutes`;
   sensitive actions check `elevated_until > now`. Rationale: OWASP requires
   server-side enforcement of session/elevation state; a client-side flag could
   be forged. It also survives Rio reconnects (which re-read the auth token and
   re-attach the session — see `refresh_attached_user_session`,
   `session_validation.py:17`), unlike an in-memory Rio attachment that would be
   lost on reconnect. This matches how `valid_until` already lives on the row.

   *Alternative considered:* an in-memory `AdminElevation` Rio attachment
   (simplest, no schema change) — rejected as primary because it is per-connection
   and lost on reconnect, and is not server-authoritative. Could be a fallback if
   we want zero schema change, but the column is the robust choice.

2. **Re-auth credential = own password (+ own TOTP if `two_factor_enabled`).**
   Reuse `AppUser.verify_password` and `Persistence.verify_two_factor_challenge`
   verbatim from the password-change flow so behavior (including recovery-code
   handling and `TwoFactorFailure.MISSING_CODE`) is identical.

3. **Short, fixed elevation window via a code constant in `config.py`**, e.g.
   `SUDO_MODE_TTL_SECONDS = 300` (5 min). Per AGENTS.md, non-secret behavior
   flags are code-configured in `config.py`, **not** `.env`/`from_env`. The
   shared deletion password stays in `.env`; this TTL does not.

4. **Reusable gate, applied first to role change.** Build
   `require_elevated_session(session)` as a sibling to
   `require_fresh_user_session` (`session_validation.py:41`) so the same gate can
   later wrap deactivate / email-edit / reset-send / currency without rework.
   v1 wires it into role change only (the user's stated target).

5. **Elevation is re-validated server-side at action time**, not just when the
   dialog closes — the action handler calls the gate immediately before the
   mutation. A stale/expired elevation re-prompts.

6. **Elevation is bound to the session and the actor**, and should be
   invalidated when the session is (logout, password change, "logout all
   devices" already set `valid_until`; treat `elevated_until` as implicitly dead
   once `valid_until <= now`). On password change, explicitly clear elevation.

## Schema change + migration

Add one column to `user_sessions` (created in
`create_session_table`, `persistence_schema.py:202`):

```sql
ALTER TABLE user_sessions ADD COLUMN elevated_until REAL;   -- nullable; NULL = not elevated
```

Because existing databases already have `user_sessions`, `CREATE TABLE IF NOT
EXISTS` will **not** add the column to them. Add an **idempotent migration** in
the schema-init path. To match the existing house pattern for the `users` table
(`_ensure_user_password_scheme_column` / `_ensure_user_is_active_column`,
`persistence_schema.py:78-99`), wrap it in `_ensure_session_elevated_until_column`
and call it from `create_session_table` right after the `CREATE TABLE`:

```python
def _ensure_session_elevated_until_column(cursor) -> None:
    cursor.execute("PRAGMA table_info(user_sessions)")
    cols = {row[1] for row in cursor.fetchall()}
    if "elevated_until" not in cols:
        cursor.execute("ALTER TABLE user_sessions ADD COLUMN elevated_until REAL")
```

Also add `elevated_until` to the `CREATE TABLE` definition for fresh DBs, and
add `elevated_until: datetime | None = None` to the `UserSession` dataclass
(`data_models.py:37`).

**Then make these four `persistence_auth.py` edits explicitly — there is no
shared row mapper; both reads are hand-rolled explicit column lists:**

1. `create_session` **INSERT** (`:321-337`): add `elevated_until` to the column
   list and bind `NULL` (new sessions start un-elevated).
2. `get_session_by_auth_token` (`:396-414`): add `elevated_until` to the
   `SELECT` list, then populate it in the `UserSession(...)` constructor
   (`:406-414`).
3. `get_valid_session_by_auth_token` (`:428-465`): add `s.elevated_until` to the
   joined `SELECT`, populate the `UserSession(...)` constructor (`:458-465`),
   **and bump the user-column slice.** This SELECT splits the row with
   `user = _row_to_app_user(row[5:])` (`:454`); inserting a session column ahead
   of the `users` columns shifts every user field. Add `elevated_until` as the
   **last** session column (index 5) and change the slice to `row[6:]`. Getting
   this wrong silently mis-parses the user object rather than erroring.

Keep `elevated_until` as the last session-position column in both reads so the
slice math stays a simple `+1`.

## New persistence methods (`persistence_auth.py`, exposed via facade)

```python
async def elevate_session(persistence, session_id: str, ttl_seconds: int) -> datetime:
    """Set elevated_until = now + ttl on this session row; return the new deadline."""

def session_is_elevated(session: UserSession, *, now=None) -> bool:
    """
    True iff session.elevated_until is set and > now AND session.valid_until > now.
    Sync (no DB hit) so it can run inside the synchronous Rio page-guard path; it
    reads the elevated_until already loaded onto UserSession by the SELECT above,
    so require_elevated_session adds NO extra query over require_fresh_user_session.
    """

async def clear_session_elevation(persistence, session_id: str) -> None:
    """Set elevated_until = NULL (called on password change / explicit drop)."""
```

`elevate_session` and `clear_session_elevation` are `async` (they write); only
`session_is_elevated` is sync. The `valid_until > now` term in `session_is_elevated`
is defense-in-depth: in practice `require_elevated_session` already runs
`require_fresh_user_session` first, which calls `get_valid_session_by_auth_token`
and raises `KeyError` when `valid_until <= now` — so a soft-invalidated session
(password change / "logout all devices" set `valid_until = now` but leave the row,
`persistence_auth.py:596,640`) can never reach the elevation check. The extra term
just keeps `session_is_elevated` safe if ever called standalone.

Expose on the `Persistence` facade in `persistence.py` (delegating, like
`update_session_duration` → `persistence_auth.update_session_duration`).

## New gate (`app/app/session_validation.py`)

```python
def require_elevated_session(
    session: rio.Session,
    *,
    now: datetime | None = None,
) -> tuple[UserSession, AppUser] | None:
    """
    Like require_fresh_user_session, but additionally requires the session to be
    within its sudo elevation window. Returns (user_session, user) when elevated,
    else None (caller should prompt for re-auth).
    """
    fresh = require_fresh_user_session(session)
    if fresh is None:
        return None
    user_session, user = fresh
    if not session_is_elevated(user_session, now=now):
        return None
    return user_session, user
```

And a verifier that performs the re-auth and elevates:

```python
async def perform_step_up(
    session, *, password: str, two_factor_code: str | None,
) -> StepUpResult:
    """
    Verify the CURRENT user's password (+ TOTP if two_factor_enabled), and on
    success call elevate_session(...). Mirrors settings.py:189-248. Returns a
    small result object (ok / failure reason) for the UI to render.
    """
```

`perform_step_up` reuses, verbatim, the verification sequence from
`settings.py:_on_confirm_password_change_pressed` (`settings.py:221-248`):
`user.verify_password(...)` then, if `user.two_factor_enabled` (a read-only
`@property` over `two_factor_secret`, `data_models.py:82-85` — read it, never
assign it), `persistence.verify_two_factor_challenge(...)` with the same
`TwoFactorFailure.MISSING_CODE` handling and recovery-code notice. Import
`TwoFactorFailure` from `persistence_auth` (`persistence_auth.py:31`), where it is
defined and where the existing callers import it.

**Recovery-code burn policy:** mirroring settings means
`verify_two_factor_challenge` runs with its default `consume_recovery_code=True`,
so a step-up performed with a recovery code **consumes** that code and surfaces
the same "a recovery code was used" notice. This is the deliberate choice (it
matches the password-change flow); it is not an accidental side effect.

## UI flow (`app/app/pages/app_page/admin.py`)

Current role-change handler chain: `_on_change_role_pressed` (`admin.py:529`) →
`_update_role` (`admin.py:551`) → `persistence.update_user_role` (after
hierarchy + rate-limit checks).

Change `_update_role` to gate on elevation **before** the mutation:

```python
elevated = require_elevated_session(self.session)
if elevated is None:
    self._show_step_up_dialog(pending="role_change", identifier=identifier, new_role=new_role)
    return False
# ... existing hierarchy + rate-limit checks ...
await persistence.update_user_role(target_user.id, new_role)   # (+ audit, per other plan)
```

Step-up dialog (reuse existing Rio form/input components, mirror the password
fields in `settings.py`):
- Password input (always).
- 2FA/recovery code input (shown only if `current_user.two_factor_enabled`).
- On submit → `perform_step_up(...)`. On success, set elevation and
  automatically re-invoke the pending role change. On failure, show the same
  error vocabulary as settings ("Current password is incorrect" / "2FA code is
  required" / "Invalid 2FA or recovery code.").
- Rate-limit the step-up attempts using the existing
  `_check_sensitive_limit(...)` machinery (`admin.py:127`) under a new scope,
  e.g. `"admin_step_up"`. The generic scope factory (`rate_limits.py`) needs no
  registry edit. Key it on the **actor only** — call with the default
  `target=""` so the key becomes `{actor}:` — because step-up throttles the
  admin's own password/TOTP guessing, not an action against a specific target.
  (Admin scopes like `admin_change_role` key on `{actor}:{target}`; that is wrong
  here, since one elevation window covers every target.)

If the step-up dialog is built as a **new sub-component** that calls
`is_mobile()`, it must inherit `ResponsiveComponent`
(`app/app/components/responsive.py`) — enforced by `test_responsive_inheritance.py`.
Prefer building the dialog inline on `AdminPage` (already responsive-safe) and
holding step-up state as `AdminPage` attributes to avoid a new component
altogether.

Once elevated, subsequent role changes within the TTL skip the dialog (the gate
passes), giving the "sudo for N minutes" UX. Optionally surface a small "Elevated
for 4:59" indicator.

## Config (`app/app/config.py`)

```python
# Sudo-mode (step-up re-auth) elevation window for sensitive admin actions.
# Non-secret behavior flag -> lives in code per AGENTS.md, NOT in .env.
SUDO_MODE_TTL_SECONDS: int = 300
```

No `.env` / `from_env` entry. The shared `ADMIN_DELETION_PASSWORD` is unchanged
and unrelated to this flow.

## Interaction with existing flows

- **Password change / "logout all devices"**: elevation dies with the session
  automatically — `update_password` (`persistence_auth.py:639-642`),
  `invalidate_all_sessions` (`:596`), and
  `consume_reset_token_and_update_password` (`:707`) set `valid_until = now` on
  the affected rows, and the elevation gate requires `valid_until > now` (via
  `require_fresh_user_session`), so a soft-invalidated row can never be treated as
  elevated. The leftover `elevated_until` value on those dead rows is therefore
  harmless, **not** a "revoked session stays elevated" hole.
  For tidiness/defense-in-depth, also `NULL` it out at the **persistence layer**
  inside `update_password` and `invalidate_all_sessions` (one extra `SET
  elevated_until = NULL` in the same `UPDATE`), rather than only in the
  `settings.py` UI handler — that way the admin-initiated reset
  (`admin.py:_on_send_reset_pressed`) and self-service reset paths are covered too.
  Note: `settings.py` password change is mutation (`:251`) followed by tearing
  down only the *current* session (`reject_stale_user_session`, `:265`); it does
  **not** call `invalidate_all_sessions`.
- **Session slide** (`__init__.py:88-91`): sliding `valid_until` must **not**
  extend `elevated_until` — elevation has its own shorter, independent clock.
- **OAuth-only admins** (no local password, `auth_provider != "password"`): they
  cannot satisfy a password step-up. Note that "mirror `settings.py`" is a trap
  here — `settings.py` has no explicit provider check, and
  `verify_password` short-circuits to `False` for any non-password provider
  (`data_models.py:183-184`), so literally mirroring it would deny the step-up
  with a confusing "Current password is incorrect". Use an explicit policy
  instead (resolved in Open Questions): for `auth_provider != "password"`, **skip
  the password leg** and require TOTP if `two_factor_enabled`, else deny step-up
  with a clear "set up a password or 2FA to perform this action" message.

## Code changes — file by file

1. `app/app/persistence_schema.py` — add `elevated_until` to the
   `user_sessions` `CREATE TABLE` (`:202`) and an idempotent
   `PRAGMA table_info` + `ALTER TABLE` migration in schema-init.
2. `app/app/data_models.py` — add `elevated_until: datetime | None = None` to
   `UserSession` (`:37`).
3. `app/app/persistence_auth.py` — the four explicit edits above (INSERT +
   both SELECT/constructor pairs, including the `row[5:]`→`row[6:]` slice bump in
   `get_valid_session_by_auth_token`); add `elevate_session`,
   `session_is_elevated`, `clear_session_elevation`; add `SET elevated_until =
   NULL` to the existing `UPDATE`s in `update_password` (`:639-642`) and
   `invalidate_all_sessions` (`:596`).
4. `app/app/persistence.py` — delegating facade methods for the three new
   functions.
5. `app/app/session_validation.py` — `require_elevated_session`,
   `perform_step_up`, `StepUpResult`.
6. `app/app/config.py` — `SUDO_MODE_TTL_SECONDS`.
7. `app/app/pages/app_page/admin.py` — step-up dialog state (held as `AdminPage`
   attributes) + handlers; gate `_update_role` on `require_elevated_session`;
   rate-limit scope `"admin_step_up"` keyed on actor only.
8. `app/app/persistence_schema.py` is also touched (item 1) — and note that
   clearing elevation now lives at the persistence layer (item 3), so no
   `settings.py` change is strictly required; the persistence-level clear already
   covers the password-change and reset paths.

## Tests

Add `app/tests/test_sudo_mode.py`:
- `update_user_role` via the admin handler is **blocked** when not elevated
  (gate returns None → no mutation).
- `perform_step_up` with correct password (no 2FA) sets `elevated_until ≈ now +
  TTL`; role change then succeeds.
- With 2FA enabled: wrong/missing TOTP fails (`MISSING_CODE` path); correct TOTP
  succeeds; recovery-code path behaves like settings.
- Elevation **expires**: set `elevated_until` in the past → gate re-prompts.
- Elevation does **not** extend when `valid_until` is slid.
- Password change clears elevation.
- Step-up attempts are rate-limited under the new scope.
- **Migration regression** (mirror `test_two_factor_verification.py`'s schema
  test): open a DB created *without* `elevated_until`, run schema-init, assert
  the column now exists and a `create_session` INSERT succeeds — guards against
  `OperationalError: table user_sessions has no column named elevated_until` on
  upgraded production DBs.
- **Joined-SELECT integrity**: assert `get_valid_session_by_auth_token` still
  returns a correctly-parsed `AppUser` after the column addition (catches a
  missed `row[5:]`→`row[6:]` slice bump).
- **Update the `_mount_admin` test helper** (`test_admin_user_lifecycle.py:113`)
  and the `AdminPage` builder in `test_rate_limit_sensitive_flows.py:133` to
  initialize any new step-up attributes. These build `AdminPage` via
  `object.__new__` + per-attribute assignment, so a new attribute read in
  `build()`/handlers raises `AttributeError` until added there.
- Existing role-change handler tests: only `test_live_session_revalidation.py:123`
  calls `update_user_role`, and it hits `Persistence` directly (bypassing the Rio
  handler), so it is unaffected by the gate. The new gate behavior is exercised
  through `_update_role`; add a helper that stamps `elevated_until` (or runs
  `perform_step_up`) for the elevated-path cases.

Run `pytest app/tests/test_sudo_mode.py -x`, the admin suite, and
`pytest app/tests/test_smoke_pages.py -x`. Boot check from `app/`:
`cd app && timeout 5 rio run --port 8012`, navigate to `/app/admin`, attempt a
role change, confirm the step-up dialog appears and that a correct password (+
TOTP) elevates and completes the change.

## Rollout

- Ship together with the schema migration; the `ALTER TABLE` is idempotent and
  safe on existing DBs. New behavior is gated entirely server-side.
- v1 scope: role change only. Because the gate is reusable, follow-ups can wrap
  the other **Rio admin handlers** — deactivate (`admin.py:348`), email edit
  (`admin.py:271`), admin-initiated reset (`admin.py:425`), currency adjust/set
  (`admin.py:718`) — by adding the same two lines.
- **The FastAPI currency endpoints (`api/currency.py:118,157`) are NOT covered by
  this gate.** They authenticate via `Authorization: Bearer` + `get_current_user`
  and have no Rio session attachments, so `require_elevated_session(rio.Session)`
  cannot apply. If those ever need sudo mode, enforce it at the API layer (e.g.
  check `elevated_until` on the session row directly, or require an
  elevated-scope token), not by reusing the Rio gate.

## Open Questions (resolve in review)

1. **TTL value**: 5 minutes (recommended) vs shorter/longer? Re-prompt on every
   action instead of a window? (Window chosen for batch UX.)
2. **OAuth-only admins** — *resolved*: do **not** mirror `settings.py` (it would
   silently fail on `verify_password`). For `auth_provider != "password"`, skip
   the password leg and require TOTP when `two_factor_enabled`; if they have
   neither a local password nor 2FA, deny step-up with an actionable message
   rather than a misleading password error.
3. **Scope of elevation**: one elevation covers all sensitive admin actions
   (simple), or scope elevation per-action-type (stricter, more friction)?
   Recommended: single elevation window in v1.
4. **Indicator**: do we show a visible "elevated for m:ss" countdown? (Nice to
   have, not required for the security property.)
