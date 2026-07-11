# Remediation Log

This is the running, plain-language record of the post-audit repair pass. Each
code change is kept in its own commit and the matching log entry is committed
with it. That makes every repair independently reviewable and revertible.

## Scope

The working baseline is commit `8b506f0` on `main`, matching `origin/main` when
this pass began on 2026-07-11. The checkout had no tracked changes. An existing
untracked crawler investigation file is deliberately being left untouched.

The prior verification baseline was:

- 320 pytest tests passing in both the existing virtual environment and a
  separately created fresh environment.
- Development and release Rio boot checks passing.
- `pip check` passing.
- Ruff reporting 19 existing source-quality errors.

## Explicit exclusions

These items are not being changed in this pass:

- crawler/server-side rendering and the existing untracked crawler note;
- Railway deployment;
- legacy database migrations, old-database upgrade compatibility, and database
  recovery tooling (there is no production database to preserve yet);
- local secret-file permission hardening;
- dependency versions, lock files, or hashes;
- response security headers;
- placeholder/demo content on the homepage, pricing, notifications, or
  dashboard pages;
- converting contact, ntfy, or SMTP delivery paths from synchronous to
  asynchronous work.

Dependency posture is note-only: direct versions are pinned but the project has
no fully locked transitive dependency graph or hashes, and the audit found
advisories affecting some resolved packages. No dependency files will be edited
as requested.

## Repair queue

Status meanings: **queued** has not started, **in progress** is actively being
worked, **done** names the verifying commit, and **excluded** records an explicit
decision not to change it.

| Area | Problem in simple terms | Status |
| --- | --- | --- |
| Profile privacy | A signed-in user can read another user's private profile fields. | done — `Restrict private profile reads` |
| Profile read hierarchy | Admin profile reads can expose root/peer private data outside the role hierarchy. | done — `Apply role hierarchy to profile reads` |
| Profile mutations | Cross-user profile edits do not consistently enforce the live role hierarchy inside the write transaction. | done — `Authorize profile writes atomically` |
| Session lifetime | API bearer authentication accepts a session beyond its absolute maximum lifetime. | done — `Enforce absolute session lifetime everywhere` |
| Password policy | Signup, reset, settings, and admin-created passwords enforce different rules. | done — `Apply one password policy to every flow` |
| OAuth account deletion | An OAuth-only user cannot complete self-service account deletion. | queued |
| Browser token storage | The bearer token is exposed to normal browser-side code instead of using Rio's HTTP-only storage marker. | done — `Store browser sessions in HTTP-only cookies` |
| OAuth handoffs | A deactivation race can leave a handoff usable after an account is reactivated. | done — `Serialize OAuth handoffs with account status` |
| Verification tokens | Concurrent email-verification requests can leave more than one live token. | done — `Replace verification tokens atomically` |
| Transaction ownership | Some persistence helpers can accidentally commit a caller's unrelated pending work. | done — `Protect caller-owned auth transactions` |
| Expired auth data | Expired sessions and completed/expired OAuth handoffs accumulate indefinitely. | done — `Bound stale authentication data` |
| Currency rounding | A positive display amount can round to a zero-unit ledger adjustment. | done — `Reject zero-unit currency adjustments` |
| Currency idempotency | Retrying the same adjustment can apply it twice. | queued |
| Protected deep links | Logged-out users lose the protected destination they originally requested. | queued |
| HTTP route semantics | Unknown/API/documentation routes can return the Rio app shell with HTTP 200, and crawler metadata lists unsuitable routes. | queued |
| Responsive refresh | The first mobile/desktop breakpoint crossing can be missed. | queued |
| Admin experience | Stale authorization, misleading mail feedback, and unbounded user-table loading need focused corrections. | queued |
| Source quality | Ruff errors remain and CI does not enforce the source checks used locally. | queued |
| Deployment guide | Non-Railway Linux guidance targets an obsolete release and an unnecessarily privileged service. | queued |
| Final verification | Focused tests, full pytest, Ruff, and dev/release boot evidence must all be reconciled here. | queued |

## Completed work

### 2026-07-11 — Private profile reads

- Changed the single-profile endpoint so ordinary users can read only their
  own profile. Admin/root access remains available for account support.
- Added API tests proving cross-user reads are rejected without leaking the
  private fields, while self and administrator reads still work.
- Verification: `pytest app/tests/test_profiles_api.py -q`.

### 2026-07-11 — Profile mutation authorization

- Moved create, update, and delete authorization into persistence operations
  that acquire SQLite's writer lock first, then reload the actor's live session,
  current role, and the target's current role before writing.
- Preserved self-service profile operations. Cross-user operations now require
  current admin-page access and a strictly lower-privilege target, so an admin
  cannot alter a root/peer account and a demoted admin cannot finish a stale
  request.
- Stopped returning raw internal exception text for unexpected profile API
  failures.
- Added API coverage for all three mutation routes, role hierarchy, demotion
  between request authentication and persistence, lower-role administration,
  and self-service delete/recreate behavior.
- Verification: `pytest app/tests/test_profiles_api.py -q`.

### 2026-07-11 — Profile read hierarchy

- Tightened both individual and bulk profile reads to the same role hierarchy
  used by account management: users see themselves, privileged users see
  themselves and lower-role users, and root/peer private profiles are excluded.
- Made authorization and profile retrieval use one consistent SQLite read
  snapshot, so a role change cannot be interleaved between the permission check
  and the sensitive read.
- Verification: `pytest app/tests/test_profiles_api.py -q`.

### 2026-07-11 — Absolute session lifetime

- Made the shared definition of a valid session enforce both the sliding expiry
  and the configured absolute lifetime. API authentication, admin mutations,
  profile operations, and protected-page revalidation all use this definition.
- Preserved renewal's existing ability to delete a row whose absolute deadline
  has elapsed rather than leaving it behind after a failed renewal.
- Added regression coverage for a session whose ordinary expiry is still in the
  future but whose absolute lifetime has elapsed, including a privileged API
  mutation that must leave the target balance unchanged.
- Verification: `pytest app/tests/test_live_session_revalidation.py
  app/tests/test_currency_api.py -q`.

### 2026-07-11 — HTTP-only browser session token

- Marked the persisted bearer token with Rio's `HttpOnly` annotation, which
  moves it from JavaScript-readable local storage into an HTTP-only cookie.
  The non-sensitive 2FA display preference remains ordinary local storage.
- Invalid/expired stored tokens are now cleared and reattached immediately, so
  the browser does not retry a bad cookie on every connection.
- Because there is no production usage, no migration is included: an old
  local-storage-only token is deliberately ignored and the user signs in once
  to receive the new cookie.
- Added framework-level tests proving cookie precedence, local-storage
  rejection, and stale-token clearing. A live browser was not needed.
- Verification: `pytest app/tests/test_user_settings_storage.py
  app/tests/test_live_session_revalidation.py -q`.

### 2026-07-11 — One password policy across every flow

- Added one policy decision function for signup, password reset, settings
  changes, administrator-created accounts, and root bootstrap.
- `ALLOW_WEAK_PASSWORDS=False` now means acknowledgement can never override the
  configured minimum. When weak passwords are enabled, every user-facing flow
  requires an explicit acknowledgement; empty passwords are always rejected.
- Enforced the same rule again at the persistence boundary for normal password
  changes, reset-token completion, and admin creation, preventing a caller from
  bypassing the UI. Rejected attempts leave hashes, sessions, and reset tokens
  untouched.
- Added matching strength/acknowledgement controls to Settings and Admin, and
  retained the existing signup/reset visuals.
- Verification: 114 focused tests passed across password policy, hashing,
  reset-token lifecycle, signup/bootstrap, mounted settings, admin lifecycle,
  and public rate-limit flows. The 16 page-smoke tests passed, and a live Rio
  dev boot returned the login page plus the expected protected redirects for
  Settings and Admin.

### 2026-07-11 — Auth transaction ownership

- Gave the remaining session, reset-token, verification-token, user-verification,
  and recovery-code helpers an explicit transaction contract. A standalone
  helper now owns and closes only the transaction it starts; an in-transaction
  helper requires the caller to have opened one.
- Removed the preliminary awaited user lookup from verification-state updates
  and made the checked update plus missing-user result part of one owned write
  transaction.
- Added a parameterized regression suite that starts an unrelated pending user
  edit, calls every affected helper, and proves the edit is neither committed
  nor rolled back and all auth rows remain unchanged.
- Verification: `pytest app/tests/test_auth_transaction_ownership.py
  app/tests/test_password_reset_token_lifecycle.py app/tests/test_auth_email_flows.py
  app/tests/test_live_session_revalidation.py -q`.

### 2026-07-11 — OAuth handoff/account-status ordering

- OAuth handoff creation now takes SQLite's writer lock before re-reading the
  account's active state, then inserts without yielding. Whichever
  commits first—handoff creation or account deactivation—therefore determines a
  safe result: deactivation either blocks creation or deletes the new handoff.
- Added explicit transaction ownership to both handoff creation and consumption,
  and rejected non-positive handoff lifetimes.
- Added deterministic ordering tests that recreate the original stale-read
  window with a held writer lock, plus caller-transaction and opposite-order
  coverage.
- Verification: `pytest app/tests/test_oauth_handoff_atomicity.py
  app/tests/test_oauth_google.py app/tests/test_admin_user_lifecycle.py -q`.

### 2026-07-11 — Atomic email-verification token replacement

- Replaced the old lookup → committed clear → committed insert sequence with one
  `BEGIN IMMEDIATE` transaction. Concurrent issuers now serialize, and each
  replacement rechecks the user, removes older tokens, and inserts exactly one
  current token before committing.
- A failed insertion rolls the deletion back, so a previously issued token is
  not destroyed by a partial replacement.
- Kept this entirely in current-schema application logic; no legacy cleanup,
  unique-index migration, or backfill was added.
- Added real two-writer coverage that proves one stored token and exactly one
  usable returned token, plus forced-failure rollback coverage.
- Verification: `pytest app/tests/test_email_verification_token_atomicity.py
  app/tests/test_auth_email_flows.py app/tests/test_rate_limit_public_flows.py -q`.

### 2026-07-11 — Bounded stale authentication data

- Session creation now removes rows past either their sliding expiry or their
  absolute lifetime inside the same transaction as the new session.
- OAuth handoff creation removes expired/previously consumed handoffs before
  inserting, and a successful consumption now deletes its one-time row instead
  of retaining a permanent consumed marker.
- Cleanup and issuance are one transaction, so an insertion failure restores
  any rows selected for cleanup. Live rows for other users are preserved.
- Kept this as current application behavior without adding schema/index
  migration work.
- Verification: `pytest app/tests/test_auth_state_cleanup.py
  app/tests/test_live_session_revalidation.py app/tests/test_oauth_google.py
  app/tests/test_oauth_handoff_atomicity.py -q`.

### 2026-07-11 — Zero-unit currency adjustments

- API validation now converts a proposed major-unit adjustment using the active
  currency precision and rejects it if it would store as zero minor units. This
  catches values such as `0.4` when the currency has no decimal places.
- Persistence independently rejects a zero minor-unit delta before reading or
  updating the account, so trusted/internal callers cannot create meaningless
  ledger and audit entries either.
- Added tests proving the balance, update timestamp, ledger, and admin audit all
  remain unchanged at both boundaries.
- Verification: `pytest app/tests/test_currency_api.py
  app/tests/test_currency_persistence.py app/tests/test_currency_reconciliation.py -q`.
