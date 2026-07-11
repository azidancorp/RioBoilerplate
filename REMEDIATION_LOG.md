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
| Currency idempotency | Retrying the same adjustment can apply it twice. | done — `Make currency API mutations idempotent` |
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

### 2026-07-11 — Idempotent currency API mutations

- Both balance mutation endpoints now require a UUID `Idempotency-Key` header.
  The server fingerprints the operation, resolved target, stored minor-unit
  amount, reason, and canonical metadata.
- Added a current-schema table binding each actor/key pair to the committed
  ledger result. A retry with the same request returns that original entry
  without another balance change or audit row; reusing the key for a different
  amount, target, operation, reason, or metadata returns HTTP 409.
- Lookup, balance/ledger/audit mutation, and key recording all share the
  existing `BEGIN IMMEDIATE` transaction. Concurrent same-key requests therefore
  apply once, while a failure to store the result rolls everything back and
  permits a clean retry.
- Trusted in-process helpers remain usable without a key; the requirement is on
  externally retryable API mutations. The built-in currency playground supplies
  a fresh key for each manual action.
- Step-up verification still runs before an idempotent replay is returned. This
  keeps authorization live, but a one-time recovery code cannot itself be reused
  to retrieve the cached response; the original mutation still cannot run twice.
- Verification: `pytest app/tests/test_currency_idempotency.py
  app/tests/test_currency_api.py app/tests/test_currency_persistence.py
  app/tests/test_currency_reconciliation.py -q`; the page-smoke suite and a
  live Rio dev boot of the playground/API surface also passed.

### 2026-07-11 — OAuth-only self-service account deletion

- Added a real deletion path for accounts that sign in only with Google. These
  users no longer see an impossible app-password requirement: Settings asks
  them to verify with Google, then shows the permanent-deletion confirmation.
- Kept normal login and account deletion as two separate OAuth purposes. A
  login handoff cannot approve deletion, and the deletion challenge/approval
  tokens are rejected by the login consumer.
- Bound the deletion challenge and final approval to the exact live app
  session that initiated the action. Google must return the same stable account
  identifier and a recent `auth_time`; revoked, expired, absolutely expired,
  switched-account, or different-session attempts fail closed.
- The final approval is consumed inside the same locked transaction as current
  session revalidation, optional 2FA/recovery-code use, audit logging, and the
  account delete. A later failure restores both the one-time approval and any
  recovery code instead of leaving a half-finished deletion.
- Used the existing current-schema OAuth handoff table and short expiry. This
  did not add any migration, upgrade, backfill, or recovery logic.
- Added persistence, HTTP callback, and mounted-Settings tests for purpose
  separation, session binding, wrong Google accounts, missing/stale provider
  authentication, rollback, and the successful no-password flow.
- Verification: 63 focused OAuth/deletion/MFA/audit/mounted-session tests and
  all 16 page-smoke tests passed. A live Rio dev boot returned the home page,
  protected Settings redirect, and safe deletion-reauth error redirect as
  expected.

### 2026-07-11 — Protected destinations survive password login

- Protected-page guards now send signed-out visitors to Login with the exact
  registered app path they originally requested, rather than dropping them on
  the public home page.
- After password/MFA completion, Login resumes that destination only when it is
  an exact `APP_ROUTES` entry and the role on the newly created live session can
  access it. Otherwise it safely falls back to the dashboard.
- The allowlist deliberately performs no URL normalization. External URLs,
  protocol-relative URLs, unknown pages, queries, fragments, and trailing-slash
  variants are not accepted as return destinations, removing open-redirect and
  path-confusion behavior.
- A still-authenticated user whose role no longer permits the requested page is
  sent home rather than through Login. A revoked or expired session is cleared
  and gets the same safe Login return path as a signed-out visitor.
- Verification: 65 focused navigation/login/session/OAuth/password tests and
  all 16 page-smoke tests passed. A live Rio dev boot returned Settings and
  Admin as redirects to their corresponding allowlisted Login destinations,
  and the Login URL rendered successfully.

### 2026-07-11 — Protected destinations survive Google login

- Google sign-in now carries the same exact allowlisted `return_to` value from
  Login through the provider round trip and back into the normal login
  completion path.
- The FastAPI start route validates the destination before putting it in the
  signed OAuth session cookie. The callback reads and removes only that stored
  value; a caller cannot inject a destination into the callback URL.
- Provider errors preserve the safe destination so the user can retry without
  losing context. The final session's live role is still checked before
  navigation, so OAuth does not bypass the authorization fallback added in the
  preceding change.
- Added tests for the signed-cookie round trip, callback-query injection,
  protocol-relative targets, and the Login button's hard-navigation URL.
- Verification: 50 focused OAuth/navigation/live-session tests and all 16
  page-smoke tests passed.

### 2026-07-11 — Real HTTP 404s and API documentation

- Stopped Rio's single-page fallback from turning every unknown browser or API
  URL into a successful HTML response. Unknown browser paths now return a plain
  404, while unknown `/api/*` and `/auth/*` paths return a JSON 404.
- Kept registered public/authenticated pages, Rio's own internal endpoints, and
  explicit FastAPI routes working normally. Path matches with the wrong HTTP
  method still reach FastAPI and return 405 rather than being mislabeled 404.
- Added working `/docs`, `/redoc`, and `/openapi.json` endpoints. The generated
  schema includes only the application `/api/*` and `/auth/*` routes, not Rio's
  internal websocket/assets/cookie machinery.
- This is HTTP routing correctness only. It does not change or attempt to solve
  the excluded crawler-rendering/WebView behavior.
- Verification: the new HTTP-semantics suite passed; 76 health/OAuth/profile/
  currency/page-smoke regression tests passed. A live Rio dev boot returned
  plain 404, JSON 404, Swagger HTML, and OpenAPI JSON for the four corresponding
  probes.

### 2026-07-11 — Public-only robots and sitemap metadata

- Replaced Rio's malformed robots sitemap URL with the canonical configured app
  origin and a stable `/sitemap.xml` endpoint.
- The sitemap now contains only public marketing pages. Login, every protected
  `/app/*` page, API/auth endpoints, and Rio internals are excluded; robots also
  tells crawlers not to visit those private/technical prefixes.
- Rio's legacy `/rio/sitemap.xml` path returns the same public-only document, so
  it can no longer reveal the protected route catalogue while old links settle.
- Generated XML with the standard sitemap namespace and escaped URL text rather
  than assembling XML with raw string interpolation.
- This changes discovery metadata only and does not touch the excluded crawler
  rendering/WebView implementation.
- Verification: the robots/sitemap assertions and all 16 page-smoke tests passed
  as part of a 21-test HTTP/page run.

### 2026-07-11 — First responsive breakpoint crossing

- Initialized each responsive component's mobile/desktop state when Rio creates
  it. Previously the state was initialized lazily on the first resize event,
  which treated the new width as the baseline and missed that first real
  mobile/desktop crossing.
- Kept refreshes limited to actual breakpoint crossings; ordinary resizes on
  the same side still do no rebuild work.
- Relied on Rio's documented parent-first post-init behavior. `CenterComponent`
  does not manually call the parent hook, which would initialize it twice.
- Added both-direction and exact-boundary tests plus same-side no-refresh cases.
- Verification: 7 responsive policy/behavior tests and all 16 page-smoke tests
  passed (23 total).

### 2026-07-11 — Admin UI reacts to locked-write authorization loss

- When a persistence mutation rejects an administrator at the final locked
  authorization check, the Admin page now immediately refreshes the actor's
  real session and role instead of leaving stale controls visible with only an
  error banner.
- A revoked/expired session is detached, its HTTP-only auth token is cleared,
  and the browser returns home. A demoted actor keeps the still-valid session
  with its new role but loses Admin state and is also sent home.
- Ordinary target-level permission denials still leave a currently authorized
  administrator on the page with the friendly error message.
- Added deterministic tests that change authorization after the page precheck
  but immediately before the persistence writer lock, proving no user/audit
  write and the correct revoke-versus-demotion cleanup.
- Verification: 40 admin lifecycle/authorization tests and all 16 page-smoke
  tests passed.

### 2026-07-11 — Truthful admin reset-delivery wording

- Changed the Admin success message from claiming an email was sent to saying
  reset instructions were prepared and directing the operator to the configured
  mailbox or local outbox. That is accurate for both SMTP delivery and the
  built-in development outbox.
- Did not change the synchronous mail/outbox implementation, as that path is an
  explicit remediation exclusion.
- Tightened the lifecycle test to reject the word “sent” while still proving the
  intended recipient, token issuance, and delivery helper call.
- Verification: all 29 admin lifecycle tests passed.

### 2026-07-11 — Bounded, paginated admin user table

- Added stable newest-first `limit`/`offset` support to user listing, with ID as
  a deterministic tie-breaker and explicit rejection of invalid page bounds.
  Existing callers can still request the full list by omitting both arguments.
- The Admin page now counts users, loads only 50 rows at a time, and displays
  bounded Previous/Next controls with page and total counts. It clamps back to
  a valid page after mutations such as deleting the final row on the last page.
- Only the visible page is converted to pandas/Table state. Admin actions still
  resolve targets directly from persistence, so users do not have to be on the
  visible page to be managed.
- Updated the currency listing CLI to pass its existing `--limit` into SQLite
  rather than reading every user and slicing in memory.
- Added persistence tests for stable/non-overlapping pages and invalid bounds,
  Admin state/control tests for forward/back/bounded/clamped navigation, and a
  CLI limit-propagation test.
- Verification: 73 user-listing/admin/rate-limit/bootstrap/page-smoke tests
  passed. A live
  Rio dev boot returned the protected Admin route's expected Login redirect.

### 2026-07-11 — Repository-wide Ruff cleanup

- Moved `.env` loading into `config.py`, before the global configuration object
  is constructed. This preserves early secret loading for every import path
  without executing code between imports in the application entrypoint.
- Removed four genuinely unused imports from the home and audit-log pages.
- Reduced the full repository Ruff result from 17 errors to zero; no rule was
  disabled and no dependency or lint configuration was changed.
- Verification: `ruff check .` passed, followed by 42 health/OAuth/page-smoke
  regression tests.

### 2026-07-11 — Ruff enforced in CI

- Added the official Ruff GitHub Action before dependency installation and the
  pytest step, so new lint regressions fail pull requests and pushes to `main`.
- Pinned Ruff to `0.15.12`, matching the version used for the clean local run,
  instead of letting CI silently change rules with `latest`.
- Kept Ruff out of `requirements.txt`; this workflow-only tool does not change
  application/runtime dependencies.
- Verification: the workflow YAML parsed successfully and local
  `ruff 0.15.12 check .` passed.
