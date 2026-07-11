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
| Profile mutations | Cross-user profile edits do not consistently enforce the live role hierarchy inside the write transaction. | queued |
| Session lifetime | API bearer authentication accepts a session beyond its absolute maximum lifetime. | queued |
| Password policy | Signup, reset, settings, and admin-created passwords enforce different rules. | queued |
| OAuth account deletion | An OAuth-only user cannot complete self-service account deletion. | queued |
| Browser token storage | The bearer token is exposed to normal browser-side code instead of using Rio's HTTP-only storage marker. | queued |
| OAuth handoffs | A deactivation race can leave a handoff usable after an account is reactivated. | queued |
| Verification tokens | Concurrent email-verification requests can leave more than one live token. | queued |
| Transaction ownership | Some persistence helpers can accidentally commit a caller's unrelated pending work. | queued |
| Expired auth data | Expired sessions and completed/expired OAuth handoffs accumulate indefinitely. | queued |
| Currency rounding | A positive display amount can round to a zero-unit ledger adjustment. | queued |
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
