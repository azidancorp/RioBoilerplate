# Google OAuth and TOTP Remediation Plan

Status: implemented and verified

Last verified: 2026-07-20

Scope: minimum code changes needed to make application-managed TOTP work correctly for Google-only accounts and to restore expiry, browser binding, and one-use semantics to the post-Google-login MFA continuation.

Implementation completed on 2026-07-19. Post-review hardening on 2026-07-20:
the three lifecycle pages now populate synchronously so a Google-only user is
never first rendered with password-account UI, callback capture and URL
scrubbing run before the verified-email gate on enrollment, an error callback
no longer erases an already-held approval, and pending-login validation and
consumption now also revalidate the stored provider. Because Rio does not
re-run a synchronous population after same-route replace navigation, the
callback pass falls through and completes initialization (candidate secret,
QR, summary refresh) itself; a real-page Rio regression proves the secret and
QR exist after the URL scrub. Before any page accepts an approval or generates
candidate material, it now non-consumingly revalidates the exact approval and
live application session; final mutations retain atomic one-use consumption.
Final verification: 689 tests passed, the 17 page smoke tests passed, Ruff and
`git diff --check` passed, and a live Rio boot returned the expected login
redirects for all three authenticated MFA pages.

## Objective

Google remains responsible for authenticating the user's Google identity. This application may still require its own TOTP as an additional application-level factor.

The implementation must therefore:

1. Let a Google-only user enroll, disable, and regenerate recovery codes without an impossible local-password check.
2. Require fresh Google reauthentication for those sensitive lifecycle actions.
3. Continue requiring the application's TOTP or a recovery code when disabling TOTP or replacing recovery codes.
4. Preserve the original OAuth pending-login expiry, browser binding, flow binding, and one-use behavior until application TOTP succeeds.
5. Leave password-account behavior unchanged.

## Confirmed defects

### Google-only MFA lifecycle actions are unreachable

`AppUser.create_social_user()` creates Google users with `password_hash=None`. The password gates in:

- `app/app/pages/app_page/enable_mfa.py`
- `app/app/pages/app_page/disable_mfa.py`
- `app/app/pages/app_page/recovery_codes.py`

can therefore never succeed for a Google-only account.

### The post-Google-login MFA continuation is consumed too early

`app/app/pages/login.py` consumes `oauth_pending_logins` when the page loads and gives `SocialMFAForm` only a user UUID. The form no longer holds an expiring, browser-bound, flow-bound, one-use continuation.

A valid TOTP is still required, so this is not a TOTP bypass. However, a serialized duplicate submission using the same still-valid TOTP can create a second session because the OAuth continuation was already discarded.

### Current persistence state transitions are otherwise suitable

The existing enrollment, disable, and recovery-code mutation methods already use fail-closed state checks and `BEGIN IMMEDIATE`. Their provider-neutral behavior should be preserved, not replaced.

The centralized transaction-aware verifier also already exists as `verify_two_factor_challenge_in_transaction()` in `app/app/persistence_auth.py`. Do not create a second verifier or duplicate its TOTP/recovery-code logic.

## Fixed design decisions

### Reuse the existing Google account-deletion reauthentication model

Generalize the current Google account-deletion primitive with a strict internal purpose allowlist:

- `mfa-enable`
- `mfa-disable`
- `recovery-codes-regenerate`

Preserve the existing security properties:

- Google authorization uses `max_age=0`.
- The callback requires a recent Google `auth_time`.
- The returned Google `sub` must match the linked identity.
- The challenge and approval are bound to the exact live application session and user.
- Approval tokens are random, hashed at rest, purpose-bound, short-lived, and one-use.
- Callback destinations are fixed by purpose; no arbitrary return URL is accepted.
- Existing account-deletion wrappers and behavior remain compatible.
- Reuse `oauth_login_handoffs`; do not add a table or schema migration.

### Separate reauthentication freshness from action time

Keep `OAUTH_HANDOFF_TTL_MINUTES = 5` for the Google challenge and `auth_time` freshness check.

Add one code-configured, non-environment setting for MFA lifecycle approvals:

```python
MFA_LIFECYCLE_APPROVAL_TTL_MINUTES = 10
```

Pass this lifetime only when issuing the final MFA approval. Failed form submissions must not extend it.

### Use the existing query-token transport, then scrub it

The OAuth callback may return one purpose-specific token or error parameter to each fixed page:

- `/app/enable-mfa`: `enable_mfa_oauth_token` or `enable_mfa_oauth_error`
- `/app/disable-mfa`: `disable_mfa_oauth_token` or `disable_mfa_oauth_error`
- `/app/recovery-codes`: `recovery_codes_oauth_token` or `recovery_codes_oauth_error`

On population, the page must:

1. Sanitize the query value.
2. Capture it in server-side component state.
3. Immediately navigate to the same clean path with `replace=True`.
4. Continue the synchronous population using only the captured state and live user row; never read the stale query again.

Add a Rio regression proving that same-route replacement preserves the captured server-side token, completes initialization in the same synchronous population pass, and does not remount or reconcile it back to an empty value.

The regression establishes Rio's current contract: same-route `replace=True` scrubs the URL without invoking a second synchronous population pass. If that framework behavior changes, retain the capture-then-scrub ordering and re-evaluate whether the approval must move to a session-scoped attachment.

This removes the token from the visible URL after the page receives it, but it does not prevent initial proxy, access-log, or browser-history exposure. General OAuth URL-secret transport cleanup, including the existing account-deletion flow, remains a separate remediation.

### Enrollment ordering is mandatory

For Google-only users, Google reauthentication must happen before generating the candidate TOTP secret and QR code. A redirect destroys transient component state; generating the secret first could leave the user scanning a secret that the returned page no longer holds.

A syntactically valid approval prefix is not proof of reauthentication. Before generating the candidate secret, non-consumingly validate the exact approval hash, expiry, purpose, provider, user, and live application session. Final enrollment must still revalidate and consume that approval atomically.

## Implementation plan

### 1. Generalize the purpose-bound OAuth reauthentication primitive

Primary files:

- `app/app/persistence_social.py`
- `app/app/api/oauth.py`
- `app/app/config.py`
- `app/app/persistence.py`

Actions:

1. Replace deletion-only internal assumptions with an explicit, closed purpose mapping.
2. Map each purpose to its token prefix, fixed callback page, and final approval lifetime.
3. Keep the normal Google-login consumer unable to consume sensitive-action tokens.
4. Keep the existing account-deletion entrypoints as compatibility wrappers over the generalized primitive.
5. Issue MFA lifecycle approvals with the ten-minute approval TTL while retaining the five-minute Google freshness requirement.
6. Add purpose-specific callback success and error query parameters. Never accept a caller-provided return URL.
   Use these exact names:
   - `enable_mfa_oauth_token` / `enable_mfa_oauth_error`
   - `disable_mfa_oauth_token` / `disable_mfa_oauth_error`
   - `recovery_codes_oauth_token` / `recovery_codes_oauth_error`

### 2. Add caller-transaction MFA mutation helpers

Primary files:

- `app/app/persistence_auth.py`
- `app/app/persistence.py`

Do not refactor or duplicate `verify_two_factor_challenge_in_transaction()`; it already provides centralized in-transaction TOTP and recovery-code verification.

Add a small pure `verify_two_factor_candidate(secret, code)` helper in `app/app/persistence_auth.py` for enrollment. It must reuse the centralized authentication-code sanitizer and TOTP normalization, but it must not read the user's currently persisted factor or accept recovery codes. The Google enrollment composite calls this helper before committing the candidate secret; the page must not implement a second candidate-code verifier.

Instead, extract the mutation bodies of:

- `enroll_two_factor()`
- `disable_two_factor()`
- `generate_recovery_codes()`

into private helpers that require an already-open transaction. The existing public methods must retain their signatures and transaction-owning behavior by opening `BEGIN IMMEDIATE`, calling the new helper, and committing or rolling back as they do today.

Add narrowly scoped composite persistence methods for the Google lifecycle actions. Each composite must perform, in one `BEGIN IMMEDIATE` transaction:

```text
revalidate the exact live application session and active user
revalidate the expected Google provider and current MFA state
consume the correct-purpose, session-bound Google approval
verify the current application TOTP/recovery code when required
perform the existing in-transaction MFA mutation
commit
```

Any invalid code, wrong purpose, expired or replayed approval, stale MFA state, revoked session, or database failure must roll back every state change, including recovery-code and approval consumption.

Enrollment verifies the newly generated candidate secret, not an existing account factor. Add a small persistence-auth helper for candidate-secret TOTP verification near the existing verifier helpers; the centralized current-factor verifier therefore applies to disable and regeneration, not to initial enrollment.

### 3. Fix the three lifecycle pages

Primary files:

- `app/app/pages/app_page/enable_mfa.py`
- `app/app/pages/app_page/disable_mfa.py`
- `app/app/pages/app_page/recovery_codes.py`

Common behavior:

1. Revalidate the mounted application session before every sensitive submission.
2. Branch on the persisted authentication provider, not on UI assumptions.
3. Keep the current password-account path unchanged.
4. For a Google-only account, present `Verify with Google` and use the appropriate purpose-bound approval instead of requesting a local password.
5. Sanitize, capture, and scrub callback query values during population.
6. Preserve the current sensitive-action rate limits and fail-closed stale-state handling.

Enrollment-specific behavior:

1. Start Google reauthentication before generating a secret.
2. Non-consumingly validate the returned approval against the exact live user and application session, then generate the candidate secret and QR.
3. Accept the candidate TOTP and invoke the atomic Google-enrollment composite.
4. On approval expiry, clear the approval token, candidate secret, QR bytes, and entered code. Database recovery codes do not exist until the composite commits, so no persisted cleanup is needed.
5. Return to `Verify with Google` with an actionable expiry message.

Disable-specific behavior:

1. Require a purpose-bound Google approval.
2. Also require the currently configured application TOTP or one recovery code.
3. Atomically consume both proofs and disable the exact live factor.

Recovery-code regeneration behavior:

1. Require a purpose-bound Google approval.
2. Also require the currently configured application TOTP or one recovery code.
3. Atomically consume both proofs and replace codes only for the exact live factor.

Enrollment and regeneration must keep newly committed recovery codes only in component state for their existing one-time display. Acknowledgement, cancellation, navigation away, or remount clears that display state; approval-expiry handling never deletes already committed recovery codes.

### 4. Preserve the pending Google login until MFA succeeds

Primary files:

- `app/app/persistence_social.py`
- `app/app/persistence.py`
- `app/app/pages/login.py`

Add a non-consuming pending-login validation path alongside `consume_oauth_pending_login()`.

Landing behavior:

1. Validate the binding digest, flow ID, provider, original `valid_until`, user existence, and active state.
2. If application TOTP is required, retain the row and display `SocialMFAForm`.
3. Store the binding digest and flow ID in server-side component state in addition to the user UUID.
4. A refresh within the original TTL may rebuild the same form.

Failure behavior:

- Invalid TOTP or recovery-code attempts retain the pending row.
- Failed attempts never update or replace `valid_until`.
- The existing account-scoped `login_mfa_policy` remains the brute-force bound.
- A stale flow ID must fail without deleting a newer same-browser pending flow.
- Expired, missing-user, or inactive-user rows may be deleted and must fail closed.

Success behavior:

1. Open `BEGIN IMMEDIATE`.
2. Revalidate the exact binding digest, flow ID, user, active state, and original expiry.
3. Call `verify_two_factor_challenge_in_transaction()` so recovery-code use is part of the same transaction.
4. Delete the exact pending row only after successful verification.
5. Commit and create the normal application session.

The locked delete is the one-use boundary: a serialized or concurrent duplicate submission must find no remaining continuation and must not create another session. Do not make ordinary 30-second TOTP values globally single-use.

### 5. Correct the misleading step-up guidance

Primary files:

- `app/app/pages/app_page/admin.py`
- `app/app/session_validation.py`

For a Google-only user without TOTP, change the guidance from `Set up a password or 2FA` to `Set up 2FA`. This application has no supported local-password setup path for a Google-only account.

The same string exists in two places: `_step_up_unavailable_message()` in `admin.py` and `verify_step_up_credentials()` in `session_validation.py`. The latter also surfaces through the currency API step-up path, so both sites must be updated.

## Focused test plan

### OAuth approval tests

- Each MFA purpose requests Google with `max_age=0`.
- Missing or stale `auth_time` fails.
- A different Google `sub` fails.
- Wrong user, application session, purpose, or callback flow fails.
- Approval is single-use and stored hashed.
- Five-minute reauthentication freshness remains unchanged.
- MFA approval remains usable for its ten-minute action lifetime only.
- Normal login and account-deletion consumers cannot consume MFA-purpose artifacts, and vice versa.

### Google-only lifecycle tests

Create fixtures with `AppUser.create_social_user()` and assert `password_hash is None`.

- Google-only user enrolls TOTP after recent Google reauthentication.
- Enrollment reauth occurs before candidate secret generation.
- Google-only user disables TOTP after approval plus current TOTP.
- Google-only user disables TOTP with a single-use recovery code.
- Google-only user regenerates recovery codes after approval plus current TOTP/recovery code.
- Invalid code, expired approval, replay, wrong purpose, wrong session, and stale factor all fail without partial mutation.
- Approval expiry during enrollment clears all candidate state and returns to the clean reauthentication step.
- Approval expiry, cancellation, or navigation away clears one-time-display recovery codes held in component state across enrollment and regeneration.
- Query replacement removes approval values from the active URL while preserving captured component state.
- Step-up guidance for a Google-only user without TOTP says `Set up 2FA` from both the admin page and `verify_step_up_credentials()`.
- Password-account behavior remains unchanged.

Do not duplicate the full provider-neutral SQLite race matrix. The existing concurrency and compare-and-swap tests remain authoritative because the Google composites must call the same extracted mutation helpers.

### Pending-login continuation tests

Rewrite the existing social-MFA tests so they create and carry a real pending OAuth continuation rather than constructing `SocialMFAForm` with only a user UUID.

Cover:

- Correct browser and flow succeeds once.
- Serialized duplicate submit creates only one session.
- Concurrent duplicate submit creates only one session.
- Wrong browser or direct form invocation fails.
- Wrong or stale flow ID fails without deleting a newer flow.
- Expiry fails cleanly.
- Refresh within the original TTL works.
- Repeated failed TOTP attempts do not change the original `valid_until`.
- A failed TOTP retains the row; a successful TOTP consumes it.
- A recovery code is consumed exactly once in the successful transaction.
- The social-MFA rate limit blocks a later valid code after the configured bad-attempt threshold.

### Existing regression and smoke tests

The pre-change focused baseline is 116 passing tests across OAuth, MFA transitions, two-factor verification, sensitive-flow rate limits, and mounted-session revalidation.

After implementation, run at minimum:

```bash
pytest app/tests/test_oauth_google.py \
  app/tests/test_oauth_pending_login_atomicity.py \
  app/tests/test_oauth_account_deletion.py \
  app/tests/test_mfa_state_transitions.py \
  app/tests/test_two_factor_verification.py \
  app/tests/test_rate_limit_sensitive_flows.py \
  app/tests/test_mounted_sensitive_session_revalidation.py

pytest app/tests/test_smoke_pages.py -x
```

Then, from the outer `app/` directory, run the required short Rio boot check on an unused port and navigate to the three affected pages.

## Acceptance criteria

The work is complete only when all of the following hold:

- A genuine Google-only user can enroll, disable, and manage recovery codes without a local password.
- Sensitive Google lifecycle actions require a recent, matching Google identity and the exact initiating application session.
- Disable and recovery-code regeneration still require the application's current TOTP or a recovery code.
- Every approval is purpose-bound, expiring, hashed at rest, and usable once.
- MFA enrollment cannot generate its candidate secret before Google reauthentication returns.
- Expired enrollment approval clears all candidate material and restarts cleanly.
- OAuth approval query values are removed after capture without losing server-side state.
- The post-Google-login MFA continuation retains its original TTL and browser/flow binding through failed attempts and refreshes.
- One pending OAuth login can create at most one application session.
- Existing password authentication, account deletion, MFA state-transition, recovery-code, and rate-limit behavior remains green.

## Deliberate exclusions

- Do not add a local password-creation flow for Google users.
- Do not assume Google MFA replaces application TOTP when application policy enables it.
- Do not make TOTP codes globally single-use.
- Do not add tables or schema migrations.
- Do not add arbitrary OAuth return URLs.
- Do not add a durable elevated-session mechanism.
- Do not expand this change into general account-recovery or account-deletion URL-token remediation.
- Do not duplicate provider-neutral concurrency logic or test matrices specifically for Google.
