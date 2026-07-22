# Account Recovery and OAuth URL-Secret Audit and Remediation Plan

Status: **audited and planned; not implemented**

Audit date: 2026-07-17/18

Repository: `/home/azidan/AQL/RioBoilerplate`

## Executive verdict

The finding is substantially correct and should be fixed before relying on the documented production setup.

The highest-risk cases are:

- Password-reset links for accounts without MFA.
- Google OAuth login for accounts without MFA.

A reader who obtains either live token from a proxy, browser, APM, or centralized log can race the legitimate user and take over the account. Email verification is lower impact because its token marks the address verified but does not directly create a login session.

One qualification is important: Uvicorn includes the full query string whenever its access logger is enabled, but the documented `rio run --release` path currently starts Rio quietly and suppresses those INFO access records. Nginx remains exposed under the documented/default configuration.

No remediation code was implemented during this audit.

## The issue from basic principles

A bearer token is a temporary key. Whoever possesses it can use it.

Hashing the token before storing it in SQLite protects the copy sitting in the database. It does not help after the raw key is placed in a URL:

```text
https://example.com/login?reset_token=THE_SECRET_KEY
```

URLs are routing metadata rather than secret containers. They are routinely copied into:

- Reverse-proxy request logs.
- Browser history and synchronized browser history.
- Monitoring, tracing, analytics, CDN, WAF, and APM systems.
- `Referer` headers sent by later requests.
- Redirect records and centralized log pipelines.

Expiry and one-use semantics still help, but “one use” creates a race: the token belongs to whoever redeems it first.

HTTPS does not solve this. HTTPS protects traffic while it crosses the network; it does not stop the browser, Nginx, the application server, or observability systems from recording the URL.

## Current token flows

| Flow | Current transport | Lifetime | What a stolen token grants |
|---|---|---:|---|
| Password reset | `/login?reset_token=...` | 30 minutes | Password change; MFA is still required when enabled |
| Email verification | `/login?verify_token=...` | 24 hours | Marks the account email verified |
| OAuth login handoff | `/login?social_login_token=...` | 5 minutes | Login session for non-MFA users; MFA challenge otherwise |
| OAuth account deletion | Query-string challenge and approval | Short-lived | Session-bound, so lower risk, but still sensitive URL leakage |

### Recovery links

The application creates plaintext recovery URLs in:

- [`app/app/scripts/message_utils.py`](../app/app/scripts/message_utils.py#L127): `verify_token`.
- [`app/app/scripts/message_utils.py`](../app/app/scripts/message_utils.py#L153): `reset_token`.

[`LoginPage.on_populate()`](../app/app/pages/login.py#L1555) reads the OAuth, verification, and reset parameters, but does not immediately replace the URL:

- Verification consumes the token but leaves it in the address bar.
- Password reset retains the token while the user chooses a new password.
- OAuth eventually navigates away, but the current navigation pushes history, so the token URL can remain behind the Back button.
- During the OAuth MFA branch, the consumed handoff remains visible in the current URL.

The recovery-token lifecycle itself is otherwise strong:

- Tokens use UUID4, providing approximately 122 random bits.
- Only SHA-256 hashes are stored.
- Reset tokens expire after 30 minutes; verification tokens expire after 24 hours.
- Issuance and redemption are transactional.
- Reset issuance replaces the previous token and a unique index enforces one reset token per user.
- Successful reset deletes every reset token for that user and revokes existing sessions.
- Verification consumption atomically deletes the token and verifies the active user.

Relevant code:

- Token generation: [`app/app/data_models.py`](../app/app/data_models.py#L217).
- Token hashing: [`app/app/persistence_auth.py`](../app/app/persistence_auth.py#L126).
- Reset completion: [`app/app/persistence_auth.py`](../app/app/persistence_auth.py#L1334).
- Reset issuance: [`app/app/persistence_auth.py`](../app/app/persistence_auth.py#L1502).
- Verification consumption: [`app/app/persistence_auth.py`](../app/app/persistence_auth.py#L1761).
- Lifetimes: [`app/app/config.py`](../app/app/config.py#L85).

Impact differs by token:

- A leaked reset token can take over a non-MFA account. The reset flow resolves the user from the token, so requiring knowledge of the email is not an additional barrier.
- An MFA-enabled reset still requires a current TOTP or recovery code.
- A leaked verification token can mark the address verified but does not itself create a session.

### OAuth handoff

The Google provider callback is properly protected before the application handoff:

- Authlib generates and validates OAuth `state`.
- OIDC nonce validation is enabled by the `openid` scope.
- The temporary OAuth session is signed, HttpOnly, `SameSite=Lax`, and Secure when production configuration requires it.

Relevant code:

- OAuth initiation: [`app/app/api/oauth.py`](../app/app/api/oauth.py#L89).
- Session middleware: [`app/app/__init__.py`](../app/app/__init__.py#L174).
- OAuth client registration: [`app/app/oauth_clients.py`](../app/app/oauth_clients.py#L20).

The security break happens after the protected callback:

1. The callback creates a separate five-minute application handoff in [`app/app/api/oauth.py`](../app/app/api/oauth.py#L292).
2. It redirects to `/login?social_login_token=...` in [`app/app/api/oauth.py`](../app/app/api/oauth.py#L303).
3. The handoff is 256 random bits, hash-only, expiring, one-use, transactional, and account-active-aware.
4. [`consume_oauth_handoff()`](../app/app/persistence_social.py#L437) validates the token but does not validate the browser or session that initiated Google login.
5. Any fresh browser possessing the handoff can therefore redeem it first.

For an account without MFA, successful redemption creates an authenticated application session. For an MFA-enabled account, it reaches the MFA challenge but still requires the second factor.

The existing Rio browser-binding cookie does not currently protect this flow. A new browser is simply given its own valid binding, and the OAuth handoff is never compared with the initiating binding. The reusable binding implementation is in [`app/app/rio_cookie_security.py`](../app/app/rio_cookie_security.py#L458).

### OAuth account deletion

Two adjacent account-deletion capabilities also enter URLs:

- The challenge is placed in `/auth/google/delete-account?deletion_challenge=...` by [`app/app/pages/app_page/settings.py`](../app/app/pages/app_page/settings.py#L62).
- The approval is returned in `/app/settings?delete_account_oauth_token=...` by [`app/app/api/oauth.py`](../app/app/api/oauth.py#L37).

These values are purpose-, identity-, and exact-app-session-bound, so a log reader without the authenticated application session cannot normally use them. They are lower severity than `social_login_token`, but should be removed from URLs as part of the same hygiene work.

## Confirmed exposure surfaces

### Nginx

The documented configuration in [`DEPLOYMENT_INSTRUCTIONS.md`](../DEPLOYMENT_INSTRUCTIONS.md#L498) has no explicit safe `log_format` or `access_log` override.

Standard Nginx `combined` logging contains both `$request` and `$http_referer`:

- `$request` includes the complete query string.
- `$http_referer` can contain a token-bearing same-origin page URL.

The documented HTTP and `www` redirects also preserve `$request_uri`, including its arguments.

Therefore, unless a deployed global Nginx configuration overrides the repository guide, a normal inherited access log records these secrets. The exact live `/etc/nginx/nginx.conf`, CDN, WAF, APM, and central-log configuration was not inspected and must be verified separately.

Reference: [Nginx access-log documentation](https://nginx.org/en/docs/http/ngx_http_log_module.html).

### Uvicorn and Rio

The installed Uvicorn builds its access-log request target from the path plus raw query string:

- `venv/lib/python3.12/site-packages/uvicorn/protocols/utils.py:58-62`
- `venv/lib/python3.12/site-packages/uvicorn/protocols/http/h11_impl.py:480-488`
- `venv/lib/python3.12/site-packages/uvicorn/protocols/http/httptools_impl.py:483-491`

However, the installed Rio CLI defaults to `quiet=True` and configures Uvicorn at ERROR level when quiet:

- `venv/lib/python3.12/site-packages/rio/cli/__init__.py:131-138`
- `venv/lib/python3.12/site-packages/rio/cli/run_project/uvicorn_worker.py:67-72`

The documented systemd service uses ordinary `rio run --release`, so Uvicorn INFO access records are currently suppressed on that supported path. Direct Uvicorn, non-quiet Rio, or a different runner would expose the full query.

Reference: [Uvicorn logging settings](https://www.uvicorn.org/settings/).

### Browser, referrer, and caching

A temporary-database HTTP probe confirmed that `GET /login?reset_token=<sentinel>` returns `200` without either of these headers:

- `Cache-Control: no-store`
- `Referrer-Policy: no-referrer`

The application currently has no general sensitive-page header middleware. Existing `no-store` handling is limited to Rio cookie endpoints.

Without an explicit referrer policy, the browser default can forward the complete same-origin path and query to subsequent favicon, JavaScript, CSS, API, or WebSocket-related requests. Standard Nginx combined logging can then duplicate the secret across multiple records.

Each protection addresses a different copy:

- `Cache-Control: no-store` prevents caches from retaining the response.
- `Referrer-Policy: no-referrer` prevents later requests from forwarding the page URL.
- History replacement removes the sensitive current browser-history entry.
- Queryless logging prevents the initial edge/application request from recording the query.
- Eliminating bearer secrets from request URLs prevents the source exposure.

No one control substitutes for the others. In particular, `history.replaceState` cannot erase the Nginx entry already written for the initial request.

References:

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [MDN Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [MDN Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control)
- [MDN history.replaceState](https://developer.mozilla.org/en-US/docs/Web/API/History/replaceState)

### Secondary exception exposure

Invalid, expired, and inactive reset-token exceptions currently interpolate the raw token in [`app/app/persistence_auth.py`](../app/app/persistence_auth.py#L1629).

Known UI callers swallow these exceptions rather than logging them, so this is not a demonstrated current access-log leak. It is nevertheless an unsafe logging footgun and should be replaced with generic exception text.

## Recommended architecture

The fix requires four independent layers:

1. Stop transporting the OAuth login bearer in a URL.
2. Prevent recovery tokens from entering or remaining in request URLs and browser state.
3. Make application and infrastructure logging queryless.
4. Apply `no-store`, `no-referrer`, and immediate history replacement.

### Browser-bound OAuth continuation

Replace `social_login_token` with a server-side pending login bound to the existing signed HttpOnly browser-binding cookie:

1. At Google-login initiation, require or create exactly one valid Rio browser binding.
2. Store its digest in the signed OAuth session with the allowlisted return destination.
3. At callback, let Authlib validate `state` and OIDC nonce, then compare the current binding with the initiating digest.
4. Create a five-minute database pending-login record keyed to the binding digest and user. Do not return its random token to the browser.
5. Redirect with `303` to clean `/login`, preserving only a validated non-secret `return_to`.
6. Let `LoginPage` read the HttpOnly binding server-side and atomically consume only that browser's pending login.
7. Preserve the current expiry, one-use, transaction, active-user, MFA, recovery-code, and session-creation behavior.
8. Reject legacy `social_login_token` URLs and instruct the user to restart Google login.

Do not merely move the same unbound bearer into another cookie. Do not bind it to an IP address or User-Agent; both are unstable and forgeable.

The provider callback will still contain Google's authorization `code` and `state`, so queryless logging remains necessary. Explicit PKCE using S256 should also be enabled as defense in depth. Current OAuth security guidance recommends PKCE for confidential clients and discusses code/state leakage through browser history and referrers.

Reference: [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700).

### Recovery fragment-to-POST exchange

For new reset and verification emails, use a fragment rather than a query:

```text
/auth/recovery/reset#token=...
```

The fragment is not transmitted in the HTTP request. A minimal same-origin recovery landing page should:

1. Read the fragment locally.
2. Immediately replace the browser URL with a clean URL.
3. POST the token in the request body to an exchange endpoint.
4. Validate and consume or claim it atomically.
5. Redirect to a clean application URL.

For password reset, exchange the original token for short-lived, HttpOnly, browser-bound recovery state. The original token should become unusable after exchange, but the account password must not change until the user submits the new password and any required MFA proof.

For email verification, POST and consume the token before redirecting to a clean, non-secret success or failure status.

Manual token entry should remain as a fallback and use the same POST exchange.

Outstanding query-based links need an explicit cutover choice:

- Invalidate them at deployment and require users to request a new email; or
- Accept them for no more than one existing TTL through an immediate exchange-and-clean redirect, but only after every logging layer is queryless.

### Account-deletion continuation

Remove both account-deletion query values:

1. Derive the live application session from its HttpOnly auth state when reauthentication begins.
2. Store the challenge server-side and carry its identity through the signed OAuth session.
3. On callback, store a pending deletion approval keyed to the existing application-session hash.
4. Redirect cleanly to `/app/settings`.
5. Let Settings discover and consume the pending approval through its authenticated session.

## Approval-gated implementation plan

### Phase 1: Add logging and response-header foundations

- Add application middleware for `/login`, recovery endpoints, OAuth initiation/callback/error redirects, and the affected Settings flow.
- Apply `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on success, invalid, expired, redirect, and error responses.
- Add a referrer meta-tag fallback to any minimal recovery landing document.
- Keep ordinary immutable/static-asset caching unchanged.
- Define an Nginx `log_format` in the `http` context using method, `$uri`, protocol, status, response size, and timing.
- Exclude `$request`, `$request_uri`, `$args`, `$query_string`, and `$http_referer`.
- Apply the named format explicitly to the HTTP redirect, `www` redirect, and canonical proxy server.
- Stop noncanonical redirects from copying sensitive query arguments.
- Make Rio quiet mode explicit in the systemd command.
- Require `--no-access-log` or an audited queryless logging configuration for any supported direct-Uvicorn launch.

### Phase 2: Replace the OAuth handoff

- Extend persistence for pending logins owned by a browser-binding digest.
- Capture and validate the initiating browser binding through the signed OAuth session.
- Replace `social_login_token` redirects with clean `303 /login` redirects.
- Consume the pending login by binding rather than a URL token.
- Preserve safe `return_to`, MFA, recovery-code, inactive-account, expiry, cleanup, and atomicity behavior.
- Add explicit PKCE S256.
- Fail closed on missing, malformed, duplicate, or changed binding.
- Ensure a failed attacker redemption attempt does not destroy the legitimate browser's pending login.

### Phase 3: Replace recovery URL transport

- Add fragment-based reset and verification landing endpoints.
- Implement immediate fragment removal and token POST exchange.
- Store only hashed, expiring, one-use server-side recovery state bound to an HttpOnly browser session.
- Update email links while preserving manual token entry.
- Ensure malformed, expired, already-used, and inactive-user outcomes never redisplay or log the token.
- Preserve the existing password policy, MFA, atomic password update, sibling-token deletion, and session revocation guarantees.

### Phase 4: Remove adjacent query capabilities and exception leaks

- Move account-deletion challenge and approval state server-side.
- Remove raw reset tokens from exception messages.
- Centralize a sensitive-parameter inventory for legacy rejection, URL scrubbing, and regression tests.
- Do not use that inventory as the primary logging defense; dropping all query strings is safer than maintaining a denylist.

### Phase 5: Add security-property tests

OAuth and persistence tests:

- The correct initiating browser completes login.
- A second browser cannot redeem the pending login.
- Missing, wrong, changed, and duplicate bindings fail safely.
- Expired and replayed continuations fail.
- Concurrent redemption remains atomic and exactly one use wins.
- Inactive or deleted users cannot complete login.
- MFA and recovery-code behavior remains unchanged.
- Pending state remains hash-only and is cleaned up safely.

HTTP and browser tests:

- No `Location` header contains `social_login_token`, reset tokens, verification tokens, deletion challenges, or deletion approvals.
- Every sensitive success, failure, expiry, malformed-input, and redirect response has `no-store` and `no-referrer`.
- The address bar is clean before user think-time.
- Back and Reload do not restore a secret URL.
- Same-origin assets and API requests send no secret-bearing `Referer`.
- Legacy links are immediately exchanged or rejected and scrubbed.
- A two-browser test proves a stolen continuation cannot authenticate.

Logging tests:

- Uvicorn h11 and httptools access logs contain method, path, and status but not sentinel query values whenever a supported logger is enabled.
- The documented Nginx format contains none of the query/referrer variables.
- `nginx -t` passes.
- End-to-end sentinel requests through HTTPS, HTTP, and `www` leave no sentinel in Nginx access/error logs, journald, APM, or centralized logs.
- The sentinel must be a non-production test value and should not be printed unnecessarily while searching logs.

Existing test surfaces likely to change or expand include:

- `app/tests/test_oauth_google.py`
- `app/tests/test_oauth_account_deletion.py`
- `app/tests/test_oauth_handoff_atomicity.py`
- `app/tests/test_auth_email_flows.py`
- `app/tests/test_password_reset_token_lifecycle.py`
- `app/tests/test_http_semantics.py`
- `app/tests/test_rio_cookie_security.py`
- `app/tests/test_smoke_pages.py`

### Phase 6: Full verification

- Run focused recovery, OAuth, persistence, header, and logging tests.
- Run the complete pytest suite.
- Run Ruff and `git diff --check`.
- Run `pytest app/tests/test_smoke_pages.py -x`.
- Boot Rio in development and release mode from the outer `app/` directory.
- Probe `/login`, recovery endpoints, OAuth redirects, `/api/health`, and affected settings behavior.
- Perform real two-browser OAuth and browser-history/referrer checks.
- Validate the final Nginx configuration and inspect the actual configured log pipeline.

### Phase 7: Rollout and containment

1. Deploy edge/proxy logging changes before application changes so no additional token-bearing requests are recorded during compatibility rollout.
2. Deploy the application headers and clean continuation flows.
3. Invalidate outstanding OAuth handoffs.
4. Decide whether to invalidate existing reset/verification tokens or support them for one bounded TTL under safe logging.
5. Audit historical Nginx, journal, CDN, WAF, APM, and centralized logs for prior exposure.
6. Restrict access and apply the organization's retention/deletion procedure to affected logs.
7. Run non-production sentinel probes after deployment and after every future logging-stack change.

## Likely implementation surfaces

- `app/app/__init__.py`
- `app/app/api/oauth.py`
- A new recovery API/landing module
- `app/app/persistence_social.py`
- `app/app/persistence_auth.py`
- `app/app/persistence_schema.py`
- `app/app/rio_cookie_security.py`
- `app/app/pages/login.py`
- `app/app/pages/app_page/settings.py`
- `app/app/scripts/message_utils.py`
- OAuth, recovery, header, logging, and smoke tests
- `DEPLOYMENT_INSTRUCTIONS.md`

## Acceptance criteria

The remediation is complete only when all of the following are true:

- No application-issued bearer or sensitive action capability appears in a request URL or redirect `Location`.
- Google login can be completed only by the browser session that initiated it.
- Reset and verification email tokens never enter normal HTTP request targets for newly issued links.
- Legacy sensitive query URLs are immediately scrubbed and operate only under queryless logging for a bounded compatibility period.
- Sensitive documents, redirects, and errors consistently return `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- Nginx and every supported application runner omit query strings and referrers from access logs.
- Centralized observability systems are verified rather than assumed safe.
- Browser history, Back, Reload, referrer, and two-browser tests pass.
- Existing token strength, hash-only storage, expiry, atomicity, one-use, MFA, password-reset, and session-revocation guarantees remain intact.
- Full tests, lint, smoke checks, release boot, Nginx validation, and live sentinel checks pass.

## Audit boundary and repository state

The audit inspected the live repository, installed Rio/Uvicorn/Authlib behavior, the documented Nginx/systemd path, current persistence guarantees, and focused existing tests. It did not inspect a deployed production host or third-party logging pipeline.

Focused recovery and OAuth tests passed during the audit; this was not a full-suite verification.

The worktree already contained unrelated concurrent edits, including changes to `message_utils.py`, configuration, deployment documentation, and email-delivery tests. Those edits were preserved. Any approved implementation should use isolated hunks, re-read the then-current files, and avoid staging or overwriting unrelated work.

No commit or push is part of this plan unless separately requested.
