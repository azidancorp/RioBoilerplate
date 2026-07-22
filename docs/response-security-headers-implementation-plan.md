# Response Security Headers: Minimal Implementation Plan

## Ship decision

Complete this before public release as one middleware-and-tests change. The
release-blocking defect is caching of security-bearing responses, especially the
TOTP provisioning QR. The requested global headers are small defense-in-depth
controls that belong in the same bounded change.

## What the reviews got right—and what to trim

- `/rio/assets/temp/*` currently receives
  `Cache-Control: max-age=31536000, immutable`, and the MFA setup page serves its
  TOTP QR through that route. Both full (`200`) and range (`206`) responses need
  a replacing `no-store` header.
- Every Rio HTML render embeds a fresh one-use session token. Dynamic HTML needs
  `no-store` to prevent cache replay or session/bootstrap misbinding. Do not
  describe every cached response as an automatic session hijack.
- The three OAuth MFA approval-token pages are outside the current sensitive
  prefix list. Modern browsers normally remove the path and query from
  cross-origin referrers, so the claimed leak to every third-party subresource
  is overstated. Same-origin subrequests may still receive the full URL, so a
  global `Referrer-Policy: no-referrer` remains warranted.
- Do not ship a broad `default-src`/`script-src` allowlist. Current Rio needs
  inline JavaScript and `new Function()`, so that policy would require
  `'unsafe-inline'` and `'unsafe-eval'`, add compatibility risk, and should not
  be presented as meaningful XSS remediation. Use only the compatible CSP
  directives with concrete value now.
- `frame-ancestors 'none'` does not break the homepage Webview: this repository's
  only Webview is an inline `srcdoc` child, not this application embedded as a
  framed URL.

## Required implementation

### 1. One application-wide response policy

Change `app/app/http_surface.py`:

1. Replace the sensitive-prefix-only logic with one helper applied to every HTTP
   response by the existing middleware.
2. Apply the same helper in the existing catch-all exception handler so uncaught
   `500` responses have the same policy.
3. Remove the obsolete sensitive-prefix list and `_is_sensitive_path()` helper.
4. Set headers by assignment (`response.headers[name] = value`) so Rio's cache
   header is replaced rather than duplicated.

Set these exact global headers:

```text
Content-Security-Policy: base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()
```

Keep these values as code constants. This CSP provides anti-framing and blocks
objects, base-URL rewriting, and cross-origin form submission; it is not an XSS
remediation.

### 2. Default to `no-store`, with a static-only exception

Set `Cache-Control: no-store` unless all three conditions hold:

- response status is `200` or `206`;
- Rio already set exactly `max-age=31536000, immutable`; and
- the request path starts with one of:

```text
/rio/frontend/assets/
/rio/assets/special/
/rio/assets/hosted/
/rio/assets/user/
/rio/icon/
```

This deliberately excludes `/rio/assets/temp/*`. It also covers dynamic HTML,
APIs, redirects, errors, cookie/token/upload routes, docs, crawler files, and
unknown routes without another sensitive-route denylist. Do not add cache
lifetimes or more exceptions in this change. In particular, the unversioned
`/rio/favicon.png`, `/robots.txt`, and sitemap responses intentionally become
`no-store`; accept the negligible refetch cost rather than invent a cache
policy for them here.

### 3. Pin the contract in the existing test file

Change only `app/tests/test_http_semantics.py` for test coverage:

- Replace the current assertions that ordinary pages lack cache/referrer
  headers.
- Assert the exact global headers on representative HTML, JSON/API, static,
  redirect, `404`, `405`, and uncaught `500` responses.
- Parameterize `/app/enable-mfa`, `/app/disable-mfa`, and
  `/app/recovery-codes` with query tokens; assert `no-store` and `no-referrer`.
- Register a temporary Rio `BytesAsset` through
  `fastapi_app.weakly_host_asset()` while retaining a local reference; assert
  the returned `/rio/assets/temp/*` URL is `no-store` for a normal `200` and
  `Range: bytes=0-3` (`206`). Do not mutate Rio's private `_assets` mapping.
- Assert one allowlisted fingerprinted frontend asset retains Rio's exact
  immutable policy.
- Preserve the `/rio/cookies` contract and prove cache headers are not
  duplicated with
  `response.headers.get_list("cache-control") == ["no-store"]`.

Do not add a `HEAD 200` immutable-asset test. In the installed FastAPI/Rio
route table, `HEAD` against these asset routes is currently `405`, not `200`;
changing that HTTP contract is unrelated to this security work. The existing
representative `405` coverage remains sufficient.

No new test file is needed.

## Verification before commit

Run:

```bash
venv/bin/pytest -q app/tests/test_http_semantics.py app/tests/test_rio_cookie_security.py
venv/bin/pytest -q app/tests/test_smoke_pages.py -x
venv/bin/pytest -q
```

Then run the required release boot from `app/` and probe representative dynamic,
static, redirect, error, MFA-token, and temporary-asset responses. In a real
browser, confirm Rio rendering/WebSocket operation, the homepage inline Webview,
login cookie delivery, MFA QR rendering, and Swagger/ReDoc. There must be no
functional CSP violation; the temp-asset check must include a ranged `206`.

## Explicitly out of scope

- Rio patching/upgrading, nonces, hashes, a strict script CSP, or CSP reporting
- OAuth/query-token redesign or browser-history cleanup
- Nginx duplication of application response policy
- self-hosting third-party assets, SRI, or cache-performance optimization
- additional security-header families, dependencies, environment variables, or
  configuration switches

The change is complete when all application and uncaught-error responses carry
the global policy, every non-allowlisted response is `no-store`, temp assets are
`no-store` for `200` and `206`, allowlisted Rio assets that already carry the
exact immutable policy remain immutable, and the focused/full tests plus
release/browser smoke pass.
