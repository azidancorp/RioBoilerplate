# API Client Authentication

Status: **decided — protected external HTTP clients are not supported until a
concrete consumer and credential model are designed.** Protected profile and
currency operations require `Authorization: Bearer <session token>`, but there
is intentionally no supported way for an external client to obtain one. Public
operations such as health, contact, test, and currency configuration do not use
the `SessionBearer` scheme.

## Current state

1. **Normal web login keeps the credential out of application JavaScript.**
   The session token is stored as `rio.HttpOnly[str]`
   (`app/app/data_models.py`) and delivered as an HTTP-only, `SameSite=Lax`
   cookie (`__Host-` prefixed in production) by
   `app/app/rio_cookie_security.py`. This limits credential theft; it does not
   make an application with an XSS flaw safe.
2. **Protected API operations accept only the bearer header.**
   `app/app/api/auth_dependencies.py` does not fall back to the session cookie,
   so a browser's ambient cookie alone cannot authenticate a protected API
   request.
3. **The transports use the same opaque session credential.** They are not
   separate credential audiences. If the raw value is manually extracted, it
   can be replayed against the API and the web session. HTTP-only storage
   prevents normal JavaScript reads; it does not scope where a stolen value is
   valid.
4. **There is no token-issuance endpoint.** Production sessions are created by
   the Rio login and Google OAuth flows. Stored session tokens are hashed, so
   the raw values cannot be recovered from the database after issuance.
5. **OpenAPI declares the runtime contract.** Protected operations use FastAPI
   `Security(HTTPBearer(...))` with the `SessionBearer` scheme. Generated
   clients therefore know how to attach a credential, but the application does
   not provide them with an acquisition flow.

Do not extract an interactive browser credential for curl, Swagger, or another
client. Besides coupling tooling to Rio's internal cookie serialization, this
undoes the JavaScript-read boundary when the value is pasted into Swagger UI.

## Current application usage

- The stock Rio UI does not depend on protected REST operations over HTTP.
- `app/app/pages/app_page/currency_playground.py` directly invokes currency
  route handlers as a manual QA harness. This is an exception, not the general
  sharing pattern. If the UI and HTTP API need the same behavior, extract an
  application-service function and keep transport concerns in the route.
- API tests create sessions directly with `Persistence.create_session()` to
  verify bearer enforcement. That is test setup, not a client authentication
  flow.

## Adding a supported client

Choose authentication per concrete consumer. A product may support both paths
when their schemes and credentials remain explicitly separate:

1. **First-party same-origin browser client.** Cookie authentication can fit a
   same-origin SPA, but accepting the session cookie on API routes requires a
   complete CSRF policy. Do not perform state changes through `GET`, `HEAD`, or
   `OPTIONS`. For unsafe methods, require an exact `Origin` match to the
   configured canonical origin. If `Origin` is absent, require the origin
   component of `Referer` to match exactly; reject the request if neither proves
   the source origin. Also require a session-bound CSRF token in a custom
   header. Use Fetch Metadata as an additional signal: reject explicit
   cross-site or untrusted same-site requests, and never let a CSRF token
   override an explicit origin mismatch. Treat `SameSite` as defense in depth,
   prefer maintained framework protection where available, and test the policy
   before enforcement. See the
   [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
2. **Mobile, automation, or third-party client.** Issue credentials that are
   separate from interactive Rio sessions and limited by scope. Define secure
   issuance, audit, expiry, rotation, and revocation. If using access and
   refresh tokens, define refresh and reuse handling; if using API keys, define
   expiry/rotation rather than treating them as refresh tokens.

Anti-patterns that undo existing protections:

- Exposing an interactive session token to JavaScript or pasting it into
  Swagger UI.
- Accepting the cookie on API endpoints without CSRF/origin checks.
- Importing FastAPI route handlers as the normal UI/service reuse mechanism.
- Adding a password-accepting `/api/login` without rate limiting, MFA, and
  audit parity with the UI login flow.

## Revisit triggers

- The `app/JSPages/` prototypes (or any browser code) start calling protected
  `/api/*` operations over HTTP.
- A mobile app, CLI, or third-party integration needs programmatic access.
