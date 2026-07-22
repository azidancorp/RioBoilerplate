# rioboilerplate.com: remaining launch work

- **Updated:** 2026-07-20
- **Current HEAD:** `c7865c04d1bda49a156815cbd95f36420c67da94`
- **Verdict:** No-go for real users. The next safe milestone is an owner-only staging deployment protected at the edge.

This file intentionally lists **open work only**. Completed OAuth login binding, Google-account MFA lifecycle, queryless Nginx logging, and global response-security-header work have been removed from the report.

## Remaining blockers

### 1. Replace the fictional public site and fix the crawler homepage

- Replace Buzzwordz copy, invented pricing/support, dummy images, fake testimonials/contact details, inert CTAs, and the premature `Production-ready` claim with an honest RioBoilerplate Features, Demo, Guide, Security, and deployment story. See [`home.py`](../app/app/pages/home.py#L23), [`about.py`](../app/app/pages/about.py#L20), and [`README.md`](../README.md#L3).
- Add Privacy, Cookies, Terms, operator identity, processor/retention details, and public-demo limitations to [`PUBLIC_NAV_ROUTES`](../app/app/navigation.py#L84) and the footer/signup/contact surfaces.
- Remove or isolate the homepage `ExampleJSPage` Webview and add a parser-level regression proving Rio's complete crawler bootstrap survives. See [`home.py`](../app/app/pages/home.py#L273) and [`utils.py`](../app/app/scripts/utils.py#L196).

### 2. Finish the production account-flow policy

- Create a downstream live repository or `live` profile with `APP_URL=https://rioboilerplate.com`, Secure auth/OAuth cookies, required email verification, real external email, an explicitly reviewed password policy, and an intentional Google-login setting. Current defaults remain development-only in [`config.py`](../app/app/config.py#L29).
- Add a real registration gate, or protect owner-only staging with tested edge access control; the stock login page exposes public signup after root bootstrap.
- Exchange password-reset and verification capabilities out of query URLs and scrub browser history. Reset tokens are still emailed and retained as `?reset_token=...`: [`message_utils.py`](../app/app/scripts/message_utils.py#L143), [`login.py`](../app/app/pages/login.py#L1623). Also remove the retained Google account-deletion approval from the Settings URL: [`settings.py`](../app/app/pages/app_page/settings.py#L167).
- Hide local Change Password controls for Google-only users, show Google CTAs only when the provider is fully configured, and make production prestart reject a partially configured enabled provider: [`settings.py`](../app/app/pages/app_page/settings.py#L763), [`prestart.py`](../app/app/scripts/prestart.py#L117).

### 3. Make runtime data and database upgrades durable

- Add one code-configured runtime-data root used consistently by SQLite, health, prestart, bootstrap/CLI tools, contact storage, and backups. SQLite is still hard-coded inside the release tree: [`persistence.py`](../app/app/persistence.py#L41).
- Add monotonic schema versions, transactional historical migrations, and upgrade tests. Startup still consists of piecemeal table creation: [`persistence_schema.py`](../app/app/persistence_schema.py#L15).
- Split liveness/readiness and validate the exact schema, critical indexes/columns, writeability, permissions, and capacity—not only table names: [`health.py`](../app/app/api/health.py#L54).
- Resolve CWD-relative resources such as the dashboard CSV: [`dashboard.py`](../app/app/pages/app_page/dashboard.py#L120).

### 4. Add safe deployment, backup, restore, and rollback

- Replace the in-place `/srv/[APP_NAME]` overlay and reused environment with versioned release directories, a fresh venv, shared runtime state, and an atomic `current` switch. The current procedure begins at [`DEPLOYMENT_INSTRUCTIONS.md`](../DEPLOYMENT_INSTRUCTIONS.md#L193).
- Add encrypted off-host SQLite/contact backups, retention and failure alerts, a pre-deploy backup, restore instructions, and an actual restore rehearsal.
- Retain the previous known-good release and define tested code/schema rollback rules. Track real systemd, Nginx, backup, deploy, and rollback artifacts instead of Markdown snippets alone.

### 5. Produce and prove the exact live release

- Resolve the four untracked audit/planning documents intentionally, then push local commits `4f995a9` and `c7865c0`.
- Require green CI and a downloadable artifact for the final SHA. Remote CI is green through `c03ced2`, but local HEAD is still two commits ahead. Add revision metadata, a running release HTTP/WebSocket/crawler smoke, a release tag, and durable artifact retention: [CI workflow](../.github/workflows/ci.yml#L46).
- Configure apex and `www` DNS, HTTPS/canonical redirects, Cloudflare client-IP handling if proxied, strict production prestart, Resend SPF/DKIM and DMARC, a real inbound mailbox, and all five Google callback URLs if Google remains enabled. Prove query redaction with sentinels in Nginx access/error logs and every CDN/WAF/APM pipeline.
- Prove signup, verification, reset, Google, contact delivery/failure, and root bootstrap through the public origin.

### 6. Remove or label prototype product/service surfaces

- Remove or clearly label the inconsistent sample dashboard, fake News/Notifications, referral field, nonfunctional email/SMS preferences, and production Currency QA navigation. See [`dashboard.py`](../app/app/pages/app_page/dashboard.py#L149), [`navigation.py`](../app/app/navigation.py#L40), and [`settings.py`](../app/app/pages/app_page/settings.py#L735).
- Remove or deliberately document public `GET /api/test`: [`example.py`](../app/app/api/example.py#L23).
- Add strict contact request/body limits and move contact persistence/ntfy off the async event loop; check response status, redact the topic, and monitor failure: [`example.py`](../app/app/api/example.py#L28), [`message_utils.py`](../app/app/scripts/message_utils.py#L380).
- Fix profile clear-vs-omitted semantics and store plain validated text instead of HTML-escaping or rejecting harmless SQL-like phrases in [`validation.py`](../app/app/validation.py#L38).

### 7. Complete public-origin acceptance and operations

- Run current-HEAD desktop/tablet/mobile visual and accessibility QA across public, user, root/admin, auth/error, MFA, and `/docs` states. Brave `9222` is reachable again; the July 18 partial pass was against old HEAD and is not current sign-off.
- Verify browser title/branding, metadata/OG image, favicon, email identity, keyboard/focus/accessibility tree, contrast, mobile overflow, crawler parsing, and WebSockets.
- Load-test SQLite writer contention and document the supported low-traffic, one-process ceiling.
- Add and test-fire uptime, 5xx/restart, disk/database growth, backup age, certificate, and email-delivery alerts; perform the restore/rollback drill before registration opens.

## Current verification snapshot

- Full suite: **694 passed**, one upstream Starlette deprecation warning.
- Ruff 0.15.12, `pip check`, runtime/dev `pip-audit`, and `git diff --check`: clean.
- Git: `main...origin/main [ahead 2]`; four untracked audit/planning documents.
- [`c03ced2` remote CI](https://github.com/azidancorp/RioBoilerplate/actions/runs/29678318227): successful; current local HEAD still needs exact-SHA CI/artifact proof.
- Live DNS check: no apex/`www` address records, MX, or TXT records; `https://rioboilerplate.com` does not resolve.

## Deployment scope and next gate

The supported first release remains one Rio process on an Ubuntu 24.04 VPS with SQLite. Railway, multiple replicas, and supported protected external API clients remain out of scope unless their documented architecture gaps are deliberately implemented; see [`railway-readiness.md`](railway-readiness.md) and [`api-client-authentication.md`](api-client-authentication.md).

Proceed to **owner-only staging** only when the exact-SHA artifact is green, the live profile passes strict prestart, runtime paths are externalized, a verified root exists, DNS/HTTPS and real email work, the whole origin is behind tested edge access control, and public-origin smoke tests pass. Do not open registration to real users until all seven sections above are closed.
