# Railway Deployment Readiness

Status: **not ready for deployments with real users.** The supported production
path today is the VPS guide in `DEPLOYMENT_INSTRUCTIONS.md`. This document
tracks what blocks Railway and how to operate it once unblocked.

## Why Railway is not ready yet

1. **The database is lost on every deploy.** Railway's container filesystem is
   ephemeral. `railway.toml` configures no volume, so the SQLite database at
   `app/app/data/app.db` — along with `email_outbox/` and `contact_messages/` —
   is erased on every deploy and restart. Any users created on such a
   deployment disappear with it.
2. **There is no safe volume mount target.** The fix for (1) is a Railway
   volume, but `app/app/data/` mixes mutable runtime state with the tracked
   sample file `sales_data.csv`. Mounting a volume over the whole directory
   would hide the tracked file from the running app.
3. **First deploy fails closed by design.** The start command runs
   `python -m app.scripts.prestart --strict-bootstrap --require-secure-auth-cookie`.
   It exits on an empty database rather than exposing an unclaimed root slot.
   It also requires secure authentication
   cookies, a canonical HTTPS `APP_URL`, and secure OAuth cookies when Google
   OAuth is configured. These are non-secret code settings: set, test, and
   commit them in `app/app/config.py` before deploying rather than expecting
   Railway environment variables or container-local edits to override them. On
   a fresh volume the service will crash-loop until the root account is
   bootstrapped (see below). This is expected behavior, not a bug.
4. **`railway run` and `railway shell` cannot bootstrap the deployment.** Both
   execute *locally* with Railway's environment variables; they do not touch
   the deployed volume. Bootstrapping must happen inside the deployed
   container.
5. **Multiple replicas require end-to-end session affinity.** Rio sessions,
   browser-binding signatures, and pending cookie-write capabilities are
   process-local. Use one replica unless Railway can keep the initial page GET,
   WebSocket/reconnect traffic, and `POST /rio/cookies` on the same process;
   sharing only a signing key is insufficient.

## TODO: runtime-data relocation

The prerequisite for Railway readiness is separating mutable runtime state from
tracked application files:

- [ ] Move `app.db`, `email_outbox/`, and `contact_messages/` out of
      `app/app/data/` into a dedicated runtime-data directory whose location is
      configured in `app/app/config.py` (defaulting to the current in-repo
      location for local development).
- [ ] Leave tracked sample data (`sales_data.csv`) where the app reads it,
      outside the runtime-data directory.
- [ ] Mount a Railway volume at the configured runtime-data path (e.g.
      `/data`) and point the config at it.
- [ ] Keep the service at one replica, or verify end-to-end affinity for the
      full Rio and secure-cookie request sequence described above.
- [ ] Update this document and remove the warnings in `README.md`,
      `DEPLOYMENT_INSTRUCTIONS.md`, and `railway.toml` once verified.

## Bootstrapping root on Railway (once a volume is mounted)

Public signup and OAuth cannot initialize an empty database; the root account
must be created by an operator against the *deployed* volume:

1. Temporarily override the service start command in the Railway dashboard to
   something inert, e.g. `sleep infinity`, and redeploy so the container stays
   up despite the empty database.
2. Open a shell inside the deployed container with `railway ssh`.
3. From the `app/` directory, run
   `python -m app.scripts.bootstrap_root --email owner@example.com`
   (it prompts for a password if not passed). Ensure it targets the database
   path on the mounted volume.
4. Restore the original start command from `railway.toml` and redeploy. The
   strict prestart check now passes and the public server starts.
5. Only then attach or expose a public Railway domain.
