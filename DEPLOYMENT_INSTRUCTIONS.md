# Rio Application Production Deployment Guide

Complete step-by-step instructions for deploying a Rio/FastAPI application to a DigitalOcean droplet with HTTPS and WebSocket support.

> **Note:** This VPS guide is the supported production deployment path. The Railway configuration in `railway.toml` is **not yet ready for deployments with real users** — the SQLite database has no persistent volume target and is lost on every deploy. See `docs/railway-readiness.md` for the outstanding work.

## Prerequisites

- DigitalOcean droplet running Ubuntu 24.04 LTS (Python 3.12)
- Domain name with DNS management access
- Local application files ready for deployment
- SSH access to the droplet

Ubuntu 24.04 LTS is used deliberately: Canonical lists standard maintenance
through May 2029, and Noble provides Python 3.12, matching this repository's CI.
See the official [Ubuntu release cycle](https://ubuntu.com/about/release-cycle?product=ubuntu&release=ubuntu&version=24.04+LTS)
and [Noble Python 3.12 package](https://packages.ubuntu.com/noble/python3.12).

## Variables to Replace

Throughout this guide, replace these variables with your actual values:
- `[DOMAIN_NAME]` - Your domain (e.g., `example.com`)
- `[DROPLET_IP]` - Your droplet's public IP address
- `[EMAIL]` - Your email for SSL certificate notifications
- `[LOCAL_APP_PATH]` - Path to your local application files
- `[APP_NAME]` - Name for your systemd service
- `[APP_USER]` - Dedicated no-login service account (e.g., `rioapp`)
- `[SSH_ALIAS]` - Short name for SSH connection (e.g., `mysite`)
- `[USERNAME]` - Your local Windows username when using the shown config path
- `[KEY_FILE]` - Filename of an optional custom SSH private key

## Step 0: Configure SSH for Easy Access (Optional but Recommended)

Set up SSH configuration on your **local machine** for easy connections:

### Windows (PowerShell/WSL) or Linux/Mac

```bash
# Create or edit SSH config file
# Windows: C:\Users\[USERNAME]\.ssh\config
# Linux/Mac: ~/.ssh/config
nano ~/.ssh/config
```

**Add this configuration block:**
```
Host [SSH_ALIAS]
    HostName [DROPLET_IP]
    User root
```

**Example configuration:**
```
Host myapp
    HostName 123.456.789.012
    User root
```

**Optional: Add SSH key for passwordless access:**
```bash
# Generate SSH key pair (if you don't have one)
ssh-keygen -t rsa -b 4096 -C "[EMAIL]"

# Copy public key to server
ssh-copy-id -i ~/.ssh/id_rsa.pub root@[DROPLET_IP]

# Or manually copy the key
cat ~/.ssh/id_rsa.pub | ssh root@[DROPLET_IP] "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

**If using a custom key file, add IdentityFile to your config:**
```
Host [SSH_ALIAS]
    HostName [DROPLET_IP]
    User root
    IdentityFile ~/.ssh/[KEY_FILE]
```

**Test the connection:**
```bash
# Now you can connect easily using the alias
ssh [SSH_ALIAS]

# Example
ssh myapp
```

## Step 1: Domain DNS Configuration

Configure DNS A records at your domain registrar:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | @ | [DROPLET_IP] | 3600 |
| A | www | [DROPLET_IP] | 3600 |

**Verify DNS propagation:**
```bash
dig [DOMAIN_NAME]
```

**Expected Output:**
```
;; ANSWER SECTION:
[DOMAIN_NAME].		3600	IN	A	[DROPLET_IP]
```

**Common Issues:**
- **DNS not propagated yet**: Wait 5-30 minutes and try again
- **Wrong IP returned**: Double-check DNS records at your registrar
- **No answer section**: DNS records may not be set correctly

## Step 2: Initial Server Setup

SSH into your droplet and prepare the environment:

```bash
# Connect to server (use your SSH alias if configured)
ssh [SSH_ALIAS]
# OR
ssh root@[DROPLET_IP]

# Update system packages
apt update && apt upgrade -y

# Install essential packages
apt install -y python3 python3-pip python3-venv git nginx ufw certbot python3-certbot-nginx ssl-cert

# Create the non-login account that will run the application
useradd --system --user-group --home-dir /srv/[APP_NAME] --shell /usr/sbin/nologin [APP_USER]
install -d -o root -g [APP_USER] -m 0750 /srv/[APP_NAME]

# Configure firewall
ufw allow OpenSSH
ufw allow 'Nginx Full'  # Opens ports 80 & 443
ufw --force enable

# Verify firewall status
ufw status
```

**Expected Output:**
```bash
# After system update
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.

# After package installation
The following NEW packages will be installed:
  certbot nginx python3-certbot-nginx python3-pip python3-venv ssl-cert ufw
...
Processing triggers for ufw (0.36.2-1) ...

# After firewall configuration
Status: active

To                         Action      From
--                         ------      ----
OpenSSH                    ALLOW       Anywhere
Nginx Full                 ALLOW       Anywhere
OpenSSH (v6)               ALLOW       Anywhere (v6)
Nginx Full (v6)            ALLOW       Anywhere (v6)
```

**Common Issues:**
- **Package installation fails**: Run `apt update` first, check internet connection
- **UFW already active**: That's fine, existing rules will be preserved
- **Permission denied**: Provisioning commands in this step require root/sudo

## Step 3: Deploy Application Files

Deploy the release artifact produced by the successful `CI` run for the exact
commit. The artifact contains only committed source, the runtime SBOM, and the
hash-verified Linux/Python 3.12 wheelhouse used for installation. Do not rebuild
dependencies from the public package index on the production server.

Before running these commands, complete the production-behavior review in
Step 3.7 in your **local checkout**, test the resulting configuration, and
commit it. Non-secret settings such as `APP_URL` and secure-cookie policy are
part of the deployed source; do not customize tracked Python files only on the
server, because the next artifact deployment will overwrite those edits.

```bash
# On your local machine, download the named artifact from the successful main
# branch run. Use the run ID and full commit SHA shown by GitHub Actions.
gh run download [RUN_ID] \
  --repo [GITHUB_REPOSITORY] \
  --name rio-boilerplate-[COMMIT_SHA] \
  --dir release
cd release
sha256sum -c rio-boilerplate-release.tar.gz.sha256
scp rio-boilerplate-release.tar.gz [SSH_ALIAS]:/tmp/

# On the server, unpack into a fresh root-only staging directory.
rm -rf /tmp/[APP_NAME]
install -d -m 0700 /tmp/[APP_NAME]
tar -xzf /tmp/rio-boilerplate-release.tar.gz -C /tmp/[APP_NAME]

# Install root-owned source and app-owned writable directories.
chown -R root:root /tmp/[APP_NAME]
cp -a /tmp/[APP_NAME]/. /srv/[APP_NAME]/
install -d -o [APP_USER] -g [APP_USER] -m 0750 \
  /srv/[APP_NAME]/app/app/data \
  /srv/[APP_NAME]/.local/share/rio-boilerplate
rm -rf /tmp/[APP_NAME]

# Build from the CI-produced wheelhouse without contacting a package index.
python3 -m venv /srv/[APP_NAME]/venv
/srv/[APP_NAME]/venv/bin/pip install \
  --no-index \
  --find-links /srv/[APP_NAME]/wheelhouse \
  --require-hashes \
  -r /srv/[APP_NAME]/requirements.txt

# Example structure on server should be:
# /srv/[APP_NAME]/
# ├── app/           # Main application files
# │   ├── rio.toml   # Rio configuration
# │   └── ...
# └── venv/          # Python virtual environment
```

Successful artifact transfer is quiet. On the server,
`test -x /srv/[APP_NAME]/venv/bin/rio` should exit successfully after the
installation finishes.

**Common Issues:**
- **Permission denied**: Check SSH access and target directory permissions
- **Artifact not found**: Verify the main-branch CI run succeeded and that the
  artifact name contains the run's full commit SHA
- **Wrong target platform**: The supplied wheelhouse targets the CI runner's
  Linux x86-64/Python 3.12 environment; use a matching production host
- **Connection timeout**: Check network connection and SSH configuration

## Step 3.5: Configure Environment

```bash
# From the application directory
cd /srv/[APP_NAME]
[ -f .env ] || cp .env.example .env
nano .env
chown root:[APP_USER] .env
chmod 0640 .env
```

Add any deployment-specific secrets required by the providers you enable.

Google OAuth requires `SESSION_SECRET_KEY` in addition to the Google client
credentials. Generate it once with the command below, copy the result into
`.env`, and keep the same value across restarts and application instances:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

This key signs the temporary OAuth state/nonce cookie. Changing it invalidates
OAuth attempts already in progress, which users can restart.

Email delivery is selected explicitly with `EMAIL_METHOD` in
`app/app/config.py`. Keep `outbox` only for local development. For production,
choose `resend` (recommended) and set `RESEND_API_KEY` in `.env`, or choose
`smtp` and configure its host, sender, TLS, and optional username in
`config.py` plus `RIO_SMTP_PASSWORD` in `.env`. Provider failures never fall
back to local token-bearing files. Use a sending-only Resend API key rather
than a full-access key.

> **Existing SMTP deployments:** Before deploying this version, set
> `EMAIL_METHOD = "smtp"` beside the existing `SMTP_*` settings and add
> `--require-production-email` to the installed systemd `ExecStartPre`. Run
> `systemctl daemon-reload` before restarting. SMTP is no longer inferred from
> `SMTP_HOST`.

> **Note:** Other behavior settings (email validation, username login, currency names, password policy) are hardcoded in `app/app/config.py`. Review, test, and commit those changes before the Step 3 release artifact is built. See `docs/configuration/email-validation.md` for the email/username validation knobs.
> **Note:** Email provider method/host/sender/TLS defaults also live in `app/app/config.py`; only secret values such as `RESEND_API_KEY` and `RIO_SMTP_PASSWORD` belong in `.env`.
> **Note:** The SQLite database file is created locally on first run at `app/app/data/app.db` and is not intended to be committed.

## Step 3.6: Initialize the First Root User

Before exposing the app publicly, create the initial verified owner account from the server shell:

```bash
cd /srv/[APP_NAME]/app
sudo -u [APP_USER] -H env PYTHONDONTWRITEBYTECODE=1 \
  ../venv/bin/python -m app.scripts.bootstrap_root
```

With no arguments, the command prompts for email and password. You can also
pass values directly:

```bash
sudo -u [APP_USER] -H env PYTHONDONTWRITEBYTECODE=1 \
  ../venv/bin/python -m app.scripts.bootstrap_root \
  --email owner@example.com --password '<strong-password>'
```

`--username owner` is optional; if you provide `--username` without `--email`,
that username becomes the root login identifier. If users already exist, the
command exits successfully without changing anything.

This CLI is the only supported initial-root creation path. Password signup and OAuth account creation are blocked while the database is empty. Run it before anything else creates users; it deliberately refuses to modify a database that already contains accounts.

`--allow-weak-password` records the same explicit warning acknowledgement used
by signup, reset, Settings, and Admin. Without it, a root password that triggers
one or more quality warnings is not created. It does not override an operator-set
`ALLOW_WEAK_PASSWORDS = False`.

## Step 3.7: Production Hardening Checklist

Although this checklist is grouped with deployment configuration, complete it
in the **local checkout before Step 3**. The boilerplate ships with
developer-friendly defaults that are convenient for local work but **must be
reviewed before public exposure**. These are non-secret behavior flags, so they
live in `app/app/config.py`: edit them locally, run the relevant tests and
prestart check, commit the intended production values, and then deploy that
commit. Do not leave production-only edits in `/srv/[APP_NAME]`.

Review each setting:

| Flag (`app/app/config.py`) | Default | Recommended for production |
| --- | --- | --- |
| `APP_URL` | `http://localhost:8000` | `https://[DOMAIN_NAME]` — the one canonical public origin. The Nginx example below redirects `www` to this apex origin. |
| `AUTH_TOKEN_COOKIE_SECURE` | `False` | `True` — required so the browser authentication cookie is never sent over plaintext HTTP. `APP_URL` must also be the canonical public `https://` URL; the supported production prestart command fails closed otherwise. |
| `OAUTH_COOKIE_SECURE` | `False` | `True` when Google OAuth is configured — required so its state/nonce cookie is only sent over HTTPS. |
| `EMAIL_METHOD` | `outbox` | `resend` or `smtp`. The production prestart check rejects the development-only outbox and incomplete or insecure provider configuration. |
| `DEFAULT_EMAIL_SENDER` | `no-reply@rio.local` | A valid address on the sending domain configured with your provider. |
| `REQUIRE_EMAIL_VERIFICATION` | `False` | `True` — required so nobody can create a usable account on an email address they do not own (an unverified squatter blocks the real owner's signup and Google sign-in). Needs the working external email provider from Step 3.5; the supported production prestart command fails closed otherwise. Enabling two-factor authentication also requires a verified email. |
| `ALLOW_WEAK_PASSWORDS` | `True` | `True` warns and requires acknowledgement but preserves user choice. Set `False` only if this deployment deliberately wants every quality warning to become a hard rejection. |
| `MIN_PASSWORD_LENGTH` | `15` | Advisory minimum. Shorter non-empty passwords show a warning and remain usable after acknowledgement while `ALLOW_WEAK_PASSWORDS` is `True`. |
| `MAX_PASSWORD_LENGTH` | `1024` | Advisory analysis limit. Longer passwords skip deeper quality analysis, show a warning, and are still hashed in full after acknowledgement. |
| `PASSWORD_STRENGTH_WARNING_THRESHOLD` | `50` | Scores below this value add a warning and require acknowledgement; the score is not independently an authorization rule. |
| `RATE_LIMIT_TRUST_PROXY_HEADERS` | `False` | `True` **only** when behind the trusted reverse proxy configured in Step 6, so per-IP rate limits use the real client IP. See the rate-limiting note later in this guide. |
| `SESSION_ABSOLUTE_MAX_DAYS` | `30` | Absolute session lifetime ceiling. Lower it for stricter re-auth cadence, or set `0` to disable the cap. |

## Step 4: Test Application

SSH back into the server and test the application:

```bash
# Navigate to application directory
cd /srv/[APP_NAME]/app

# Test application locally
# Note: --release flag enables production optimizations (faster performance,
# lower memory usage, and additional safety checks)
APP_PORT=8000
sudo -u [APP_USER] -H env PYTHONDONTWRITEBYTECODE=1 \
  ../venv/bin/python -m app.scripts.prestart --strict-bootstrap \
  --require-secure-auth-cookie --require-production-email \
  --require-email-verification
sudo -u [APP_USER] -H env PYTHONDONTWRITEBYTECODE=1 \
  XDG_CACHE_HOME=/tmp/[APP_NAME]-cache \
  ../venv/bin/rio run --port "$APP_PORT" --release --quiet

# Verify it's working from another terminal with the same port value.
APP_PORT=8000
curl -fsS "http://127.0.0.1:${APP_PORT}/api/health"

# Test the browser page through the public HTTPS origin after Nginx and
# Certbot are configured. Production browser cookies intentionally do not
# round-trip through this direct plaintext backend address.

# Stop the test (Ctrl+C)
```

**Expected Output:**
```bash
# Rio startup output
  _____  _
 |  __ \(_)
 | |__) |_  ___
 |  _  /| |/ _ \
 | | \ \| | (_) |
 |_|  \_\_|\___/

Starting...
Running in local mode. Only this device can access the app.
The app is running at http://127.0.0.1:8000

# health check output
{"status":"ok","checks":{"app":"ok","database":"ok","schema":"ok"}}

```

**Common Issues:**
- **"Couldn't find rio.toml"**: Make sure you're in the correct app directory
- **Module import errors**: Check virtual environment is activated and dependencies installed
- **Port already in use**: Another service might be using port 8000, try a different port
- **Health request fails**: Check the Rio process output and the selected port

## Step 5: Create systemd Service

Create a systemd service for automatic startup and management:

```bash
# Create service file
nano /etc/systemd/system/[APP_NAME].service
```

**Service file content:**
```ini
[Unit]
Description=Rio App for [DOMAIN_NAME]
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=[APP_USER]
Group=[APP_USER]
WorkingDirectory=/srv/[APP_NAME]/app
Environment=HOME=/srv/[APP_NAME]
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=XDG_CACHE_HOME=/tmp/[APP_NAME]-cache
# --release provides production optimizations and safety checks; --quiet
# explicitly suppresses HTTP access logs and routine server noise.
# Required: verify schema, root ownership, secure cookies, external email,
# and enforced signup email verification
ExecStartPre=/srv/[APP_NAME]/venv/bin/python -m app.scripts.prestart --strict-bootstrap --require-secure-auth-cookie --require-production-email --require-email-verification
ExecStart=/srv/[APP_NAME]/venv/bin/rio run --port 8000 --release --quiet
Restart=on-failure
RestartSec=5s
UMask=0077

# Keep the service read-only except for its two documented runtime-data paths.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/srv/[APP_NAME]/app/app/data /srv/[APP_NAME]/.local/share/rio-boilerplate

[Install]
WantedBy=multi-user.target
```

**Enable and start the service:**
```bash
# Reload systemd and start service
systemctl daemon-reload
systemctl enable --now [APP_NAME]

# Verify service is running
systemctl status [APP_NAME]

# Check logs if needed
journalctl -u [APP_NAME] -f
```

**Expected Output:**
```bash
# systemctl enable output
Created symlink '/etc/systemd/system/multi-user.target.wants/[APP_NAME].service' → '/etc/systemd/system/[APP_NAME].service'.

# systemctl status output
● [APP_NAME].service - Rio App for [DOMAIN_NAME]
     Loaded: loaded (/etc/systemd/system/[APP_NAME].service; enabled; preset: enabled)
     Active: active (running) since Sat 2025-06-21 11:30:32 UTC; 5s ago
   Main PID: 19392 (rio)
      Tasks: 1 (limit: 1109)
     Memory: 20.2M (peak: 20.4M)
        CPU: 278ms
     CGroup: /system.slice/[APP_NAME].service
             └─19392 /srv/[APP_NAME]/venv/bin/python3 /srv/[APP_NAME]/venv/bin/rio run --port 8000 --release --quiet
```

**Common Issues:**
- **Service fails to start**: Check the service file syntax and file paths
- **"restart counter is at 2"**: Service restarted due to quick exit, check logs for errors
- **Permission denied**: Confirm `/srv/[APP_NAME]` is root-owned and traversable
  by group `[APP_USER]`, and both `ReadWritePaths` are owned by `[APP_USER]`
- **Python module not found**: Virtual environment path may be incorrect

## Step 6: Configure Nginx Reverse Proxy

Create Nginx configuration for your domain. This reverse proxy setup provides security benefits by:
- Keeping the Rio application private (only accessible locally)
- Handling SSL termination and HTTPS traffic
- Providing additional security headers and request filtering
- Providing a single public entry point for the supported one-process Rio service

Run one Rio process/replica unless the proxy provides session affinity across
the initial page request, WebSocket and reconnects, and `POST /rio/cookies`.
Rio's latent/active sessions and pending cookie capabilities are process-local;
the browser-binding signing key is process-local too, so sharing only that key
would not make an unaffined multi-worker deployment safe.


```bash
# Create Nginx site configuration
nano /etc/nginx/sites-available/[DOMAIN_NAME]
```

**Nginx configuration file content:**
```nginx
# Queryless access-log format. Password-reset, email-verification, and OAuth
# flows carry secrets in URL query strings; the default "combined" format
# would persist them (via $request and $http_referer) in access logs. This
# format records the path only — never $request, $request_uri, $args,
# $query_string, or $http_referer.
log_format queryless '$remote_addr [$time_local] '
                     '"$request_method $uri $server_protocol" '
                     '$status $body_bytes_sent $request_time';

# HTTP to HTTPS redirect. Deliberately drops the query string ($uri, not
# $request_uri) so secret-bearing links arriving over plain HTTP are not
# copied into a redirect Location that gets logged again.
server {
    listen 80;
    server_name [DOMAIN_NAME] www.[DOMAIN_NAME];

    add_header Cache-Control "no-store" always;
    add_header Referrer-Policy "no-referrer" always;

    access_log /var/log/nginx/access.log queryless;

    return 301 https://[DOMAIN_NAME]$uri;
}

# Redirect the alternate HTTPS hostname to the APP_URL origin before Rio sees
# the request. This keeps Origin-bound authentication cookie writes reliable.
# Like the HTTP redirect above, this drops the query string on purpose.
server {
    listen 443 ssl;
    server_name www.[DOMAIN_NAME];

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header Cache-Control "no-store" always;
    add_header Referrer-Policy "no-referrer" always;

    access_log /var/log/nginx/access.log queryless;

    # Temporary SSL certificate (will be replaced by Certbot)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    return 301 https://[DOMAIN_NAME]$uri;
}

# HTTPS reverse proxy with WebSocket support
server {
    listen 443 ssl;
    server_name [DOMAIN_NAME];

    access_log /var/log/nginx/access.log queryless;

    # Keep future visits on HTTPS after the first successful HTTPS response.
    add_header Strict-Transport-Security "max-age=31536000" always;

    # Temporary SSL certificate (will be replaced by Certbot)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # Reverse proxy with WebSocket support for Rio
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Sensitive URLs, access logs, and redirects:**

Recovery and OAuth links currently transport secrets in URL query strings
(`reset_token`, `verify_token`, `social_login_token`), and Google's OAuth
callback always carries `code` and `state`. The `queryless` log format keeps
those values out of the access log, and the redirect servers use `$uri`
instead of `$request_uri` so a secret-bearing request arriving on the wrong
scheme or hostname is not copied into a logged `Location` header. The cost is
that redirected deep links lose benign query parameters too; application-
issued links always point at the canonical HTTPS origin, and HSTS keeps
returning browsers there, so in practice this affects little beyond first
visits. Keep the same queryless discipline in any CDN, WAF, or centralized
log pipeline placed in front of this configuration. This format controls
Nginx access logs only; validate the separate Nginx error log and every
upstream logging layer with a non-production sentinel on the deployment host.

The supported service command pins Rio's `--quiet` mode even though the
installed Rio version currently enables it by default. Do not replace the
documented command with a direct Uvicorn launch unless Uvicorn access logging
is disabled or independently configured and tested to omit query strings.

**Client IPs for rate limits:**

The nginx configuration above sends the original client address with
`X-Real-IP` and `X-Forwarded-For`. The documented
`rio run --port 8000 --release --quiet` path runs on Uvicorn, which trusts proxy
headers from `127.0.0.1` by default, so Rio/FastAPI sees the real client IP
before application rate-limit checks run.

If you run the app under a different ASGI server, disable Uvicorn proxy-header
handling, or proxy through a non-loopback address, verify that trusted proxy
headers are handled before deployment. Otherwise IP-based rate limits can share
one proxy address across all users. In that non-standard setup, either enable
trusted proxy-header handling in the ASGI server or set
`RATE_LIMIT_TRUST_PROXY_HEADERS = True` and update `RATE_LIMIT_TRUSTED_PROXIES`
in `app/app/config.py` to the private IPs of proxies you control. Do not enable
trusted proxy headers for requests that can arrive directly from the public
internet.

**Enable the site:**
```bash
# Create symlink to enable site
ln -s /etc/nginx/sites-available/[DOMAIN_NAME] /etc/nginx/sites-enabled/

# Test Nginx configuration
nginx -t

# If test passes, reload Nginx
systemctl reload nginx
```

**Expected Output:**
```bash
# nginx -t output
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful

# systemctl reload output (silent if successful)
```

**Common Issues:**
- **SSL certificate error**: Install ssl-cert package: `apt install -y ssl-cert && make-ssl-cert generate-default-snakeoil --force-overwrite`
- **nginx syntax error**: Check configuration file syntax, especially brackets and semicolons
- **Site already enabled**: Remove existing symlink first: `rm /etc/nginx/sites-enabled/[DOMAIN_NAME]`
- **nginx fails to start**: Check error logs: `tail -f /var/log/nginx/error.log`

## Step 7: Install SSL Certificate

Use Let's Encrypt to install a free SSL certificate:

```bash
# Install SSL certificate
certbot --nginx -d [DOMAIN_NAME] -d www.[DOMAIN_NAME]
```

**During the interactive prompts:**
- Enter your email: `[EMAIL]`
- Agree to Terms of Service: `Y`
- Share email with EFF (optional): `N`

**Verify SSL setup:**
```bash
# Test certificate renewal
certbot renew --dry-run

# Check certificate status
certbot certificates

# Final Nginx reload
systemctl reload nginx
```

**Expected Output:**
```bash
# Certbot certificate installation
Saving debug log to /var/log/letsencrypt/letsencrypt.log
Enter email address (used for urgent renewal and security notices)
 (Enter 'c' to cancel): [EMAIL]

Please read the Terms of Service at
https://letsencrypt.org/documents/LE-SA-v1.5-February-24-2025.pdf. You must
agree in order to register with the ACME server. Do you agree?
(Y)es/(N)o: y

Account registered.
Requesting a certificate for [DOMAIN_NAME] and www.[DOMAIN_NAME]

Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/[DOMAIN_NAME]/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/[DOMAIN_NAME]/privkey.pem
This certificate expires on 2025-09-19.

Deploying certificate
Successfully deployed certificate for [DOMAIN_NAME] to /etc/nginx/sites-enabled/[DOMAIN_NAME]
Successfully deployed certificate for www.[DOMAIN_NAME] to /etc/nginx/sites-enabled/[DOMAIN_NAME]

Congratulations! You have successfully enabled HTTPS on https://[DOMAIN_NAME] and https://www.[DOMAIN_NAME]

# Dry run test
Saving debug log to /var/log/letsencrypt/letsencrypt.log
Processing /etc/letsencrypt/renewal/[DOMAIN_NAME].conf

Simulating renewal of an existing certificate for [DOMAIN_NAME] and www.[DOMAIN_NAME]

Congratulations, all simulated renewals succeeded:
  /etc/letsencrypt/live/[DOMAIN_NAME]/fullchain.pem (success)
```

**Common Issues:**
- **Domain not accessible**: Ensure DNS is propagated and nginx is running
- **Rate limiting**: Let's Encrypt has rate limits, wait before retrying
- **Permission denied**: Check that nginx user can read certificate files
- **Certificate already exists**: Use `--force-renewal` flag if needed

## Step 8: Final Verification

Test your deployment:

```bash
# Test HTTP to HTTPS redirect
curl -I http://[DOMAIN_NAME]

# Test HTTPS with GET request (recommended). The real page response is 200 and
# seeds the browser-binding cookie without a bootstrap redirect. The jar simply
# verifies that cookie can be retained for a later request.
COOKIE_JAR=/tmp/[APP_NAME]-verification.cookies
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" https://[DOMAIN_NAME] | head -20
rm -f "$COOKIE_JAR"

# Verify HSTS is present on the public HTTPS response.
curl -sS -D - -o /dev/null https://[DOMAIN_NAME] \
  | grep -i '^Strict-Transport-Security:'

# Alternative: Test HTTPS with HEAD request
# Note: May return 405 if app doesn't handle HEAD requests
curl -I https://[DOMAIN_NAME]
```

**Expected Output:**
```bash
# HTTP redirect test
HTTP/1.1 301 Moved Permanently
Server: nginx/1.24.0 (Ubuntu)
Date: Sat, 21 Jun 2025 11:35:57 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: https://[DOMAIN_NAME]/

# HTTPS GET request (shows actual content)
<!doctype html>
<html>
    <head>
        <title>Home</title>
        <meta name="og:title" content="Home">
        ...

# HTTPS HEAD request (may show 405 - this is normal)
HTTP/1.1 405 Method Not Allowed
Server: nginx/1.24.0 (Ubuntu)
Date: Sun, 09 Nov 2025 23:18:48 GMT
Content-Type: application/json
Content-Length: 31
Connection: keep-alive
allow: GET

# Note: 405 for HEAD requests is normal behavior for Rio/FastAPI apps
# that don't explicitly handle HEAD method. The important indicators are:
# - Connection is established over HTTPS
# - SSL certificate is valid (no errors)
# - Browser test shows padlock and loads content
```

**Browser tests:**
1. Visit `https://[DOMAIN_NAME]` - should show padlock and load your site
2. Visit `http://[DOMAIN_NAME]` - should redirect to HTTPS
3. Open DevTools Console - should show no WebSocket connection errors

**Common Issues:**
- **502 Bad Gateway**: Rio service may not be running, check `systemctl status [APP_NAME]`
- **Connection refused**: Check firewall settings and nginx status
- **Certificate warnings**: DNS may not be fully propagated, wait a few minutes
- **WebSocket errors**: Check nginx proxy headers configuration

## Maintenance Commands

### Service Management
```bash
# Check service status
systemctl status [APP_NAME]

# View live logs
journalctl -u [APP_NAME] -f

# Restart service
systemctl restart [APP_NAME]

# Check Nginx status
systemctl status nginx

# View Nginx error logs
tail -f /var/log/nginx/error.log
```

### System Updates
```bash
# Update system packages
apt update && apt upgrade -y

# Check SSL certificate expiry
certbot certificates

# Manual certificate renewal (auto-renewal runs automatically)
certbot renew
```

### Troubleshooting

#### Common Issues

**1. SSL Certificate Error (Ubuntu 24.04 LTS)**
```bash
# Install missing SSL certificate package
apt install -y ssl-cert
make-ssl-cert generate-default-snakeoil --force-overwrite
nginx -t && systemctl reload nginx
```

**2. Application Not Responding**
```bash
# Check if Rio is binding to port 8000
curl -fsS http://127.0.0.1:8000/api/health
curl -s http://127.0.0.1:8000 | head

# Check service logs
journalctl -u [APP_NAME] -n 50
```

**3. Nginx Configuration Issues**
```bash
# Test Nginx configuration
nginx -t

# Check Nginx error logs
tail -f /var/log/nginx/error.log
```

**4. Firewall Issues**
```bash
# Check firewall status
ufw status

# Ensure required ports are open
ufw allow 'Nginx Full'
ufw allow OpenSSH
```

## File Structure Reference

**Server directory structure:**
```
/srv/[APP_NAME]/
├── .env                   # Deployment secrets
├── requirements.txt       # CI-generated wheelhouse lock
├── requirements-source.txt # Audited platform-neutral source lock
├── sbom.cdx.json          # Runtime dependency inventory
├── wheelhouse/            # CI-built, hash-verified Python wheels
├── app/                    # Main application files
│   ├── rio.toml           # Rio configuration
│   └── app/
│       └── __init__.py    # Rio app bootstrap + FastAPI bridge
├── venv/                  # Server-built Python virtual environment
│   ├── bin/
│   └── lib/
└── .local/share/rio-boilerplate/  # Contact-message runtime data
```

**Key configuration files created:**
- `/etc/systemd/system/[APP_NAME].service` - Service definition
- `/etc/nginx/sites-available/[DOMAIN_NAME]` - Nginx configuration
- `/etc/nginx/sites-enabled/[DOMAIN_NAME]` - Symlink to enable site
- `/etc/letsencrypt/live/[DOMAIN_NAME]/` - SSL certificates

## Security Notes

- Root/sudo is used only for provisioning packages, firewall, Nginx, Certbot,
  source installation, and the systemd unit.
- The application itself runs as the dedicated no-login `[APP_USER]` account.
  Do not grant this account sudo or an interactive shell.
- The systemd unit makes the OS and deployed source read-only to the service;
  only the SQLite data directory and contact-message data directory are
  writable. The local email outbox is development-only.
- During code updates, install files and dependencies as root, keep source and
  `venv/` root-owned, preserve `[APP_USER]` ownership of the two runtime-data
  directories, run strict prestart as `[APP_USER]`, and then restart the
  service.
- Regularly update system packages and monitor security advisories
- Consider implementing fail2ban for additional security
- Monitor SSL certificate expiry (auto-renewal should handle this)

## Success Criteria

Your deployment is successful when:
- ✅ Domain resolves to your droplet IP
- ✅ HTTP requests redirect to HTTPS
- ✅ HTTPS shows valid SSL certificate
- ✅ Application loads without errors
- ✅ WebSocket connections work properly
- ✅ Service starts automatically on boot
- ✅ Strict prestart passes with a verified root account
- ✅ SSL certificate auto-renewal is configured

---

**Note:** This guide targets Ubuntu 24.04 LTS on DigitalOcean. That release
provides the Python 3.12 line used by CI and receives standard security
maintenance through May 2029. Re-verify package/runtime compatibility before
moving the deployment to a newer Ubuntu or Python release.
