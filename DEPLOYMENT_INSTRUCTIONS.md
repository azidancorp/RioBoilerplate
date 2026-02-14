# Rio Application Production Deployment Guide

Complete step-by-step instructions for deploying a Rio/FastAPI application to a DigitalOcean droplet with HTTPS and WebSocket support.

## Prerequisites

- DigitalOcean droplet running Ubuntu 24.10
- Domain name with DNS management access
- Local application files ready for deployment
- SSH access to the droplet

## Variables to Replace

Throughout this guide, replace these variables with your actual values:
- `[DOMAIN_NAME]` - Your domain (e.g., `example.com`)
- `[DROPLET_IP]` - Your droplet's public IP address
- `[EMAIL]` - Your email for SSL certificate notifications
- `[LOCAL_APP_PATH]` - Path to your local application files
- `[APP_NAME]` - Name for your systemd service
- `[SSH_ALIAS]` - Short name for SSH connection (e.g., `mysite`)

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
- **Permission denied**: Ensure you're logged in as root user

## Step 3: Deploy Application Files

From your **local machine**, upload your application:

```bash
# Upload application files (run from local machine)
scp -r [LOCAL_APP_PATH] [SSH_ALIAS]:/root/
# OR
scp -r [LOCAL_APP_PATH] root@[DROPLET_IP]:/root/

# Example structure on server should be:
# /root/[APP_NAME]/
# ├── app/           # Main application files
# │   ├── rio.toml   # Rio configuration
# │   └── ...
# └── venv/          # Python virtual environment
```

**Expected Output:**
```bash
# SCP upload progress
app/                          100%  2048KB   1.5MB/s   00:01
venv/                         100%  50MB     8.2MB/s   00:06
```

**Common Issues:**
- **Permission denied**: Check SSH access and target directory permissions
- **No such file or directory**: Verify local path and create target directory if needed
- **Connection timeout**: Check network connection and SSH configuration

## Step 3.5: Configure Environment & Migrate Database

```bash
# From the application directory
cd /root/[APP_NAME]
[ -f .env ] || cp .env.example .env
nano .env
```

**Required `.env` additions:**

```
ADMIN_DELETION_PASSWORD="<strong admin password>"
```

> **Note:** Other configuration settings (email validation, currency names, password policy) are hardcoded in `app/app/config.py`. Edit that file directly to customize behavior.

> **Note:** The bundled schema expects a fresh database. If you are upgrading an existing installation, export your data and migrate manually before redeploying.

## Step 4: Test Application

SSH back into the server and test the application:

```bash
# Navigate to application directory
cd /root/[APP_NAME]
source venv/bin/activate
cd app

# Test application locally
# Note: --release flag enables production optimizations (faster performance, 
# lower memory usage, and additional safety checks)
rio run --port 8000 --release

# Verify it's working (from another terminal or check logs)
curl -s http://127.0.0.1:8000 | head

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

# curl test output
<!doctype html>
<html>
    <head>
        <title>Home</title>
        <meta name="og:title" content="Home">
        <meta name="description" content="A Rio web-app written in 100% Python">
```

**Common Issues:**
- **"Couldn't find rio.toml"**: Make sure you're in the correct app directory
- **Module import errors**: Check virtual environment is activated and dependencies installed
- **Port already in use**: Another service might be using port 8000, try a different port
- **No HTML output from curl**: Rio app may not be starting properly, check error messages

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
After=network.target

[Service]
WorkingDirectory=/root/[APP_NAME]/app
# --release flag provides production optimizations and safety checks
ExecStart=/root/[APP_NAME]/venv/bin/rio run --port 8000 --release
Restart=always

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
             └─19392 /root/[APP_NAME]/venv/bin/python3 /root/[APP_NAME]/venv/bin/rio run --port 8000 --release
```

**Common Issues:**
- **Service fails to start**: Check the service file syntax and file paths
- **"restart counter is at 2"**: Service restarted due to quick exit, check logs for errors
- **Permission denied**: Ensure service file has correct ownership and permissions
- **Python module not found**: Virtual environment path may be incorrect

## Step 6: Configure Nginx Reverse Proxy

Create Nginx configuration for your domain. This reverse proxy setup provides security benefits by:
- Keeping the Rio application private (only accessible locally)
- Handling SSL termination and HTTPS traffic
- Providing additional security headers and request filtering
- Enabling load balancing and caching if needed


```bash
# Create Nginx site configuration
nano /etc/nginx/sites-available/[DOMAIN_NAME]
```

**Nginx configuration file content:**
```nginx
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name [DOMAIN_NAME] www.[DOMAIN_NAME];
    return 301 https://$host$request_uri;
}

# HTTPS reverse proxy with WebSocket support
server {
    listen 443 ssl;
    server_name [DOMAIN_NAME] www.[DOMAIN_NAME];

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

# Test HTTPS with GET request (recommended)
curl -s https://[DOMAIN_NAME] | head -20

# Alternative: Test HTTPS with HEAD request
# Note: May return 405 if app doesn't handle HEAD requests
curl -I https://[DOMAIN_NAME]
```

**Expected Output:**
```bash
# HTTP redirect test
HTTP/1.1 301 Moved Permanently
Server: nginx/1.26.0 (Ubuntu)
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

**1. SSL Certificate Error (Ubuntu 24.10)**
```bash
# Install missing SSL certificate package
apt install -y ssl-cert
make-ssl-cert generate-default-snakeoil --force-overwrite
nginx -t && systemctl reload nginx
```

**2. Application Not Responding**
```bash
# Check if Rio is binding to port 8000
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
/root/[APP_NAME]/
├── app/                    # Main application files
│   ├── rio.toml           # Rio configuration
│   ├── main.py            # Application entry point
│   └── ...                # Other app files
└── venv/                  # Python virtual environment
    ├── bin/
    ├── lib/
    └── ...
```

**Key configuration files created:**
- `/etc/systemd/system/[APP_NAME].service` - Service definition
- `/etc/nginx/sites-available/[DOMAIN_NAME]` - Nginx configuration
- `/etc/nginx/sites-enabled/[DOMAIN_NAME]` - Symlink to enable site
- `/etc/letsencrypt/live/[DOMAIN_NAME]/` - SSL certificates

## Security Notes

- This guide uses root user for simplicity
- For production environments, consider creating a dedicated application user
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
- ✅ SSL certificate auto-renewal is configured

---

**Note:** This guide provides general deployment instructions for Rio applications on Ubuntu 24.10 DigitalOcean droplets. Adapt the instructions as needed for your specific application and requirements.
