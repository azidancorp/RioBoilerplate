# Email Validation Configuration

This boilerplate is email-first by default. Email format validation is controlled
in `app/app/config.py`, and secrets are not involved. Do not add these behavior
knobs to `.env` or `AppConfig.from_env`.

## Settings

`REQUIRE_VALID_EMAIL` defaults to `True`.

When `True`, sign-up, user creation, profile validation, contact forms, and
reset-email entry points use `SecuritySanitizer.validate_email_format()` to
enforce strict email syntax via `email-validator`. The current policy disables
SMTPUTF8, skips deliverability checks, enables strict parsing, normalizes casing,
and rejects internationalized domains.

When `False`, the same validator still runs length and suspicious-pattern
checks, then accepts non-email identifiers. This mode is for apps that want to
reuse the `email` database column as a generic identifier. The stock UI still
labels the field as email, so a real username-mode product should update labels,
messages, and tests before shipping.

`ALLOW_USERNAME_LOGIN` defaults to `False`.

When `True`, login falls back from email lookup to username lookup for users that
already have a `username` stored. The stock sign-up form does not collect a
separate username.

## Current Flow

Relevant code paths:

- Config: `app/app/config.py`
- Central validator: `app/app/validation.py`
- Rio sign-up and reset forms: `app/app/pages/login.py`
- Persistence safety check before insert: `app/app/persistence.py`
- Username fallback lookup: `app/app/persistence_users.py`

The central validator is the security seam. If strict email validation is
enabled, it returns the normalized email address. Sign-up and persistence should
store that normalized value rather than the raw submitted string.

## Safe Defaults

For most deployments, keep:

```python
REQUIRE_VALID_EMAIL = True
ALLOW_USERNAME_LOGIN = False
```

Only set `REQUIRE_VALID_EMAIL = False` if the application has intentionally been
converted to identifier-based auth. That conversion should include UI wording,
duplicate-account checks, reset-flow wording, and tests for the non-email
identifier path.

## Verification

Focused validator check:

```bash
./venv/bin/python -m pytest app/tests/test_email_validation.py -q
```

Broader auth/page smoke checks:

```bash
./venv/bin/python -m pytest app/tests/test_auth_email_flows.py app/tests/test_smoke_pages.py -q
cd app && timeout 5 ../venv/bin/rio run --port 8001
```
