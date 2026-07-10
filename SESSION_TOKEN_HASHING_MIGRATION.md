# Session Token Hashing — Migration Guide

## What changed

Session bearer tokens are now **hashed at rest**. Previously the raw token returned by
`secrets.token_urlsafe()` was stored verbatim as the `user_sessions.id` primary key and looked
up with `WHERE id = ?` on the raw token. Now:

- `user_sessions.id` stores `sha256(token)` (64-char lowercase hex digest).
- The **raw** token is still what the client holds (`UserSettings.auth_token`) and presents on
  every request — only the at-rest representation changed.
- Lookups hash the incoming token before matching; `UserSession.id` returned to callers stays
  the raw token.

This closes a CWE-312 (Cleartext Storage) gap and brings session tokens in line with every other
secret in `persistence_auth.py` (reset tokens, email-verification tokens, recovery codes), all of
which were already SHA-256'd via `_hash_one_time_token()`.

### Code already applied to this repo (Track 1 — breaking change)

These edits are committed on the core repo and require **no migration code** for a fresh install:

- `app/app/persistence_auth.py`
  - `create_session` — stores `_hash_one_time_token(session.id)`; returns the raw token unchanged.
  - `get_and_extend_valid_session_by_auth_token` / `invalidate_session` — hash the raw token
    before renewing or deleting its session row.
  - `get_session_by_auth_token` / `get_valid_session_by_auth_token` — hash the lookup input;
    return `UserSession(id=auth_token)` (the raw input), never `row[0]` (the stored hash).
    Token values were also removed from the `KeyError` messages (no token in logs).
- `app/tests/test_live_session_revalidation.py`, `app/tests/test_mounted_sensitive_session_revalidation.py`
  — direct `UPDATE user_sessions ... WHERE id = ?` statements now hash the key.
- `app/tests/test_session_token_hashing.py` — new regression test.

**No schema change** ships in the core repo: the `user_sessions` columns are identical before and
after; only the meaning of the `id` value changed.

---

## Who needs to do anything

| Situation | Action |
|---|---|
| **Fresh install** of the boilerplate | Nothing. New sessions are hashed from the first boot. |
| **Local dev DB** with old plaintext sessions | Delete `app/app/data/app.db` (recreated on next boot), or run `DELETE FROM user_sessions;` once. Old plaintext rows never match a lookup anyway — they are dead rows that expire on their own — but clearing them removes lingering cleartext. |
| **Downstream project with LIVE users** (cannot start from an empty DB) | Apply the **Track 2 migration** below. |

---

## Track 2 — Downstream projects with live users

Existing rows in a live `user_sessions` table still hold **cleartext** tokens. After deploying the
hashed code, those rows will no longer authenticate (incoming tokens are now hashed before lookup),
so they are effectively dead — but they must be **purged**, otherwise cleartext tokens linger at
rest until each row's `valid_until`, which defeats the purpose of this change.

### Recommended approach: purge + forced re-login

Delete all pre-hardening session rows on the first boot of the new code. Every currently-logged-in
user is logged out once and re-authenticates. For short-lived (1–7 day) session tokens this is the
standard, expected UX for a credential-storage hardening, and it clears all cleartext atomically.

This was chosen over a lazy "dual-read / rehash-on-use" scheme because dual-read leaves cleartext
rows at rest until each user happens to return (defeating the security goal) and complicates the
auth hot path.

### Migration code

Add the purge to `create_session_table` in `app/app/persistence_schema.py`, immediately after the
existing `CREATE TABLE IF NOT EXISTS user_sessions (...)` statement:

```python
# One-time hardening migration: session ids are now stored as SHA-256 hex
# digests (64 lowercase hex chars). Any row whose id is NOT a 64-char hex
# digest holds a CLEARTEXT token from before the hardening — purge it so no
# plaintext session tokens remain at rest. Affected users simply re-login.
cursor.execute(
    """
    DELETE FROM user_sessions
    WHERE length(id) <> 64
       OR lower(id) GLOB '*[^0-9a-f]*'
    """
)
conn.commit()
```

Why this trigger: the table's columns are unchanged, so the repo's usual column-name migration
heuristic (see `create_recovery_codes_table`) does not apply. Instead this detects the **value
shape** — a hashed id is exactly 64 hex chars, whereas a legacy `token_urlsafe()` id is a base64url
string (~43 chars, contains `-`/`_`/mixed case and so always trips the `GLOB` or the length check).

Properties:
- **Idempotent** — after the first run no non-hex / non-64-char rows remain, so later boots delete
  nothing.
- **Safe** — a `token_urlsafe` value that is coincidentally 64 hex chars is astronomically
  improbable; the worst case is one dead row that fails to authenticate.

### Deploy checklist

1. **Back up the database** before deploying — the migration is destructive to `user_sessions`.
2. Ship the `persistence_auth.py` code edits **and** the purge in the **same release**. Splitting
   them causes churn (purge without hashing re-purges new plaintext rows each boot) or leaves
   cleartext rows (hashing without purge).
3. Expect and communicate a **one-time forced re-login** for all active users. The purge runs
   atomically on the first boot of the new code — there is no rolling/partial state.
4. No foreign-key or index work is needed: `user_sessions` is referenced only by `user_id` joins,
   never by `id`.

### Verify the migration

Boot the new code against a **copy** of a pre-hardening database, then confirm:

```sql
-- After first boot: every remaining id is a 64-char hex digest.
SELECT COUNT(*) FROM user_sessions WHERE length(id) <> 64 OR lower(id) GLOB '*[^0-9a-f]*';
-- Expect 0.
```

- A second boot deletes nothing (idempotent).
- A previously-logged-in user is prompted to log in again; after logging in, their new
  `user_sessions` row has a 64-hex `id` that differs from the `auth_token` stored on the client.

---

## Optional follow-up (not included)

`get_user_by_reset_token` in `app/app/persistence_auth.py` still interpolates the reset token into
its `KeyError` messages — the same log-leak pattern that was removed from the session lookups. If
you adopt the message redaction, apply it there too for consistency.

`request_context.py` now carries the raw session token in-memory as `RequestContext.session_id`.
It is SHA-256'd by `hash_rate_limit_key` before any persistence, so nothing is stored in cleartext;
this is a behavioral note only, no change required.
