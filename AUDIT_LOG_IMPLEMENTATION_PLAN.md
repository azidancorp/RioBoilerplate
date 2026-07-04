# Implementation Plan — Admin Action Audit Log

## Objective

Persist a tamper-evident record of **who did what to whom** for every privileged
admin mutation, so that after the fact we can answer "who changed this user's
role / deleted this account / moved this balance, and when." Today there is **no
audit table** in the schema and `update_user_role` (and the other admin
mutations) commit silently — the only logging anywhere in `admin.py` is
`logger.exception(...)` on the *error* path (`admin.py:186`).

This plan covers **attribution** (who/what/when). It is independent of, and
complementary to, the sudo-mode step-up plan (which covers *proof the legitimate
admin was present*). Build this one first: it is cheaper, has zero UX cost, and
stands on its own.

## Design Decisions (and why)

1. **Write the audit row inside the same DB transaction as the mutation.**
   This guarantees the invariant "if the state changed, there is exactly one
   audit row for it" — no drift where a role change succeeds but the log write
   fails (or vice-versa). This mirrors how `user_currency_ledger` is written in
   the same transaction as the balance update. Logging from the UI handler
   (`admin.py`) instead would be non-atomic. It would also miss any non-UI
   caller: today that is the currency CLI (`app/app/scripts/currency_admin.py`
   calls `set_currency_balance` / `adjust_currency_balance` directly at
   `:114`/`:122`), plus any future API routes. (The user mutations —
   `update_user_role`, `delete_user`, `admin_set_user_active`, etc. — currently
   have no non-UI callers, so for those the atomicity guarantee is the whole
   justification; instrumenting in persistence still keeps all actions in one
   place and future-proofs new callers.)

2. **No `FOREIGN KEY ... ON DELETE CASCADE` on the audit table.** This is the
   single most important difference from the currency ledger. The currency
   ledger cascades on user deletion; the audit log must **survive** user
   deletion — otherwise deleting a user erases the record of who deleted them.
   `actor_user_id` and `target_user_id` are stored as plain `TEXT` with **no FK
   constraint** so rows are never cascaded away. (We accept that the referenced
   user may no longer exist; the row is a historical fact, not a live relation.)

3. **Reuse the existing `actor: AppUser` parameter; only add an actor where one
   doesn't already exist.** Four of the six admin mutations *already* take
   `actor: AppUser` (keyword-only) and authorize against it:
   `admin_create_user` (`persistence.py:341`), `admin_update_user_profile`
   (`:412`), `admin_set_user_active` (`:561`), `admin_issue_password_reset`
   (`:612`). For these, the audit row is built from the actor already in hand
   (`actor.id`, `actor.role`) — do **not** add a parallel
   `actor_user_id`/`actor_role` mechanism beside it. Only `update_user_role`
   (`:776`) and `delete_user` (`:878`) lack an actor; add `actor: AppUser` to
   them, matching the keyword-only convention of the other four, and derive the
   audit attribution from it.

   `client_ip` is genuinely new — no mutation accepts it today — so it is the one
   field threaded as a new keyword param (`client_ip: str | None = None`),
   defaulted so existing callers are unaffected.

4. **Structured `before`/`after`/`metadata` as JSON `TEXT`.** Matches the
   `metadata TEXT` convention already used by `user_currency_ledger` and
   `rate_limit_events`. Lets one table cover heterogeneous actions without a
   column explosion.

5. **New module `persistence_audit.py`** exposed via the `Persistence` facade,
   matching the existing split (`persistence_auth.py`, `persistence_currency.py`,
   `persistence_rate_limits.py`, …). The facade in `persistence.py` delegates.

6. **Append-only by convention.** No update/delete methods are exposed for audit
   rows. (SQLite cannot truly prevent a privileged process from rewriting the
   file; true tamper-proofing is out of scope — see "Future hardening".)

## Schema

New table, created the same way as the others. Add `create_admin_audit_table(persistence)`
to the schema-init sequence in `persistence_schema.py` (the function whose body
spans lines 17–26, alongside `create_currency_ledger_table` and
`create_rate_limit_tables`), and define the function mirroring
`create_currency_ledger_table` (`persistence_schema.py:118`):

```sql
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id   TEXT,            -- admin who performed the action (no FK: must survive deletion)
    actor_role      TEXT,            -- actor's role at action time (roles can change later)
    action          TEXT NOT NULL,   -- e.g. 'role_change', 'user_deactivate', 'user_delete'
    target_user_id  TEXT,            -- subject of the action, if any (no FK)
    target_label    TEXT,            -- human-readable email/username snapshot at action time
    before          TEXT,            -- JSON snapshot of relevant fields before, nullable
    after           TEXT,            -- JSON snapshot of relevant fields after, nullable
    metadata        TEXT,            -- JSON: extra context, nullable
    client_ip       TEXT,            -- best-effort source IP, nullable
    outcome         TEXT NOT NULL DEFAULT 'success',  -- 'success' | 'failure'
    created_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_actor   ON admin_audit_log(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_target  ON admin_audit_log(target_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action  ON admin_audit_log(action, created_at DESC);
```

Notes:
- `target_label` stores a snapshot of the email/username so the log is readable
  even after the target is deleted/renamed.
- `actor_role` is snapshotted because roles change; the log must show the
  privilege the actor held at the time.
- `outcome` lets us optionally record *denied/failed* attempts (e.g. wrong
  hierarchy, rate-limited) for security monitoring, not just successes.

### Migration / backward compatibility

The table uses `CREATE TABLE IF NOT EXISTS`, so existing databases get it on
next boot with no migration step. No existing table is altered, so there is no
`ALTER TABLE` / `PRAGMA table_info` dance here (unlike the sudo-mode plan).
Existing rows in other tables are untouched.

## New module: `app/app/persistence_audit.py`

```python
def record_admin_action(
    persistence,
    *,
    actor_user_id: uuid.UUID | None,
    actor_role: str | None,
    action: str,
    target_user_id: uuid.UUID | None = None,
    target_label: str | None = None,
    before: dict | None = None,
    after: dict | None = None,
    metadata: dict | None = None,
    client_ip: str | None = None,
    outcome: str = "success",
    commit: bool = False,  # False: write on the shared txn, let the caller commit; True: commit standalone
) -> None:
    ...
```

- `before`/`after`/`metadata` are `json.dumps(...)`-serialized (or `None`).
- **`commit` follows the existing codebase idiom**, not a new `cursor=` param.
  All delegated persistence methods share one thread-local connection via
  `persistence._get_cursor()` (`persistence.py:78`), so a row written with
  `commit=False` lands in the caller's open transaction and is committed
  atomically by the caller's `conn.commit()`. This mirrors
  `append_currency_ledger_entry(..., commit: bool = False)`
  (`persistence_currency.py:78`, used at `persistence.py:276`). Inside a
  mutation, call `record_admin_action(..., commit=False)` (the default) before
  the mutation commits. Standalone call sites (e.g. recording a denied attempt
  that has no surrounding mutation) pass `commit=True`.
- Add a read helper for an admin "audit viewer" later:
  `list_admin_actions(persistence, *, actor_user_id=None, target_user_id=None, action=None, limit=100, offset=0)`.

Expose both on the `Persistence` facade in `persistence.py` (delegating, exactly
like `create_session` delegates to `persistence_auth.create_session`):

```python
def record_admin_action(self, **kw): return persistence_audit.record_admin_action(self, **kw)
def list_admin_actions(self, **kw):  return persistence_audit.list_admin_actions(self, **kw)
```

## Mutations to instrument (and the JSON payload for each)

For each, build the audit attribution from the actor (reuse the existing
`actor: AppUser` where present — see Design Decision #3 — else add it), thread
`client_ip`, and write the audit row on the **same transaction** via
`record_admin_action(..., commit=False)` before the mutation's `commit()`.

| Action key            | Persistence method (file:line)               | Admin handler (file:line)                    | before → after |
|-----------------------|----------------------------------------------|----------------------------------------------|----------------|
| `role_change`         | `update_user_role` (`persistence.py:776`)    | `_update_role` (`admin.py:551`)              | `{"role": old}` → `{"role": new}` |
| `user_deactivate` / `user_reactivate` | `set_user_active` (persistence) | `_on_set_active_pressed` (`admin.py:348`)    | `{"is_active": old}` → `{"is_active": new}` |
| `user_edit`           | admin profile/email update (persistence)     | `_on_edit_user_pressed` (`admin.py:271`)     | `{"email":…, "username":…}` → new values |
| `password_reset_sent` | reset-token creation (persistence)           | `_on_send_reset_pressed` (`admin.py:425`)    | `null` → `{"token_id": …}` (never the token itself) |
| `user_create`         | `create_user` (persistence)                  | `_on_create_user_pressed` (`admin.py:189`)   | `null` → `{"email":…, "role":…}` |
| `user_delete`         | `delete_user` / `admin_delete_user` (persistence) | `_on_delete_user_pressed` (admin page)   | `{"email":…, "role":…}` → `null` |
| `currency_adjust` / `currency_set` | currency adjust/set (persistence) | `_on_currency_submit` (`admin.py:718`) + API `api/currency.py:118,157` | `{"balance": old}` → `{"balance": new}` |

Notes:
- **`user_delete`**: write the audit row *before* the cascade deletes run, on the
  same transaction, so the target's email/role are snapshotted into
  `target_label`/`before`. Because the audit table has no FK cascade, the row
  persists after the user is gone.
- **`user_delete` covers two paths.** `delete_user` is the self-service path and
  requires the target user's password plus optional target 2FA. Admin removal
  uses `admin_delete_user` after caller-side actor step-up and a persistence-side
  role-hierarchy check. Audit both paths —
  - admin path: `actor = self.current_user` (admin ≠ target);
  - self-service path: no admin actor; the persistence layer attributes the row
    to the target user and tags `metadata={"self_service": true}` so actor ==
    target reads correctly.
  This keeps the "every deletion is audited" invariant while distinguishing
  admin removals from self-deletions. (Decide in review whether self-deletions
  belong in the *admin* audit log at all, or only admin-initiated ones — see
  Open Questions.)
- **`password_reset_sent` is not truly same-transaction.**
  `admin_issue_password_reset` (`persistence.py:608`) delegates to
  `create_reset_token` (`persistence_auth.py:785`), which commits on its own
  (`:833`) and is preceded by a separate `clear_reset_tokens` commit (`:896`).
  So the audit row for this action cannot share one transaction with token
  creation without first refactoring that two-commit flow. For v1, accept
  best-effort ordering (write the audit row immediately after the token is
  created) rather than expanding scope to refactor the reset-token path.
- **Currency** is partially covered already: `user_currency_ledger` records
  `actor_user_id` + `delta` + `balance_after`. To avoid double bookkeeping, the
  audit row for currency can be thin (`metadata: {"ledger_id": <id>}`) and defer
  detail to the ledger — or skip currency in v1 since the ledger already
  attributes it. **Decide in review** (see Open Questions). Recommended: log a
  thin audit row for symmetry so one table answers "all admin actions".
- **Secrets never logged**: never store passwords, shared secrets, TOTP codes,
  recovery codes, or raw reset tokens in `before`/`after`/`metadata`.

### Acquiring `client_ip`

The codebase already derives request context via `context_from_rio_session`
(used in `admin.py:_check_sensitive_limit`, ~`admin.py:134`) which yields
`client_ip`. Pass that down from the handler into the persistence call.

## Code changes — file by file

1. `app/app/persistence_schema.py`
   - Add `create_admin_audit_table(persistence)` (mirror
     `create_currency_ledger_table`, `persistence_schema.py:118`).
   - Register the call in the schema-init body (the block at
     `persistence_schema.py:17-26`).

2. `app/app/persistence_audit.py` (new)
   - `record_admin_action(...)`, `list_admin_actions(...)`, internal row mapper.

3. `app/app/persistence.py`
   - Import `persistence_audit`; add the two delegating facade methods.
   - Build the audit row from the existing `actor: AppUser` on the four methods
     that already have it (`admin_create_user`, `admin_update_user_profile`,
     `admin_set_user_active`, `admin_issue_password_reset`) — no new actor param.
   - Add `actor` to `update_user_role` and `delete_user` only (the two that lack
     it), keyword-only to match the other four. **On both, make it
     `actor: AppUser | None = None` (optional), not required** — these actor
     values are for audit attribution, while self-service `delete_user` still
     authorizes via the target user's password/2FA. Making it required would
     break existing actor-less callers:
     - `update_user_role` is called without an actor by
       `test_live_session_revalidation.py:123` (`update_user_role(user.id, "user")`).
     - `delete_user` is called without an actor by the self-service path
       (`settings.py:355`).

     A call without an actor simply writes a null `actor_user_id` (self-service
     deletion additionally tags `metadata={"self_service": true}` — see below).
   - **Do NOT add `_require_admin_actor_can_manage` to self-service
     `delete_user`.** It keeps target-user password / optional 2FA verification.
     Admin-authorized deletion belongs in the separate `admin_delete_user` path
     after caller-side actor step-up and must enforce role hierarchy itself.
     Any read of `actor.*` inside shared deletion cleanup must be guarded
     (`if actor is not None and actor.id != user_id:`). `update_user_role`
     likewise must guard `actor.role`/`actor.id` behind an `actor is not None`
     check before using them in the audit row.
   - Add `client_ip: str | None = None` (keyword-only, defaulted) where audit
     needs it.
   - Each method calls `persistence_audit.record_admin_action(..., commit=False)`
     before its final `conn.commit()`, so the audit row commits atomically with
     the mutation. (Exception: `password_reset_sent` — see the note above.)
   - **Backward-compat for callers**: every new param is defaulted
     (`actor=None` on the two methods that gain it, `client_ip=None`). Existing
     tests/scripts keep working; a row written without a known actor simply has a
     null `actor_user_id`.

4. `app/app/pages/app_page/admin.py`
   - The four methods that already take `actor: AppUser` are already passed
     `actor=self.current_user` by these handlers — leave that as-is. For the two
     newly-actor'd methods (`update_user_role`, `delete_user`), add
     `actor=self.current_user`; admin deletion should call `admin_delete_user`
     after per-action actor re-auth.
   - In each handler, also pass the `client_ip` from
     `context_from_rio_session(self.session)` into the persistence call.

5. `app/app/api/currency.py` (if currency auditing is in scope for v1)
   - Pass the authenticated admin's id/role into the adjust/set persistence calls.

## Tests

Add `app/tests/test_admin_audit_log.py`:
- Role change writes exactly one `role_change` row with correct
  actor/target/before/after; assert atomicity (role updated ⇔ row exists).
- **Deletion survives**: delete a user, assert the `user_delete` audit row still
  exists and `target_label`/`before` are populated (proves no FK cascade).
- Failed/denied action with `outcome='failure'` is recorded when we choose to
  log denials.
- `list_admin_actions` filters by actor/target/action and orders newest-first.
- No secret material appears in any audit column (scan `before/after/metadata`
  for the test password / token).
- Existing admin tests still pass with the new keyword params defaulted.
  Specifically, the actor-less callers must still work unchanged:
  `test_live_session_revalidation.py:123` (`update_user_role` with no actor) and
  the self-service `delete_user` path. No edits to those callers are required —
  this is the contract that keeps `actor` optional on both methods.

Run: `pytest app/tests/test_admin_audit_log.py -x` and the full admin suite.
Because this adds an admin "Audit log" page (Rollout, below) and touches
`admin.py`, also run the mandated page smoke test (AGENTS.md):
`pytest app/tests/test_smoke_pages.py -x`.
Boot check from `app/`: `cd app && timeout 5 rio run --port 8011` to confirm the
new table is created cleanly on a fresh DB.

## Rollout

- Pure additive; safe to ship behind no flag. New table + new columns of
  behavior only. No data backfill (history before this change is unknowable).
- Optional follow-up: an admin-only "Audit log" page that renders
  `list_admin_actions` (add to `APP_ROUTES` in `navigation.py`). **Register it
  with a flat `url_segment`** (e.g. `audit-log` → `/app/audit-log`, mirroring
  `/app/currency-playground`), **not** a nested `/app/admin/audit`. The `/app/`
  guard builds its access key from the **last path segment only**
  (`app_page.py:23`: `full_path = "/app/" + active_pages[-1].url_segment`), so a
  nested route would resolve to `/app/audit`, miss `PAGE_ROLE_MAPPING`, and
  `check_access` would default-deny it (`permissions.py:72`) for every non-root
  role. (Root still passes via the highest-privilege short-circuit at
  `permissions.py:64`, which is exactly why this misconfiguration is easy to
  miss in testing — verify with a non-root admin role.) Add the matching
  `/app/audit-log` key to `APP_ROUTES` so the mapping and the guard agree.

## Future hardening (out of scope here)

- Append-only enforcement via a hash chain (each row stores
  `prev_hash = H(prev_row || this_row)`) to make tampering detectable.
- Ship audit rows to an external sink (syslog/SIEM) so a DB-file compromise
  can't quietly erase them.
- Retention/rotation policy for the table.

## Open Questions (resolve in review)

1. Currency: thin audit row for symmetry, or rely solely on the existing ledger?
   (Recommended: thin row.)
2. Do we log **denied** attempts (`outcome='failure'`) in v1, or successes only?
   (Recommended: log denials for role/delete/deactivate — they're the
   security-interesting ones.)
3. Actor for non-UI callers (the currency CLI): record as `actor='system'` vs
   null?
4. Self-service account deletion (`settings.py:355`): record it in the *admin*
   audit log tagged `self_service`, or keep this log admin-initiated-only and
   leave self-deletions out? (Recommended: include with the `self_service` tag —
   one table answers "every account deletion".)
