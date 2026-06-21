"""Append-only audit log for privileged admin mutations.

Records *who did what to whom, and when* for every privileged admin action so
that after the fact we can answer "who changed this user's role / deleted this
account / moved this balance". Rows are written on the same DB transaction as
the mutation they describe (``commit=False``), guaranteeing the invariant "if
the state changed, there is exactly one audit row for it".

The table has no foreign keys to ``users`` (see ``persistence_schema``), so rows
survive deletion of the actor or target they reference. No update/delete helpers
are exposed here: the log is append-only by convention.
"""

import json
import sqlite3
import typing as t
import uuid
from datetime import datetime, timezone
from typing import Protocol


class AuditPersistence(Protocol):
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...


def _get_connection(persistence: AuditPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _json_or_none(value: dict[str, t.Any] | None) -> str | None:
    # default=str keeps the helper robust if a caller slips a UUID/datetime into
    # a payload; audit rows must never fail to serialize.
    return json.dumps(value, default=str) if value is not None else None


def _loads_or_none(value: str | None) -> t.Any:
    return json.loads(value) if value else None


def _row_to_audit_entry(row: tuple) -> dict[str, t.Any]:
    """Convert an ``admin_audit_log`` row tuple into a dict."""
    return {
        "id": row[0],
        "actor_user_id": uuid.UUID(row[1]) if row[1] else None,
        "actor_role": row[2],
        "action": row[3],
        "target_user_id": uuid.UUID(row[4]) if row[4] else None,
        "target_label": row[5],
        "before": _loads_or_none(row[6]),
        "after": _loads_or_none(row[7]),
        "metadata": _loads_or_none(row[8]),
        "client_ip": row[9],
        "outcome": row[10],
        "created_at": datetime.fromtimestamp(row[11], tz=timezone.utc),
    }


def record_admin_action(
    persistence: AuditPersistence,
    *,
    actor_user_id: uuid.UUID | None,
    actor_role: str | None,
    action: str,
    target_user_id: uuid.UUID | None = None,
    target_label: str | None = None,
    before: dict[str, t.Any] | None = None,
    after: dict[str, t.Any] | None = None,
    metadata: dict[str, t.Any] | None = None,
    client_ip: str | None = None,
    outcome: str = "success",
    created_at: float | None = None,
    commit: bool = False,
) -> None:
    """Insert a single audit row.

    ``commit`` follows the existing codebase idiom (cf.
    ``append_currency_ledger_entry``): with ``commit=False`` (the default) the
    row lands in the caller's open transaction and is committed atomically by
    the caller's ``conn.commit()``. Standalone call sites — e.g. recording a
    best-effort or denied attempt with no surrounding mutation — pass
    ``commit=True``.
    """
    cursor = persistence._get_cursor()
    timestamp = created_at or datetime.now(timezone.utc).timestamp()
    cursor.execute(
        """
        INSERT INTO admin_audit_log (
            actor_user_id,
            actor_role,
            action,
            target_user_id,
            target_label,
            before,
            after,
            metadata,
            client_ip,
            outcome,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(actor_user_id) if actor_user_id else None,
            actor_role,
            action,
            str(target_user_id) if target_user_id else None,
            target_label,
            _json_or_none(before),
            _json_or_none(after),
            _json_or_none(metadata),
            client_ip,
            outcome,
            timestamp,
        ),
    )
    if commit:
        _get_connection(persistence).commit()


def list_admin_actions(
    persistence: AuditPersistence,
    *,
    actor_user_id: uuid.UUID | None = None,
    target_user_id: uuid.UUID | None = None,
    action: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, t.Any]]:
    """Return audit rows newest-first, optionally filtered by actor/target/action."""
    cursor = persistence._get_cursor()

    clauses: list[str] = []
    params: list[t.Any] = []
    if actor_user_id is not None:
        clauses.append("actor_user_id = ?")
        params.append(str(actor_user_id))
    if target_user_id is not None:
        clauses.append("target_user_id = ?")
        params.append(str(target_user_id))
    if action is not None:
        clauses.append("action = ?")
        params.append(action)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"""
        SELECT id, actor_user_id, actor_role, action, target_user_id, target_label,
               before, after, metadata, client_ip, outcome, created_at
        FROM admin_audit_log
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
    """
    params.append(max(1, min(limit, 500)))
    params.append(max(0, offset))

    cursor.execute(query, params)
    return [_row_to_audit_entry(row) for row in cursor.fetchall()]
