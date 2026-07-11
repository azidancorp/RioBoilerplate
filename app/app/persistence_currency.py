import json
import sqlite3
import typing as t
import uuid
from datetime import datetime, timezone
from typing import Protocol

import app.persistence_audit as persistence_audit
from app.currency import (
    format_minor_amount,
    get_currency_config,
    get_major_amount,
)
from app.data_models import CurrencyLedgerEntry


class CurrencyPersistence(Protocol):
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...


def _get_connection(persistence: CurrencyPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _row_to_currency_ledger_entry(row: tuple) -> CurrencyLedgerEntry:
    """Convert a ledger row tuple into a dataclass instance."""
    metadata_json = row[5]
    metadata = json.loads(metadata_json) if metadata_json else None
    actor_id = uuid.UUID(row[6]) if row[6] else None
    return CurrencyLedgerEntry(
        id=row[0],
        user_id=uuid.UUID(row[1]),
        delta=int(row[2]),
        balance_after=int(row[3]),
        reason=row[4],
        metadata=metadata,
        actor_user_id=actor_id,
        created_at=datetime.fromtimestamp(row[7], tz=timezone.utc),
    )


def _build_reconciliation_result(
    *,
    user_id: uuid.UUID,
    stored_balance: int,
    ledger_balance: int,
    fixed: bool = False,
) -> dict[str, t.Any]:
    discrepancy = stored_balance - ledger_balance
    return {
        "user_id": str(user_id),
        "stored_balance": stored_balance,
        "ledger_balance": ledger_balance,
        "discrepancy": discrepancy,
        "matches": discrepancy == 0,
        "fixed": fixed,
    }


def append_currency_ledger_entry(
    persistence: CurrencyPersistence,
    *,
    user_id: uuid.UUID,
    delta: int,
    balance_after: int,
    reason: str | None,
    metadata: dict[str, t.Any] | None,
    actor_user_id: uuid.UUID | None,
    created_at: float | None = None,
    commit: bool = False,
) -> CurrencyLedgerEntry:
    """
    Internal helper to insert a row into the currency ledger table.
    """
    cursor = persistence._get_cursor()
    timestamp = created_at or datetime.now(timezone.utc).timestamp()
    metadata_json = json.dumps(metadata) if metadata is not None else None
    cursor.execute(
        """
        INSERT INTO user_currency_ledger (
            user_id,
            delta,
            balance_after,
            reason,
            metadata,
            actor_user_id,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(user_id),
            int(delta),
            int(balance_after),
            reason,
            metadata_json,
            str(actor_user_id) if actor_user_id else None,
            timestamp,
        ),
    )
    entry_id = cursor.lastrowid
    if commit:
        _get_connection(persistence).commit()

    return CurrencyLedgerEntry(
        id=entry_id,
        user_id=user_id,
        delta=int(delta),
        balance_after=int(balance_after),
        reason=reason,
        metadata=metadata,
        actor_user_id=actor_user_id,
        created_at=datetime.fromtimestamp(timestamp, tz=timezone.utc),
    )


async def get_currency_balance(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
) -> int:
    """Return the raw minor-unit balance for a user."""
    overview = await get_currency_overview(persistence, user_id)
    return overview["balance_minor"]


async def get_currency_overview(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
) -> dict[str, t.Any]:
    """Retrieve balance, formatted string, and last update timestamp for a user."""
    cursor = persistence._get_cursor()
    cursor.execute(
        """
        SELECT primary_currency_balance, primary_currency_updated_at
        FROM users
        WHERE id = ?
        LIMIT 1
        """,
        (str(user_id),),
    )
    row = cursor.fetchone()
    if not row:
        raise KeyError(user_id)

    balance_minor = int(row[0]) if row[0] is not None else 0
    updated_at_ts = row[1] or 0
    updated_at = (
        datetime.fromtimestamp(updated_at_ts, tz=timezone.utc)
        if updated_at_ts
        else None
    )

    formatted = format_minor_amount(balance_minor)
    balance_major = get_major_amount(balance_minor)
    cfg = get_currency_config()

    return {
        "balance_minor": balance_minor,
        "balance_major": float(balance_major),
        "formatted": formatted,
        "label": cfg.display_name(balance_major),
        "updated_at": updated_at,
    }


def adjust_currency_balance_in_transaction(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
    delta_minor: int,
    *,
    actor_user_id: uuid.UUID | None,
    actor_role: str | None,
    client_ip: str | None,
    reason: str | None = None,
    metadata: dict[str, t.Any] | None = None,
) -> CurrencyLedgerEntry:
    """Adjust a balance and write its ledger/audit rows in an open transaction."""
    conn = _get_connection(persistence)
    if not conn.in_transaction:
        raise RuntimeError("Currency adjustment requires an open transaction.")
    if int(delta_minor) == 0:
        raise ValueError("Currency adjustment must be non-zero in minor units")
    cfg = get_currency_config()
    cursor = persistence._get_cursor()

    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be a mapping if provided")

    cursor.execute(
        "SELECT primary_currency_balance FROM users WHERE id = ?",
        (str(user_id),),
    )
    row = cursor.fetchone()
    if not row:
        raise KeyError(user_id)

    current_balance = int(row[0] or 0)
    new_balance = current_balance + int(delta_minor)

    if not cfg.allow_negative and new_balance < 0:
        raise ValueError("Currency balance cannot be negative")

    timestamp = datetime.now(timezone.utc).timestamp()
    cursor.execute(
        """
        UPDATE users
        SET primary_currency_balance = ?, primary_currency_updated_at = ?
        WHERE id = ?
        """,
        (new_balance, timestamp, str(user_id)),
    )

    ledger_entry = append_currency_ledger_entry(
        persistence,
        user_id=user_id,
        delta=int(delta_minor),
        balance_after=new_balance,
        reason=reason,
        metadata=metadata,
        actor_user_id=actor_user_id,
        created_at=timestamp,
    )

    # Thin audit row for symmetry: the currency ledger holds the detail
    # (delta + balance_after + actor), so the audit row just points at it via
    # ledger_id and answers "all admin actions" from one table.
    persistence_audit.record_admin_action(
        persistence,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        action="currency_adjust",
        target_user_id=user_id,
        before={"balance": current_balance},
        after={"balance": new_balance},
        metadata={"ledger_id": ledger_entry.id},
        client_ip=client_ip,
        created_at=timestamp,
        commit=False,
    )

    return ledger_entry


def set_currency_balance_in_transaction(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
    new_balance_minor: int,
    *,
    actor_user_id: uuid.UUID | None,
    actor_role: str | None,
    client_ip: str | None,
    reason: str | None = None,
    metadata: dict[str, t.Any] | None = None,
) -> CurrencyLedgerEntry:
    """Set a balance and write its ledger/audit rows in an open transaction."""
    conn = _get_connection(persistence)
    if not conn.in_transaction:
        raise RuntimeError("Currency replacement requires an open transaction.")
    cfg = get_currency_config()
    if not cfg.allow_negative and new_balance_minor < 0:
        raise ValueError("Currency balance cannot be negative")

    cursor = persistence._get_cursor()
    cursor.execute(
        "SELECT primary_currency_balance FROM users WHERE id = ?",
        (str(user_id),),
    )
    row = cursor.fetchone()
    if not row:
        raise KeyError(user_id)

    current_balance = int(row[0] or 0)
    delta = int(new_balance_minor) - current_balance

    timestamp = datetime.now(timezone.utc).timestamp()
    cursor.execute(
        """
        UPDATE users
        SET primary_currency_balance = ?, primary_currency_updated_at = ?
        WHERE id = ?
        """,
        (int(new_balance_minor), timestamp, str(user_id)),
    )

    ledger_entry = append_currency_ledger_entry(
        persistence,
        user_id=user_id,
        delta=delta,
        balance_after=int(new_balance_minor),
        reason=reason,
        metadata=metadata,
        actor_user_id=actor_user_id,
        created_at=timestamp,
    )

    # Thin audit row for symmetry (see adjust_currency_balance).
    persistence_audit.record_admin_action(
        persistence,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        action="currency_set",
        target_user_id=user_id,
        before={"balance": current_balance},
        after={"balance": int(new_balance_minor)},
        metadata={"ledger_id": ledger_entry.id},
        client_ip=client_ip,
        created_at=timestamp,
        commit=False,
    )

    return ledger_entry


async def adjust_currency_balance(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
    delta_minor: int,
    *,
    reason: str | None = None,
    metadata: dict[str, t.Any] | None = None,
) -> CurrencyLedgerEntry:
    """Trusted/system balance adjustment with atomic ledger and audit writes."""
    conn = _get_connection(persistence)
    if conn.in_transaction:
        raise RuntimeError(
            "Currency adjustments cannot run inside an existing transaction."
        )

    try:
        conn.execute("BEGIN IMMEDIATE")
        ledger_entry = adjust_currency_balance_in_transaction(
            persistence,
            user_id,
            delta_minor,
            actor_user_id=None,
            actor_role=None,
            client_ip=None,
            reason=reason,
            metadata=metadata,
        )
        conn.commit()
        return ledger_entry
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


async def set_currency_balance(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
    new_balance_minor: int,
    *,
    reason: str | None = None,
    metadata: dict[str, t.Any] | None = None,
) -> CurrencyLedgerEntry:
    """Trusted/system balance replacement with atomic ledger and audit writes."""
    conn = _get_connection(persistence)
    if conn.in_transaction:
        raise RuntimeError(
            "Currency replacements cannot run inside an existing transaction."
        )

    try:
        conn.execute("BEGIN IMMEDIATE")
        ledger_entry = set_currency_balance_in_transaction(
            persistence,
            user_id,
            new_balance_minor,
            actor_user_id=None,
            actor_role=None,
            client_ip=None,
            reason=reason,
            metadata=metadata,
        )
        conn.commit()
        return ledger_entry
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


async def list_currency_ledger(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
    *,
    limit: int = 50,
    before: datetime | None = None,
    after: datetime | None = None,
) -> list[CurrencyLedgerEntry]:
    """Retrieve ledger entries for a user ordered by most recent first."""
    cursor = persistence._get_cursor()

    clauses = ["user_id = ?"]
    params: list[t.Any] = [str(user_id)]

    if before is not None:
        clauses.append("created_at < ?")
        params.append(before.timestamp())

    if after is not None:
        clauses.append("created_at > ?")
        params.append(after.timestamp())

    query = """
        SELECT id, user_id, delta, balance_after, reason, metadata, actor_user_id, created_at
        FROM user_currency_ledger
        WHERE {conditions}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
    """.format(conditions=" AND ".join(clauses))

    params.append(max(1, min(limit, 500)))

    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [_row_to_currency_ledger_entry(row) for row in rows]


async def verify_currency_balance(
    persistence: CurrencyPersistence,
    user_id: uuid.UUID,
    *,
    auto_fix: bool = False,
) -> dict[str, t.Any]:
    """Compare one user's stored currency balance against ledger deltas."""
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    owns_transaction = auto_fix and not conn.in_transaction

    try:
        if owns_transaction:
            conn.execute("BEGIN IMMEDIATE")

        cursor.execute(
            """
            SELECT
                users.primary_currency_balance,
                COALESCE(SUM(user_currency_ledger.delta), 0)
            FROM users
            LEFT JOIN user_currency_ledger
                ON user_currency_ledger.user_id = users.id
            WHERE users.id = ?
            GROUP BY users.id, users.primary_currency_balance
            """,
            (str(user_id),),
        )
        row = cursor.fetchone()
        if not row:
            raise KeyError(user_id)

        stored_balance = int(row[0] or 0)
        ledger_balance = int(row[1] or 0)
        discrepancy = stored_balance - ledger_balance
        matches = discrepancy == 0
        fixed = False

        if auto_fix and not matches:
            cursor.execute(
                """
                UPDATE users
                SET primary_currency_balance = ?, primary_currency_updated_at = ?
                WHERE id = ?
                """,
                (
                    ledger_balance,
                    datetime.now(timezone.utc).timestamp(),
                    str(user_id),
                ),
            )
            fixed = True

        if owns_transaction:
            conn.commit()

        return _build_reconciliation_result(
            user_id=user_id,
            stored_balance=stored_balance,
            ledger_balance=ledger_balance,
            fixed=fixed,
        )
    except Exception:
        if owns_transaction:
            conn.rollback()
        raise


async def verify_all_balances(
    persistence: CurrencyPersistence,
    *,
    auto_fix: bool = False,
) -> dict[str, t.Any]:
    """Verify currency reconciliation for every user."""
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    owns_transaction = auto_fix and not conn.in_transaction

    try:
        if owns_transaction:
            conn.execute("BEGIN IMMEDIATE")

        cursor.execute(
            """
            SELECT
                users.id,
                users.primary_currency_balance,
                COALESCE(SUM(user_currency_ledger.delta), 0)
            FROM users
            LEFT JOIN user_currency_ledger
                ON user_currency_ledger.user_id = users.id
            GROUP BY users.id, users.primary_currency_balance
            ORDER BY users.created_at ASC, users.id ASC
            """
        )
        rows = cursor.fetchall()

        details: list[dict[str, t.Any]] = []
        updates: list[tuple[int, float, str]] = []
        timestamp = datetime.now(timezone.utc).timestamp()

        for row in rows:
            user_id = uuid.UUID(row[0])
            stored_balance = int(row[1] or 0)
            ledger_balance = int(row[2] or 0)
            result = _build_reconciliation_result(
                user_id=user_id,
                stored_balance=stored_balance,
                ledger_balance=ledger_balance,
                fixed=auto_fix and stored_balance != ledger_balance,
            )
            if not result["matches"]:
                details.append(result)
                if auto_fix:
                    updates.append((ledger_balance, timestamp, str(user_id)))

        if updates:
            cursor.executemany(
                """
                UPDATE users
                SET primary_currency_balance = ?, primary_currency_updated_at = ?
                WHERE id = ?
                """,
                updates,
            )

        if owns_transaction:
            conn.commit()

        return {
            "total_checked": len(rows),
            "mismatches_found": len(details),
            "fixed": len(updates),
            "details": details,
        }
    except Exception:
        if owns_transaction:
            conn.rollback()
        raise
