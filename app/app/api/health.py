from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.persistence import DEFAULT_DB_PATH


router = APIRouter()

HEALTH_DB_PATH = DEFAULT_DB_PATH

# Future operational work such as error tracking, metrics, tracing, log
# aggregation, dashboards, uptime monitoring, or split live/ready probes belongs
# outside this minimal health endpoint until a deployment has a concrete need.
REQUIRED_TABLES = frozenset(
    {
        "users",
        "user_sessions",
        "password_reset_tokens",
        "email_verification_tokens",
        "profiles",
        "two_factor_recovery_codes",
        "user_currency_ledger",
        "rate_limit_buckets",
        "rate_limit_events",
    }
)


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    code: str | None
    checks: dict[str, str]


def _failure(code: str, *, database: str, schema: str) -> HealthResult:
    return HealthResult(
        ok=False,
        code=code,
        checks={
            "app": "ok",
            "database": database,
            "schema": schema,
        },
    )


def check_sqlite_health(db_path: Path) -> HealthResult:
    """Check the local SQLite DB without creating or migrating anything."""
    if not db_path.exists():
        return _failure("db_missing", database="failed", schema="skipped")

    conn: sqlite3.Connection | None = None
    try:
        uri = db_path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
        conn.execute("PRAGMA query_only = ON")
        conn.execute("SELECT 1").fetchone()

        placeholders = ",".join("?" for _ in REQUIRED_TABLES)
        rows = conn.execute(
            f"""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            AND name IN ({placeholders})
            """,
            tuple(REQUIRED_TABLES),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        code = (
            "db_locked"
            if "locked" in message or "busy" in message
            else "db_unavailable"
        )
        return _failure(code, database="failed", schema="skipped")
    except sqlite3.DatabaseError:
        return _failure("db_corrupt", database="failed", schema="skipped")
    finally:
        if conn is not None:
            conn.close()

    existing_tables = {row[0] for row in rows}
    if not REQUIRED_TABLES.issubset(existing_tables):
        return _failure("schema_missing", database="ok", schema="failed")

    return HealthResult(
        ok=True,
        code=None,
        checks={
            "app": "ok",
            "database": "ok",
            "schema": "ok",
        },
    )


@router.get("/api/health")
def health_check() -> JSONResponse:
    result = check_sqlite_health(HEALTH_DB_PATH)
    payload: dict[str, object] = {
        "status": "ok" if result.ok else "unhealthy",
        "checks": result.checks,
    }
    if result.code is not None:
        payload["code"] = result.code

    return JSONResponse(
        content=payload,
        status_code=(
            status.HTTP_200_OK
            if result.ok
            else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
    )
