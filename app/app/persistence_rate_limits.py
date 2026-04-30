from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Protocol

from app.config import config
from app.rate_limits import (
    RateLimitDecision,
    RateLimitPolicy,
    hash_rate_limit_key,
    utc_now,
)


class RateLimitPersistence(Protocol):
    conn: sqlite3.Connection | None

    def _ensure_connection(self) -> None:
        ...

    def _get_cursor(self) -> sqlite3.Cursor:
        ...


def _get_connection(persistence: RateLimitPersistence) -> sqlite3.Connection:
    persistence._ensure_connection()
    if persistence.conn is None:
        raise RuntimeError("Database connection is not initialized")
    return persistence.conn


def _coerce_now(now: datetime | None) -> datetime:
    current = now or utc_now()
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _bucket_start(timestamp: float, bucket_seconds: int) -> int:
    return int(timestamp // bucket_seconds) * bucket_seconds


def _decision_from_rows(
    rows: list[tuple[int, int]],
    *,
    policy: RateLimitPolicy,
    now_ts: float,
    total: int,
) -> tuple[bool, int | None, datetime]:
    if total <= policy.limit:
        # For allowed requests, reset_at is the earliest active bucket expiry:
        # the first moment any counted request ages out of the rolling window.
        reset_ts = (
            min((start + policy.window_seconds + policy.bucket_seconds for start, _ in rows), default=now_ts + policy.window_seconds)
        )
        return True, None, datetime.fromtimestamp(reset_ts, tz=timezone.utc)

    excess = total - policy.limit
    retry_after = policy.bucket_seconds
    for start, count in rows:
        excess -= count
        retry_after = max(
            1,
            int(math.ceil(start + policy.window_seconds + policy.bucket_seconds - now_ts)),
        )
        if excess <= 0:
            break

    reset_at = datetime.fromtimestamp(now_ts + retry_after, tz=timezone.utc)
    return False, retry_after, reset_at


def _metadata_json(metadata: Mapping[str, object] | None) -> str | None:
    if not metadata:
        return None
    return json.dumps(dict(metadata), sort_keys=True, separators=(",", ":"))


def check_rate_limit(
    persistence: RateLimitPersistence,
    *,
    policy: RateLimitPolicy,
    key: str,
    cost: int = 1,
    now: datetime | None = None,
    metadata: Mapping[str, object] | None = None,
) -> RateLimitDecision:
    if cost <= 0:
        raise ValueError("Rate-limit cost must be positive.")

    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    current = _coerce_now(now)
    now_ts = current.timestamp()
    key_hash = hash_rate_limit_key(key)
    bucket_start = _bucket_start(now_ts, policy.bucket_seconds)
    bucket_expires_at = (
        bucket_start
        + policy.window_seconds
        + policy.bucket_seconds
        + config.RATE_LIMIT_BUCKET_GRACE_SECONDS
    )
    event_prune_before = now_ts - config.RATE_LIMIT_EVENT_RETENTION_SECONDS
    oldest_bucket_start = _bucket_start(
        now_ts - policy.window_seconds,
        policy.bucket_seconds,
    )

    conn.execute("BEGIN IMMEDIATE")
    try:
        cursor.execute(
            "DELETE FROM rate_limit_buckets WHERE expires_at <= ?",
            (now_ts,),
        )
        cursor.execute(
            "DELETE FROM rate_limit_events WHERE created_at <= ?",
            (event_prune_before,),
        )
        cursor.execute(
            """
            INSERT INTO rate_limit_buckets (
                scope,
                key_hash,
                bucket_start,
                bucket_seconds,
                count,
                first_seen_at,
                updated_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, key_hash, bucket_start, bucket_seconds)
            DO UPDATE SET
                count = count + excluded.count,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at
            """,
            (
                policy.scope,
                key_hash,
                bucket_start,
                policy.bucket_seconds,
                cost,
                now_ts,
                now_ts,
                bucket_expires_at,
            ),
        )
        cursor.execute(
            """
            SELECT bucket_start, count
            FROM rate_limit_buckets
            WHERE scope = ?
              AND key_hash = ?
              AND bucket_seconds = ?
              AND bucket_start >= ?
            ORDER BY bucket_start ASC
            """,
            (policy.scope, key_hash, policy.bucket_seconds, oldest_bucket_start),
        )
        rows = [(int(row[0]), int(row[1])) for row in cursor.fetchall()]
        total = sum(count for _, count in rows)
        allowed, retry_after, reset_at = _decision_from_rows(
            rows,
            policy=policy,
            now_ts=now_ts,
            total=total,
        )

        if not allowed and policy.log_denies:
            cursor.execute(
                """
                INSERT INTO rate_limit_events (
                    scope,
                    key_hash,
                    decision,
                    count_after,
                    limit_count,
                    retry_after_seconds,
                    metadata,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy.scope,
                    key_hash,
                    "deny",
                    total,
                    policy.limit,
                    retry_after,
                    _metadata_json(metadata),
                    now_ts,
                ),
            )

        conn.commit()
        return RateLimitDecision(
            allowed=allowed,
            remaining=max(0, policy.limit - total),
            count_after=total,
            retry_after_seconds=retry_after,
            reset_at=reset_at,
        )
    except Exception:
        conn.rollback()
        raise


def clear_rate_limit(
    persistence: RateLimitPersistence,
    *,
    scope: str,
    key: str,
) -> None:
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    cursor.execute(
        "DELETE FROM rate_limit_buckets WHERE scope = ? AND key_hash = ?",
        (scope, hash_rate_limit_key(key)),
    )
    conn.commit()


def cleanup_rate_limits(
    persistence: RateLimitPersistence,
    *,
    now: datetime | None = None,
) -> int:
    conn = _get_connection(persistence)
    cursor = persistence._get_cursor()
    now_ts = _coerce_now(now).timestamp()
    event_prune_before = now_ts - config.RATE_LIMIT_EVENT_RETENTION_SECONDS
    cursor.execute("DELETE FROM rate_limit_buckets WHERE expires_at <= ?", (now_ts,))
    removed = cursor.rowcount
    cursor.execute(
        "DELETE FROM rate_limit_events WHERE created_at <= ?",
        (event_prune_before,),
    )
    removed += cursor.rowcount
    conn.commit()
    return removed
