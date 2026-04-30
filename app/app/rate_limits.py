from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from app.config import config


_DEVELOPMENT_HMAC_SECRET = "rio-boilerplate-development-rate-limit-secret"


@dataclass(frozen=True)
class RateLimitPolicy:
    scope: str
    limit: int
    window_seconds: int
    bucket_seconds: int = 60
    log_denies: bool = True

    def __post_init__(self) -> None:
        if not self.scope:
            raise ValueError("Rate limit scope is required.")
        if self.limit <= 0:
            raise ValueError("Rate limit limit must be positive.")
        if self.window_seconds <= 0:
            raise ValueError("Rate limit window_seconds must be positive.")
        if self.bucket_seconds <= 0:
            raise ValueError("Rate limit bucket_seconds must be positive.")


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    count_after: int
    retry_after_seconds: int | None
    reset_at: datetime


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_rate_limit_value(value: object) -> str:
    normalized = str(value or "").strip().lower()
    return " ".join(normalized.split()) or "unknown"


def rate_limit_key(kind: str, value: object) -> str:
    return f"{normalize_rate_limit_value(kind)}:{normalize_rate_limit_value(value)}"


def hash_rate_limit_key(key: str) -> str:
    secret = config.RATE_LIMIT_HMAC_SECRET or _DEVELOPMENT_HMAC_SECRET
    return hmac.new(
        secret.encode("utf-8"),
        normalize_rate_limit_value(key).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def token_rate_limit_key(token: str) -> str:
    digest = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
    return rate_limit_key("token", digest)


def format_retry_after(seconds: int | None) -> str:
    remaining = max(1, int(math.ceil(seconds or 1)))
    units = (
        (86400, "day"),
        (3600, "hour"),
        (60, "minute"),
        (1, "second"),
    )
    parts: list[str] = []
    for unit_seconds, label in units:
        value, remaining = divmod(remaining, unit_seconds)
        if not value:
            continue
        suffix = "" if value == 1 else "s"
        parts.append(f"{value} {label}{suffix}")
        if len(parts) == 2:
            break
    return ", ".join(parts) if parts else "1 second"


def rate_limited_message(prefix: str, retry_after_seconds: int | None) -> str:
    return f"{prefix} Please wait {format_retry_after(retry_after_seconds)} and try again."


def first_blocked(decisions: Iterable[RateLimitDecision]) -> RateLimitDecision | None:
    for decision in decisions:
        if not decision.allowed:
            return decision
    return None
