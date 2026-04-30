import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.config import config
from app.persistence import Persistence
from app.rate_limits import RateLimitPolicy, hash_rate_limit_key, rate_limit_key


@pytest.fixture
def temp_db(tmp_path: Path):
    db_path = tmp_path / "rate-limits.db"
    persistence = Persistence(db_path=db_path)
    try:
        yield persistence
    finally:
        persistence.close()


@pytest.fixture(autouse=True)
def rate_limit_config():
    original = {
        "RATE_LIMIT_BUCKET_GRACE_SECONDS": config.RATE_LIMIT_BUCKET_GRACE_SECONDS,
        "RATE_LIMIT_EVENT_RETENTION_SECONDS": config.RATE_LIMIT_EVENT_RETENTION_SECONDS,
    }
    config.RATE_LIMIT_BUCKET_GRACE_SECONDS = 30
    config.RATE_LIMIT_EVENT_RETENTION_SECONDS = 3600
    yield
    for key, value in original.items():
        setattr(config, key, value)


def _base_time() -> datetime:
    return datetime.fromtimestamp(1_700_000_040, tz=timezone.utc)


def _policy(scope: str = "login_identifier") -> RateLimitPolicy:
    return RateLimitPolicy(
        scope=scope,
        limit=3,
        window_seconds=120,
        bucket_seconds=30,
    )


def test_rate_limit_allows_until_threshold_then_blocks(temp_db: Persistence):
    policy = _policy()
    key = rate_limit_key("identifier", "Victim@Example.com")
    now = _base_time()

    for attempt in range(1, 4):
        decision = temp_db.check_rate_limit(policy=policy, key=key, now=now)
        assert decision.allowed is True
        assert decision.count_after == attempt
        assert decision.remaining == policy.limit - attempt

    blocked = temp_db.check_rate_limit(policy=policy, key=key, now=now)

    assert blocked.allowed is False
    assert blocked.count_after == 4
    assert blocked.remaining == 0
    assert blocked.retry_after_seconds is not None
    assert 0 < blocked.retry_after_seconds <= policy.window_seconds + policy.bucket_seconds

    row = temp_db.conn.execute(
        """
        SELECT decision, count_after, limit_count, retry_after_seconds
        FROM rate_limit_events
        WHERE scope = ?
        """,
        (policy.scope,),
    ).fetchone()
    assert row == ("deny", 4, policy.limit, blocked.retry_after_seconds)


def test_rate_limit_expires_after_rolling_window(temp_db: Persistence):
    policy = _policy()
    key = rate_limit_key("identifier", "victim@example.com")
    now = _base_time()

    for _ in range(4):
        temp_db.check_rate_limit(policy=policy, key=key, now=now)

    still_blocked = temp_db.check_rate_limit(
        policy=policy,
        key=key,
        now=now + timedelta(seconds=policy.window_seconds),
    )
    assert still_blocked.allowed is False

    allowed = temp_db.check_rate_limit(
        policy=policy,
        key=key,
        now=now + timedelta(seconds=policy.window_seconds + policy.bucket_seconds + 1),
    )
    assert allowed.allowed is True


def test_rate_limit_scopes_are_independent(temp_db: Persistence):
    key = rate_limit_key("identifier", "victim@example.com")
    now = _base_time()
    login_policy = _policy("login_identifier")
    reset_policy = _policy("password_reset_email")

    for _ in range(4):
        temp_db.check_rate_limit(policy=login_policy, key=key, now=now)

    reset_decision = temp_db.check_rate_limit(policy=reset_policy, key=key, now=now)
    assert reset_decision.allowed is True
    assert reset_decision.count_after == 1


def test_rate_limit_stores_hashed_keys_not_raw_identifiers(temp_db: Persistence):
    policy = _policy()
    raw_email = "Victim@Example.com"
    key = rate_limit_key("identifier", raw_email)

    temp_db.check_rate_limit(policy=policy, key=key, now=_base_time())

    stored_hash = temp_db.conn.execute(
        "SELECT key_hash FROM rate_limit_buckets WHERE scope = ?",
        (policy.scope,),
    ).fetchone()[0]

    assert stored_hash == hash_rate_limit_key(key)
    assert raw_email.lower() not in stored_hash
    assert "victim" not in stored_hash
    assert "example" not in stored_hash


def test_clear_rate_limit_removes_only_matching_scope_and_key(temp_db: Persistence):
    now = _base_time()
    key = rate_limit_key("identifier", "victim@example.com")
    other_key = rate_limit_key("identifier", "other@example.com")
    policy = _policy()

    temp_db.check_rate_limit(policy=policy, key=key, now=now)
    temp_db.check_rate_limit(policy=policy, key=other_key, now=now)
    temp_db.clear_rate_limit(scope=policy.scope, key=key)

    rows = temp_db.conn.execute(
        "SELECT key_hash FROM rate_limit_buckets WHERE scope = ?",
        (policy.scope,),
    ).fetchall()

    assert rows == [(hash_rate_limit_key(other_key),)]


def test_cleanup_removes_expired_buckets_and_old_events(temp_db: Persistence):
    policy = _policy()
    key = rate_limit_key("identifier", "victim@example.com")
    now = _base_time()

    for _ in range(4):
        temp_db.check_rate_limit(policy=policy, key=key, now=now)

    removed = temp_db.cleanup_rate_limits(now=now + timedelta(hours=2))

    assert removed >= 2
    assert temp_db.conn.execute("SELECT COUNT(*) FROM rate_limit_buckets").fetchone()[0] == 0
    assert temp_db.conn.execute("SELECT COUNT(*) FROM rate_limit_events").fetchone()[0] == 0


def test_rate_limit_state_survives_new_persistence_instance(tmp_path: Path):
    db_path = tmp_path / "shared-rate-limits.db"
    policy = _policy()
    key = rate_limit_key("identifier", "victim@example.com")
    now = _base_time()

    first = Persistence(db_path=db_path)
    try:
        for _ in range(3):
            first.check_rate_limit(policy=policy, key=key, now=now)
    finally:
        first.close()

    second = Persistence(db_path=db_path)
    try:
        blocked = second.check_rate_limit(policy=policy, key=key, now=now)
    finally:
        second.close()

    assert blocked.allowed is False


def test_concurrent_rate_limit_updates_are_not_lost(tmp_path: Path):
    db_path = tmp_path / "concurrent-rate-limits.db"
    Persistence(db_path=db_path).close()
    policy = RateLimitPolicy(
        scope="concurrent_login",
        limit=20,
        window_seconds=120,
        bucket_seconds=30,
        log_denies=False,
    )
    key = rate_limit_key("identifier", "victim@example.com")
    now = _base_time()
    worker_count = 8

    def consume_once() -> None:
        persistence = Persistence(db_path=db_path)
        try:
            decision = persistence.check_rate_limit(policy=policy, key=key, now=now)
            assert decision.allowed is True
        finally:
            persistence.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        list(executor.map(lambda _: consume_once(), range(worker_count)))

    verification = Persistence(db_path=db_path)
    try:
        total = verification.conn.execute(
            """
            SELECT SUM(count)
            FROM rate_limit_buckets
            WHERE scope = ? AND key_hash = ?
            """,
            (policy.scope, hash_rate_limit_key(key)),
        ).fetchone()[0]
    finally:
        verification.close()

    assert total == worker_count
