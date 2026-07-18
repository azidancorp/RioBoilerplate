import asyncio
import concurrent.futures
import hashlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event

import pytest

from app import persistence_social
from app.data_models import AppUser
from app.persistence import (
    AdminMutationContext,
    Persistence,
    _reset_initialized_db_paths,
)


PASSWORD = "VeryStrongPass!9"
FLOW_ID = "0123456789abcdef0123456789abcdef"
OTHER_FLOW_ID = "fedcba9876543210fedcba9876543210"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "oauth-pending-login-atomicity.db")
    try:
        yield persistence
    finally:
        persistence.close()


def _binding_digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


async def _create_user(
    persistence: Persistence,
    *,
    email: str,
    role: str = "user",
    social: bool = False,
) -> AppUser:
    if social:
        user = AppUser.create_social_user(
            email=email,
            provider="google",
            provider_user_id=f"sub-{email}",
        )
    else:
        user = AppUser.create_new_user_with_default_settings(
            email=email,
            password=PASSWORD,
        )
    user.role = role
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def _pending_count(persistence: Persistence, user_id: uuid.UUID) -> int:
    return persistence.conn.execute(
        "SELECT COUNT(*) FROM oauth_pending_logins WHERE user_id = ?",
        (str(user_id),),
    ).fetchone()[0]


def test_deactivation_committing_first_blocks_stale_pending_login_creation(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    target = asyncio.run(
        _create_user(
            temp_db,
            email="oauth-ordering-target@example.com",
            social=True,
        )
    )
    binding_digest = _binding_digest("deactivation-first")
    creation_reached_transaction = Event()
    original_get_connection = persistence_social._get_connection

    def signal_transaction_boundary(persistence):
        conn = original_get_connection(persistence)
        creation_reached_transaction.set()
        return conn

    monkeypatch.setattr(
        persistence_social,
        "_get_connection",
        signal_transaction_boundary,
    )

    blocker = sqlite3.connect(temp_db.db_path, timeout=30.0)
    blocker.execute("PRAGMA foreign_keys = ON")
    blocker.execute("BEGIN IMMEDIATE")
    blocker.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (str(target.id),),
    )

    def create_pending_login():
        worker = Persistence(db_path=temp_db.db_path)
        try:
            return asyncio.run(
                worker.create_oauth_pending_login(
                    binding_digest=binding_digest,
                    flow_id=FLOW_ID,
                    user_id=target.id,
                    provider="google",
                )
            )
        finally:
            worker.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(create_pending_login)
            assert creation_reached_transaction.wait(timeout=10)
            blocker.commit()
            with pytest.raises(ValueError, match="inactive"):
                future.result(timeout=20)
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()

    assert asyncio.run(temp_db.get_user_by_id(target.id)).is_active is False
    assert _pending_count(temp_db, target.id) == 0


def test_creation_committing_first_is_followed_by_deactivation_cleanup(
    temp_db: Persistence,
):
    async def scenario():
        root = await _create_user(
            temp_db,
            email="oauth-ordering-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            email="oauth-ordering-social@example.com",
            social=True,
        )
        root_session = await temp_db.create_session(root.id)
        binding_digest = _binding_digest("creation-first")
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=target.id,
            provider="google",
        )
        assert _pending_count(temp_db, target.id) == 1

        await temp_db.admin_set_user_active(
            target.id,
            False,
            admin_context=AdminMutationContext(auth_token=root_session.id),
        )

        assert _pending_count(temp_db, target.id) == 0
        with pytest.raises(KeyError):
            await temp_db.consume_oauth_pending_login(binding_digest, FLOW_ID)

    asyncio.run(scenario())


def test_user_deletion_cleans_pending_login(temp_db: Persistence):
    async def scenario():
        root = await _create_user(
            temp_db,
            email="oauth-delete-root@example.com",
            role="root",
        )
        target = await _create_user(
            temp_db,
            email="oauth-delete-target@example.com",
            social=True,
        )
        root_session = await temp_db.create_session(root.id)
        binding_digest = _binding_digest("delete-target")
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=target.id,
            provider="google",
        )

        assert await temp_db.admin_delete_user(
            target.id,
            admin_context=AdminMutationContext(auth_token=root_session.id),
        ) is True
        assert _pending_count(temp_db, target.id) == 0

    asyncio.run(scenario())


def test_pending_login_helpers_preserve_caller_owned_transactions(
    temp_db: Persistence,
):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="oauth-transaction-owner@example.com",
            social=True,
        )
        binding_digest = _binding_digest("caller-owned-transaction")
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=user.id,
            provider="google",
        )
        before = temp_db.conn.execute(
            """
            SELECT user_id, provider, created_at, valid_until
            FROM oauth_pending_logins
            WHERE binding_digest = ?
            """,
            (binding_digest,),
        ).fetchone()

        for operation in ("create", "consume"):
            temp_db.conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (f"pending-{operation}", str(user.id)),
            )
            try:
                with pytest.raises(RuntimeError, match="existing transaction"):
                    if operation == "create":
                        await temp_db.create_oauth_pending_login(
                            binding_digest=binding_digest,
                            flow_id=FLOW_ID,
                            user_id=user.id,
                            provider="google",
                        )
                    else:
                        await temp_db.consume_oauth_pending_login(binding_digest, FLOW_ID)

                assert temp_db.conn.in_transaction is True
                assert temp_db.conn.execute(
                    """
                    SELECT user_id, provider, created_at, valid_until
                    FROM oauth_pending_logins
                    WHERE binding_digest = ?
                    """,
                    (binding_digest,),
                ).fetchone() == before
                with sqlite3.connect(temp_db.db_path) as verifier:
                    assert verifier.execute(
                        "SELECT username FROM users WHERE id = ?",
                        (str(user.id),),
                    ).fetchone() == (None,)
            finally:
                temp_db.conn.rollback()

    asyncio.run(scenario())


def test_pending_login_rejects_invalid_lifetime_and_missing_user(
    temp_db: Persistence,
):
    async def scenario():
        social_user = await _create_user(
            temp_db,
            email="oauth-invalid-lifetime@example.com",
            social=True,
        )

        with pytest.raises(ValueError, match="must be positive"):
            await temp_db.create_oauth_pending_login(
                binding_digest=_binding_digest("invalid-lifetime"),
                flow_id=FLOW_ID,
                user_id=social_user.id,
                provider="google",
                ttl_minutes=0,
            )
        with pytest.raises(KeyError):
            await temp_db.create_oauth_pending_login(
                binding_digest=_binding_digest("missing-user"),
                flow_id=FLOW_ID,
                user_id=uuid.uuid4(),
                provider="google",
            )

        assert _pending_count(temp_db, social_user.id) == 0

    asyncio.run(scenario())


def test_pending_login_helpers_reject_malformed_digests(temp_db: Persistence):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="oauth-malformed-digest@example.com",
            social=True,
        )
        invalid_digests = (
            None,
            123,
            "",
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "a" * 63 + "g",
        )

        for binding_digest in invalid_digests:
            with pytest.raises(KeyError):
                await temp_db.create_oauth_pending_login(
                    binding_digest=binding_digest,
                    flow_id=FLOW_ID,
                    user_id=user.id,
                    provider="google",
                )
            with pytest.raises(KeyError):
                await temp_db.consume_oauth_pending_login(binding_digest, FLOW_ID)

        valid_digest = _binding_digest("malformed-flow-id")
        invalid_flow_ids = (
            None,
            123,
            "",
            "a" * 31,
            "a" * 33,
            "A" * 32,
            "a" * 31 + "g",
        )
        for flow_id in invalid_flow_ids:
            with pytest.raises(KeyError):
                await temp_db.create_oauth_pending_login(
                    binding_digest=valid_digest,
                    flow_id=flow_id,
                    user_id=user.id,
                    provider="google",
                )
            with pytest.raises(KeyError):
                await temp_db.consume_oauth_pending_login(valid_digest, flow_id)

        assert _pending_count(temp_db, user.id) == 0

    asyncio.run(scenario())


def test_second_creation_for_binding_replaces_first_user(temp_db: Persistence):
    async def scenario():
        first = await _create_user(
            temp_db,
            email="oauth-replacement-first@example.com",
            social=True,
        )
        second = await _create_user(
            temp_db,
            email="oauth-replacement-second@example.com",
            social=True,
        )
        binding_digest = _binding_digest("replacement-binding")

        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=first.id,
            provider="google",
        )
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=OTHER_FLOW_ID,
            user_id=second.id,
            provider="google",
        )

        assert temp_db.conn.execute(
            """
            SELECT user_id, flow_id, provider
            FROM oauth_pending_logins
            WHERE binding_digest = ?
            """,
            (binding_digest,),
        ).fetchall() == [(str(second.id), OTHER_FLOW_ID, "google")]
        consumed = await temp_db.consume_oauth_pending_login(
            binding_digest,
            OTHER_FLOW_ID,
        )
        assert consumed.id == second.id

    asyncio.run(scenario())


def test_flow_id_mismatch_rolls_back_without_deleting_row(temp_db: Persistence):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="oauth-flow-mismatch@example.com",
            social=True,
        )
        binding_digest = _binding_digest("flow-mismatch")
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=user.id,
            provider="google",
        )
        before = temp_db.conn.execute(
            """
            SELECT binding_digest, flow_id, user_id, provider, created_at,
                   valid_until
            FROM oauth_pending_logins
            WHERE binding_digest = ?
            """,
            (binding_digest,),
        ).fetchone()

        # A superseded tab's flow ID must fail without destroying the row
        # that the newest flow's landing still needs.
        with pytest.raises(KeyError, match="does not match"):
            await temp_db.consume_oauth_pending_login(
                binding_digest,
                OTHER_FLOW_ID,
            )
        assert temp_db.conn.in_transaction is False
        assert temp_db.conn.execute(
            """
            SELECT binding_digest, flow_id, user_id, provider, created_at,
                   valid_until
            FROM oauth_pending_logins
            WHERE binding_digest = ?
            """,
            (binding_digest,),
        ).fetchone() == before

        consumed = await temp_db.consume_oauth_pending_login(
            binding_digest,
            FLOW_ID,
        )
        assert consumed.id == user.id
        assert _pending_count(temp_db, user.id) == 0

    asyncio.run(scenario())


def test_pre_flow_id_pending_logins_table_is_reset_in_place(tmp_path: Path):
    db_path = tmp_path / "pre-flow-id.db"
    setup = Persistence(db_path=db_path)
    user = asyncio.run(
        _create_user(
            setup,
            email="oauth-schema-reset@example.com",
            social=True,
        )
    )
    setup.conn.execute("DROP TABLE oauth_pending_logins")
    setup.conn.execute(
        """
        CREATE TABLE oauth_pending_logins (
            binding_digest TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            created_at REAL NOT NULL,
            valid_until REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    setup.conn.execute(
        """
        INSERT INTO oauth_pending_logins (
            binding_digest, user_id, provider, created_at, valid_until
        )
        VALUES (?, ?, 'google', 0, 9999999999)
        """,
        (_binding_digest("pre-flow-id-row"), str(user.id)),
    )
    setup.conn.commit()
    setup.close()

    # Schema setup is guarded per database path per process; forget it so the
    # reopen behaves like the first boot after deploying the new schema.
    _reset_initialized_db_paths()
    reopened = Persistence(db_path=db_path)
    try:
        columns = {
            row[1]
            for row in reopened.conn.execute(
                "PRAGMA table_info(oauth_pending_logins)"
            ).fetchall()
        }
        assert "flow_id" in columns
        assert _pending_count(reopened, user.id) == 0

        # The reset must be a one-time shape upgrade, not a wipe on boot.
        asyncio.run(
            reopened.create_oauth_pending_login(
                binding_digest=_binding_digest("post-upgrade-row"),
                flow_id=FLOW_ID,
                user_id=user.id,
                provider="google",
            )
        )
    finally:
        reopened.close()

    _reset_initialized_db_paths()
    reopened_again = Persistence(db_path=db_path)
    try:
        assert _pending_count(reopened_again, user.id) == 1
    finally:
        reopened_again.close()


def test_concurrent_pending_login_consumption_is_exactly_once(
    temp_db: Persistence,
):
    async def setup():
        user = await _create_user(
            temp_db,
            email="oauth-concurrent-consume@example.com",
            social=True,
        )
        binding_digest = _binding_digest("concurrent-consume")
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=user.id,
            provider="google",
        )
        return user, binding_digest

    user, binding_digest = asyncio.run(setup())
    barrier = Barrier(2)

    def consume_in_worker():
        worker = Persistence(db_path=temp_db.db_path)
        try:
            barrier.wait(timeout=10)
            try:
                consumed = asyncio.run(
                    worker.consume_oauth_pending_login(binding_digest, FLOW_ID)
                )
            except KeyError:
                return "key_error", None
            return "success", consumed.id
        finally:
            worker.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(consume_in_worker) for _ in range(2)]
        outcomes = [future.result(timeout=20) for future in futures]

    assert sorted(outcome[0] for outcome in outcomes) == ["key_error", "success"]
    assert [outcome[1] for outcome in outcomes if outcome[0] == "success"] == [
        user.id
    ]
    assert _pending_count(temp_db, user.id) == 0


def test_consume_samples_expiry_after_acquiring_writer_lock(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def setup():
        user = await _create_user(
            temp_db,
            email="oauth-lock-time-expiry@example.com",
            social=True,
        )
        binding_digest = _binding_digest("lock-time-expiry")
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=user.id,
            provider="google",
        )
        return user, binding_digest

    user, binding_digest = asyncio.run(setup())
    before_expiry = datetime(2030, 1, 1, tzinfo=timezone.utc)
    expiry = before_expiry + timedelta(seconds=1)
    after_expiry = expiry + timedelta(seconds=1)
    release_writer = Event()

    class ControlledDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = after_expiry if release_writer.is_set() else before_expiry
            if tz is None:
                return value.replace(tzinfo=None)
            return value.astimezone(tz)

    temp_db.conn.execute(
        "UPDATE oauth_pending_logins SET valid_until = ? WHERE binding_digest = ?",
        (expiry.timestamp(), binding_digest),
    )
    temp_db.conn.commit()
    monkeypatch.setattr(persistence_social, "datetime", ControlledDateTime)

    blocker = sqlite3.connect(temp_db.db_path, timeout=30.0)
    blocker.execute("BEGIN IMMEDIATE")
    begin_attempted = Event()

    def consume_pending_login():
        worker = Persistence(db_path=temp_db.db_path)

        def trace(statement: str) -> None:
            if statement.strip().upper().startswith("BEGIN IMMEDIATE"):
                begin_attempted.set()

        worker.conn.set_trace_callback(trace)
        try:
            return asyncio.run(
                worker.consume_oauth_pending_login(binding_digest, FLOW_ID)
            )
        finally:
            worker.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(consume_pending_login)
            assert begin_attempted.wait(timeout=10)
            release_writer.set()
            blocker.commit()
            with pytest.raises(KeyError, match="expired"):
                future.result(timeout=20)
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()

    assert _pending_count(temp_db, user.id) == 0


def test_inactive_pending_login_is_deleted_on_consumption(temp_db: Persistence):
    async def scenario():
        user = await _create_user(
            temp_db,
            email="oauth-inactive-consume@example.com",
            social=True,
        )
        binding_digest = _binding_digest("inactive-consume")
        await temp_db.create_oauth_pending_login(
            binding_digest=binding_digest,
            flow_id=FLOW_ID,
            user_id=user.id,
            provider="google",
        )
        temp_db.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(user.id),),
        )
        temp_db.conn.commit()

        with pytest.raises(KeyError, match="inactive"):
            await temp_db.consume_oauth_pending_login(binding_digest, FLOW_ID)
        assert _pending_count(temp_db, user.id) == 0

    asyncio.run(scenario())
