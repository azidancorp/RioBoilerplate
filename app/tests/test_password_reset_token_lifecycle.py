import asyncio
import concurrent.futures
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

import app.persistence_auth as persistence_auth
from app.data_models import AppUser
from app.persistence import Persistence, _reset_initialized_db_paths


PASSWORD = "OldStrongPass!123"
NEW_PASSWORD = "NewStrongPass!456"
RESET_TOKEN_USER_INDEX = "idx_password_reset_tokens_user_id"


async def _create_password_user(
    persistence: Persistence,
    email: str,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password=PASSWORD,
    )
    # MFA enrollment requires a verified email.
    user.is_verified = True
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def _reset_token_count(persistence: Persistence, user_id: uuid.UUID) -> int:
    return int(
        persistence.conn.execute(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ?",
            (str(user_id),),
        ).fetchone()[0]
    )


def _insert_reset_token(
    persistence: Persistence,
    *,
    user_id: uuid.UUID,
    raw_token: str,
) -> None:
    now = datetime.now(timezone.utc)
    persistence.conn.execute(
        """
        INSERT INTO password_reset_tokens (token_hash, user_id, created_at, valid_until)
        VALUES (?, ?, ?, ?)
        """,
        (
            persistence._hash_one_time_token(raw_token),
            str(user_id),
            now.timestamp(),
            (now + timedelta(minutes=30)).timestamp(),
        ),
    )
    persistence.conn.commit()


def test_normal_password_change_invalidates_reset_token_and_cannot_be_overwritten(
    tmp_path: Path,
):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "password-change.db")
        try:
            user = await _create_password_user(
                persistence,
                "password-change-reset@example.com",
            )
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)

            await persistence.update_password(user.id, NEW_PASSWORD)

            refreshed = await persistence.get_user_by_id(user.id)
            assert refreshed.verify_password(NEW_PASSWORD)
            assert not refreshed.verify_password(PASSWORD)
            with pytest.raises(KeyError):
                await persistence.get_session_by_auth_token(session.id)
            with pytest.raises(KeyError):
                await persistence.get_user_by_reset_token(reset_token.token)
            assert await persistence.consume_reset_token_and_update_password(
                reset_token.token,
                user.id,
                "AttackerChosenPass!789",
            ) is False

            after_replay = await persistence.get_user_by_id(user.id)
            assert after_replay.verify_password(NEW_PASSWORD)
            assert not after_replay.verify_password("AttackerChosenPass!789")
            assert _reset_token_count(persistence, user.id) == 0
        finally:
            persistence.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["update", "reset"])
def test_password_mutations_accept_acknowledged_live_context_warning(
    tmp_path: Path,
    operation: str,
):
    async def scenario() -> None:
        persistence = Persistence(
            db_path=tmp_path / f"acknowledged-live-context-{operation}.db"
        )
        password = "Context.Account-2026@example.com"
        try:
            user = await _create_password_user(persistence, password)
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)

            with pytest.raises(ValueError, match="acknowledge"):
                if operation == "update":
                    await persistence.update_password(user.id, password)
                else:
                    await persistence.consume_reset_token_and_update_password(
                        reset_token.token,
                        user.id,
                        password,
                    )

            unchanged = await persistence.get_user_by_id(user.id)
            assert unchanged.verify_password(PASSWORD)
            assert not unchanged.verify_password(password)
            assert (
                await persistence.get_session_by_auth_token(session.id)
            ).user_id == user.id
            assert _reset_token_count(persistence, user.id) == 1

            if operation == "update":
                await persistence.update_password(
                    user.id,
                    password,
                    acknowledged_weak=True,
                )
            else:
                assert await persistence.consume_reset_token_and_update_password(
                    reset_token.token,
                    user.id,
                    password,
                    acknowledged_weak=True,
                )

            updated = await persistence.get_user_by_id(user.id)
            assert updated.verify_password(password)
            assert not updated.verify_password(PASSWORD)
            with pytest.raises(KeyError):
                await persistence.get_session_by_auth_token(session.id)
            assert _reset_token_count(persistence, user.id) == 0
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_missing_reset_token_and_user_returns_false_without_hashing(
    tmp_path: Path,
    monkeypatch,
):
    persistence = Persistence(db_path=tmp_path / "missing-reset-token.db")

    def fail_if_hashed(_password: str):
        raise AssertionError("A missing reset token must not trigger Argon2")

    monkeypatch.setattr(
        persistence_auth.password_utils,
        "hash_password",
        fail_if_hashed,
    )
    try:
        assert asyncio.run(
            persistence.consume_reset_token_and_update_password(
                "A" * 32,
                uuid.uuid4(),
                NEW_PASSWORD,
            )
        ) is False
    finally:
        persistence.close()


def test_wrong_reset_token_owner_is_cleaned_without_hashing(
    tmp_path: Path,
    monkeypatch,
):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "wrong-reset-owner.db")
        try:
            user = await _create_password_user(
                persistence,
                "reset-owner@example.com",
            )
            reset_token = await persistence.create_reset_token(user.id)

            def fail_if_hashed(_password: str):
                raise AssertionError("A mismatched reset token must not trigger Argon2")

            monkeypatch.setattr(
                persistence_auth.password_utils,
                "hash_password",
                fail_if_hashed,
            )
            assert await persistence.consume_reset_token_and_update_password(
                reset_token.token,
                uuid.uuid4(),
                NEW_PASSWORD,
            ) is False
            with pytest.raises(KeyError):
                await persistence.get_user_by_reset_token(reset_token.token)
        finally:
            persistence.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["update", "reset"])
@pytest.mark.parametrize(
    ("context_column", "new_context_value"),
    [
        ("email", "new.account.name@example.com"),
        ("username", "new-account-name-2026"),
    ],
)
def test_password_mutations_recheck_live_account_context_after_hashing(
    tmp_path: Path,
    monkeypatch,
    operation: str,
    context_column: str,
    new_context_value: str,
):
    async def scenario() -> None:
        db_path = tmp_path / f"live-context-{operation}-{context_column}.db"
        persistence = Persistence(db_path=db_path)
        try:
            user = await _create_password_user(
                persistence,
                f"old-{operation}-{context_column}@example.com",
            )
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)
            auth_state_before = persistence.conn.execute(
                """
                SELECT password_hash, password_salt, password_scheme
                FROM users
                WHERE id = ?
                """,
                (str(user.id),),
            ).fetchone()
            original_hash_password = persistence_auth.password_utils.hash_password
            context_changed = False

            def change_context_then_hash(password: str):
                nonlocal context_changed
                if not context_changed:
                    context_changed = True
                    other = Persistence(db_path=db_path)
                    try:
                        other.conn.execute(
                            f"UPDATE users SET {context_column} = ? WHERE id = ?",
                            (new_context_value, str(user.id)),
                        )
                        other.conn.commit()
                    finally:
                        other.close()
                return original_hash_password(password)

            monkeypatch.setattr(
                persistence_auth.password_utils,
                "hash_password",
                change_context_then_hash,
            )
            with pytest.raises(
                ValueError,
                match="account identifier.*predictable",
            ):
                if operation == "update":
                    await persistence.update_password(
                        user.id,
                        new_context_value,
                    )
                else:
                    await persistence.consume_reset_token_and_update_password(
                        reset_token.token,
                        user.id,
                        new_context_value,
                    )

            assert persistence.conn.execute(
                f"SELECT {context_column} FROM users WHERE id = ?",
                (str(user.id),),
            ).fetchone() == (new_context_value,)
            assert persistence.conn.execute(
                """
                SELECT password_hash, password_salt, password_scheme
                FROM users
                WHERE id = ?
                """,
                (str(user.id),),
            ).fetchone() == auth_state_before
            assert (
                await persistence.get_session_by_auth_token(session.id)
            ).user_id == user.id
            assert _reset_token_count(persistence, user.id) == 1
        finally:
            persistence.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("state_column", "new_state", "message"),
    [
        ("is_active", 0, "Inactive users"),
        ("auth_provider", "oidc", "External-auth users"),
    ],
)
def test_password_update_rechecks_live_account_state_after_hashing(
    tmp_path: Path,
    monkeypatch,
    state_column: str,
    new_state: object,
    message: str,
):
    async def scenario() -> None:
        db_path = tmp_path / f"live-password-state-{state_column}.db"
        persistence = Persistence(db_path=db_path)
        try:
            user = await _create_password_user(
                persistence,
                f"live-{state_column}@example.com",
            )
            session = await persistence.create_session(user.id)
            await persistence.create_reset_token(user.id)
            auth_state_before = persistence.conn.execute(
                """
                SELECT password_hash, password_salt, password_scheme
                FROM users
                WHERE id = ?
                """,
                (str(user.id),),
            ).fetchone()
            original_hash_password = persistence_auth.password_utils.hash_password
            state_changed = False

            def change_state_then_hash(password: str):
                nonlocal state_changed
                if not state_changed:
                    state_changed = True
                    other = Persistence(db_path=db_path)
                    try:
                        other.conn.execute(
                            f"UPDATE users SET {state_column} = ? WHERE id = ?",
                            (new_state, str(user.id)),
                        )
                        other.conn.commit()
                    finally:
                        other.close()
                return original_hash_password(password)

            monkeypatch.setattr(
                persistence_auth.password_utils,
                "hash_password",
                change_state_then_hash,
            )
            with pytest.raises(ValueError, match=message):
                await persistence.update_password(user.id, NEW_PASSWORD)

            assert persistence.conn.execute(
                f"SELECT {state_column} FROM users WHERE id = ?",
                (str(user.id),),
            ).fetchone() == (new_state,)
            assert persistence.conn.execute(
                """
                SELECT password_hash, password_salt, password_scheme
                FROM users
                WHERE id = ?
                """,
                (str(user.id),),
            ).fetchone() == auth_state_before
            assert (
                await persistence.get_session_by_auth_token(session.id)
            ).user_id == user.id
            assert _reset_token_count(persistence, user.id) == 1
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_failed_password_change_rolls_back_password_session_and_reset_token(
    tmp_path: Path,
):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "password-change-rollback.db")
        try:
            user = await _create_password_user(
                persistence,
                "password-change-rollback@example.com",
            )
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)
            persistence.conn.execute(
                f"""
                CREATE TRIGGER fail_reset_token_delete
                BEFORE DELETE ON password_reset_tokens
                WHEN OLD.user_id = '{user.id}'
                BEGIN
                    SELECT RAISE(ABORT, 'forced reset-token delete failure');
                END
                """
            )
            persistence.conn.commit()

            with pytest.raises(sqlite3.IntegrityError):
                await persistence.update_password(user.id, NEW_PASSWORD)

            persistence.conn.execute("DROP TRIGGER fail_reset_token_delete")
            persistence.conn.commit()
            refreshed = await persistence.get_user_by_id(user.id)
            assert refreshed.verify_password(PASSWORD)
            assert not refreshed.verify_password(NEW_PASSWORD)
            assert (await persistence.get_session_by_auth_token(session.id)).user_id == user.id
            assert (await persistence.get_user_by_reset_token(reset_token.token)).id == user.id
            assert _reset_token_count(persistence, user.id) == 1
            assert persistence.conn.in_transaction is False
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_failed_session_bound_password_change_rolls_back_recovery_code(
    tmp_path: Path,
):
    async def scenario() -> None:
        persistence = Persistence(
            db_path=tmp_path / "session-password-change-rollback.db"
        )
        try:
            user = await _create_password_user(
                persistence,
                "session-password-change-rollback@example.com",
            )
            recovery_code = persistence.enroll_two_factor(
                user.id,
                pyotp.random_base32(),
                count=1,
            )[0]
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)
            persistence.conn.execute(
                f"""
                CREATE TRIGGER fail_session_reset_token_delete
                BEFORE DELETE ON password_reset_tokens
                WHEN OLD.user_id = '{user.id}'
                BEGIN
                    SELECT RAISE(ABORT, 'forced reset-token delete failure');
                END
                """
            )
            persistence.conn.commit()

            with pytest.raises(sqlite3.IntegrityError):
                await persistence.change_password_for_session(
                    auth_token=session.id,
                    current_password=PASSWORD,
                    new_password=NEW_PASSWORD,
                    two_factor_code=recovery_code,
                )

            persistence.conn.execute(
                "DROP TRIGGER fail_session_reset_token_delete"
            )
            persistence.conn.commit()
            refreshed = await persistence.get_user_by_id(user.id)
            assert refreshed.verify_password(PASSWORD)
            assert not refreshed.verify_password(NEW_PASSWORD)
            assert (
                await persistence.get_session_by_auth_token(session.id)
            ).user_id == user.id
            assert (
                await persistence.get_user_by_reset_token(reset_token.token)
            ).id == user.id
            assert persistence.get_recovery_codes_summary(user.id)["remaining"] == 1
            assert persistence.conn.in_transaction is False
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_failed_reset_completion_rolls_back_password_session_and_reset_token(
    tmp_path: Path,
):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "reset-completion-rollback.db")
        try:
            user = await _create_password_user(
                persistence,
                "reset-completion-rollback@example.com",
            )
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)
            persistence.conn.execute(
                f"""
                CREATE TRIGGER fail_consumed_reset_token_delete
                BEFORE DELETE ON password_reset_tokens
                WHEN OLD.user_id = '{user.id}'
                BEGIN
                    SELECT RAISE(ABORT, 'forced consumed-token delete failure');
                END
                """
            )
            persistence.conn.commit()

            with pytest.raises(sqlite3.IntegrityError):
                await persistence.consume_reset_token_and_update_password(
                    reset_token.token,
                    user.id,
                    NEW_PASSWORD,
                )

            persistence.conn.execute(
                "DROP TRIGGER fail_consumed_reset_token_delete"
            )
            persistence.conn.commit()
            refreshed = await persistence.get_user_by_id(user.id)
            assert refreshed.verify_password(PASSWORD)
            assert not refreshed.verify_password(NEW_PASSWORD)
            assert (await persistence.get_session_by_auth_token(session.id)).user_id == user.id
            assert (await persistence.get_user_by_reset_token(reset_token.token)).id == user.id
            assert _reset_token_count(persistence, user.id) == 1
            assert persistence.conn.in_transaction is False
        finally:
            persistence.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("operation", "error_message"),
    [
        (
            "change_password_for_session",
            "Session-bound password change cannot run inside an existing transaction",
        ),
        (
            "update_password",
            "Password update cannot run inside an existing transaction",
        ),
        (
            "consume_reset_token_and_update_password",
            "Password reset completion cannot run inside an existing transaction",
        ),
    ],
)
def test_password_mutations_reject_caller_owned_transaction(
    tmp_path: Path,
    operation: str,
    error_message: str,
):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / f"{operation}.db")
        try:
            user = await _create_password_user(
                persistence,
                f"{operation}@example.com",
            )
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)
            token_hash = persistence._hash_one_time_token(reset_token.token)
            session_hash = persistence._hash_one_time_token(session.id)

            auth_state_before = persistence.conn.execute(
                """
                SELECT password_hash, password_salt, password_scheme
                FROM users
                WHERE id = ?
                """,
                (str(user.id),),
            ).fetchone()

            persistence.conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                ("caller-pending", str(user.id)),
            )

            try:
                with pytest.raises(RuntimeError, match=error_message):
                    if operation == "change_password_for_session":
                        await persistence.change_password_for_session(
                            auth_token=session.id,
                            current_password=PASSWORD,
                            new_password=NEW_PASSWORD,
                        )
                    elif operation == "update_password":
                        await persistence.update_password(user.id, NEW_PASSWORD)
                    else:
                        await persistence.consume_reset_token_and_update_password(
                            reset_token.token,
                            user.id,
                            NEW_PASSWORD,
                        )

                assert persistence.conn.in_transaction is True
                assert persistence.conn.execute(
                    "SELECT username FROM users WHERE id = ?",
                    (str(user.id),),
                ).fetchone() == ("caller-pending",)
                with sqlite3.connect(persistence.db_path) as verifier:
                    assert verifier.execute(
                        "SELECT username FROM users WHERE id = ?",
                        (str(user.id),),
                    ).fetchone() == (None,)

                assert persistence.conn.execute(
                    """
                    SELECT password_hash, password_salt, password_scheme
                    FROM users
                    WHERE id = ?
                    """,
                    (str(user.id),),
                ).fetchone() == auth_state_before
                assert persistence.conn.execute(
                    "SELECT 1 FROM user_sessions WHERE id = ?",
                    (session_hash,),
                ).fetchone() == (1,)
                assert persistence.conn.execute(
                    "SELECT 1 FROM password_reset_tokens WHERE token_hash = ?",
                    (token_hash,),
                ).fetchone() == (1,)
            finally:
                persistence.conn.rollback()
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_new_reset_token_replaces_previous_token(tmp_path: Path):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "sequential-reset-tokens.db")
        try:
            user = await _create_password_user(
                persistence,
                "sequential-reset@example.com",
            )
            first = await persistence.create_reset_token(user.id)
            second = await persistence.create_reset_token(user.id)

            with pytest.raises(KeyError):
                await persistence.get_user_by_reset_token(first.token)
            assert (await persistence.get_user_by_reset_token(second.token)).id == user.id
            assert _reset_token_count(persistence, user.id) == 1
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_failed_reset_token_rotation_preserves_previous_token(tmp_path: Path):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "reset-rotation-rollback.db")
        try:
            user = await _create_password_user(
                persistence,
                "reset-rotation-rollback@example.com",
            )
            previous = await persistence.create_reset_token(user.id)
            persistence.conn.execute(
                """
                CREATE TRIGGER fail_reset_token_insert
                BEFORE INSERT ON password_reset_tokens
                BEGIN
                    SELECT RAISE(ABORT, 'forced reset-token insert failure');
                END
                """
            )
            persistence.conn.commit()

            with pytest.raises(sqlite3.IntegrityError):
                await persistence.create_reset_token(user.id)

            persistence.conn.execute("DROP TRIGGER fail_reset_token_insert")
            persistence.conn.commit()
            assert (await persistence.get_user_by_reset_token(previous.token)).id == user.id
            assert _reset_token_count(persistence, user.id) == 1
            assert persistence.conn.in_transaction is False
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_concurrent_reset_token_issuance_leaves_exactly_one_valid_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    db_path = tmp_path / "concurrent-reset-tokens.db"

    async def setup() -> AppUser:
        persistence = Persistence(db_path=db_path)
        try:
            return await _create_password_user(
                persistence,
                "concurrent-reset@example.com",
            )
        finally:
            persistence.close()

    user = asyncio.run(setup())
    start_barrier = threading.Barrier(2)
    legacy_clear_barrier = threading.Barrier(2)
    original_clear = persistence_auth.clear_reset_tokens

    async def synchronized_legacy_clear(
        persistence: Persistence,
        user_id: uuid.UUID,
    ) -> None:
        await original_clear(persistence, user_id)
        legacy_clear_barrier.wait(timeout=10)

    # This forces the old clear/commit + insert/commit implementation into its
    # vulnerable DELETE/DELETE/INSERT/INSERT ordering. Atomic issuance no longer
    # calls this standalone helper, so the barrier is intentionally unused there.
    monkeypatch.setattr(
        persistence_auth,
        "clear_reset_tokens",
        synchronized_legacy_clear,
    )

    def issue() -> str:
        persistence = Persistence(db_path=db_path)
        try:
            start_barrier.wait(timeout=10)
            return asyncio.run(persistence.create_reset_token(user.id)).token
        finally:
            persistence.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(issue) for _ in range(2)]
        tokens = [future.result(timeout=15) for future in futures]

    verification = Persistence(db_path=db_path)
    try:
        validity: list[bool] = []

        async def token_is_valid(raw_token: str) -> bool:
            try:
                await verification.get_user_by_reset_token(raw_token)
            except KeyError:
                return False
            return True

        for token in tokens:
            validity.append(asyncio.run(token_is_valid(token)))

        assert _reset_token_count(verification, user.id) == 1
        assert validity.count(True) == 1
        assert validity.count(False) == 1
    finally:
        verification.close()


def test_reset_completion_invalidates_all_legacy_sibling_tokens(tmp_path: Path):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "reset-siblings.db")
        try:
            user = await _create_password_user(
                persistence,
                "reset-siblings@example.com",
            )
            other_user = await _create_password_user(
                persistence,
                "reset-siblings-other@example.com",
            )
            primary = await persistence.create_reset_token(user.id)
            other = await persistence.create_reset_token(other_user.id)
            persistence.conn.execute(f"DROP INDEX {RESET_TOKEN_USER_INDEX}")
            persistence.conn.commit()
            sibling_token = "A" * 32
            _insert_reset_token(
                persistence,
                user_id=user.id,
                raw_token=sibling_token,
            )
            assert _reset_token_count(persistence, user.id) == 2

            assert await persistence.consume_reset_token_and_update_password(
                primary.token,
                user.id,
                NEW_PASSWORD,
            ) is True

            assert _reset_token_count(persistence, user.id) == 0
            with pytest.raises(KeyError):
                await persistence.get_user_by_reset_token(primary.token)
            with pytest.raises(KeyError):
                await persistence.get_user_by_reset_token(sibling_token)
            assert (await persistence.get_user_by_reset_token(other.token)).id == other_user.id
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_reset_token_uniqueness_migration_invalidates_legacy_rows_once(
    tmp_path: Path,
):
    db_path = tmp_path / "reset-token-migration.db"

    async def create_legacy_state() -> tuple[uuid.UUID, str]:
        persistence = Persistence(db_path=db_path)
        try:
            user = await _create_password_user(
                persistence,
                "reset-migration@example.com",
            )
            original = await persistence.create_reset_token(user.id)
            persistence.conn.execute(f"DROP INDEX {RESET_TOKEN_USER_INDEX}")
            persistence.conn.commit()
            _insert_reset_token(
                persistence,
                user_id=user.id,
                raw_token="B" * 32,
            )
            assert _reset_token_count(persistence, user.id) == 2
            return user.id, original.token
        finally:
            persistence.close()

    user_id, legacy_token = asyncio.run(create_legacy_state())
    _reset_initialized_db_paths()
    migrated = Persistence(db_path=db_path)
    try:
        assert _reset_token_count(migrated, user_id) == 0
        indexes = {
            row[1]: row
            for row in migrated.conn.execute(
                "PRAGMA index_list(password_reset_tokens)"
            ).fetchall()
        }
        assert RESET_TOKEN_USER_INDEX in indexes
        assert indexes[RESET_TOKEN_USER_INDEX][2] == 1
        indexed_columns = [
            row[2]
            for row in migrated.conn.execute(
                f"PRAGMA index_info({RESET_TOKEN_USER_INDEX})"
            ).fetchall()
        ]
        assert indexed_columns == ["user_id"]

        with pytest.raises(KeyError):
            asyncio.run(migrated.get_user_by_reset_token(legacy_token))

        current = asyncio.run(migrated.create_reset_token(user_id))
        now = datetime.now(timezone.utc)
        with pytest.raises(sqlite3.IntegrityError):
            migrated.conn.execute(
                """
                INSERT INTO password_reset_tokens
                    (token_hash, user_id, created_at, valid_until)
                VALUES (?, ?, ?, ?)
                """,
                (
                    migrated._hash_one_time_token("C" * 32),
                    str(user_id),
                    now.timestamp(),
                    (now + timedelta(minutes=30)).timestamp(),
                ),
            )
        migrated.conn.rollback()
    finally:
        migrated.close()

    _reset_initialized_db_paths()
    reopened = Persistence(db_path=db_path)
    try:
        assert asyncio.run(reopened.get_user_by_reset_token(current.token)).id == user_id
        assert _reset_token_count(reopened, user_id) == 1
    finally:
        reopened.close()


def test_external_auth_user_cannot_issue_or_consume_reset_token(tmp_path: Path):
    async def scenario() -> None:
        persistence = Persistence(db_path=tmp_path / "external-auth-reset.db")
        try:
            user = AppUser.create_social_user(
                email="external-reset@example.com",
                provider="oidc",
                provider_user_id="external-reset-user",
            )
            await persistence._create_user_unchecked(user)

            with pytest.raises(ValueError):
                await persistence.create_reset_token(user.id)

            stale_token = "D" * 32
            _insert_reset_token(
                persistence,
                user_id=user.id,
                raw_token=stale_token,
            )
            assert await persistence.consume_reset_token_and_update_password(
                stale_token,
                user.id,
                NEW_PASSWORD,
            ) is False

            refreshed = await persistence.get_user_by_id(user.id)
            assert refreshed.auth_provider == "oidc"
            assert refreshed.password_hash is None
            assert _reset_token_count(persistence, user.id) == 0
        finally:
            persistence.close()

    asyncio.run(scenario())
