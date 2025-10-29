"""
Tests for currency balance reconciliation and data integrity.

These tests verify that the stored balance (users.primary_currency_balance)
always matches the sum of ledger deltas (user_currency_ledger.delta).

REQUIRED METHODS (to be implemented in app.persistence.Persistence):
    - verify_currency_balance(user_id, *, auto_fix=False) -> dict
    - verify_all_balances(*, auto_fix=False) -> dict

If these methods don't exist yet, these tests will be skipped.
"""

import asyncio
from pathlib import Path
import uuid

import pytest

from app.config import config
from app.data_models import AppUser
from app.persistence import Persistence


@pytest.fixture
def temp_db(tmp_path: Path):
    """Create isolated test database."""
    db_path = tmp_path / "reconciliation_test.db"
    persistence = Persistence(db_path=db_path)
    try:
        yield persistence
    finally:
        persistence.close()


@pytest.fixture(autouse=True)
def reset_currency_config():
    """Reset config after each test."""
    original = {
        "PRIMARY_CURRENCY_INITIAL_BALANCE": config.PRIMARY_CURRENCY_INITIAL_BALANCE,
        "PRIMARY_CURRENCY_ALLOW_NEGATIVE": config.PRIMARY_CURRENCY_ALLOW_NEGATIVE,
    }
    yield
    for key, value in original.items():
        setattr(config, key, value)


async def _create_user(persistence: Persistence, email: str, password: str = "password") -> AppUser:
    """Helper to create a test user."""
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    await persistence.create_user(user)
    return await persistence.get_user_by_id(user.id)


async def _manually_corrupt_balance(persistence: Persistence, user_id: uuid.UUID, corrupted_balance: int) -> None:
    """Simulate balance corruption by directly updating without ledger."""
    cursor = persistence._get_cursor()
    cursor.execute(
        "UPDATE users SET primary_currency_balance = ? WHERE id = ?",
        (corrupted_balance, str(user_id))
    )
    persistence.conn.commit()


async def _calculate_ledger_sum(persistence: Persistence, user_id: uuid.UUID) -> int:
    """Manually calculate balance from ledger entries."""
    cursor = persistence._get_cursor()
    cursor.execute(
        "SELECT COALESCE(SUM(delta), 0) FROM user_currency_ledger WHERE user_id = ?",
        (str(user_id),)
    )
    return int(cursor.fetchone()[0])


def _has_reconciliation_methods(persistence: Persistence) -> bool:
    """Check if reconciliation methods are implemented."""
    return (
        hasattr(persistence, 'verify_currency_balance') and
        callable(getattr(persistence, 'verify_currency_balance'))
    )


# ============================================================================
# Core Reconciliation Tests
# ============================================================================

def test_balance_matches_ledger_after_single_adjustment(temp_db: Persistence):
    """Verify stored balance equals ledger sum after one transaction."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "single@example.com")

        # Make one adjustment
        await temp_db.adjust_currency_balance(
            user.id,
            delta_minor=1000,
            reason="Initial grant"
        )

        # Manually verify balance matches ledger
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert updated_user.primary_currency_balance == ledger_sum
        assert updated_user.primary_currency_balance == 1000

    asyncio.run(scenario())


def test_balance_matches_ledger_after_multiple_adjustments(temp_db: Persistence):
    """Verify stored balance equals ledger sum after multiple transactions."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "multi@example.com")

        # Perform several adjustments
        await temp_db.adjust_currency_balance(user.id, 1000, reason="Grant 1")
        await temp_db.adjust_currency_balance(user.id, 500, reason="Bonus")
        await temp_db.adjust_currency_balance(user.id, -200, reason="Purchase")
        await temp_db.adjust_currency_balance(user.id, 750, reason="Refund")

        # Verify balance matches ledger
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert updated_user.primary_currency_balance == ledger_sum
        assert updated_user.primary_currency_balance == 2050  # 1000+500-200+750

    asyncio.run(scenario())


def test_balance_matches_ledger_with_initial_balance(temp_db: Persistence):
    """Verify reconciliation works when user starts with initial balance."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 500

    async def scenario():
        user = await _create_user(temp_db, "initial@example.com")

        # User should have initial balance recorded in ledger
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)
        assert user.primary_currency_balance == 500
        assert ledger_sum == 500

        # Make additional adjustments
        await temp_db.adjust_currency_balance(user.id, 100, reason="Add")
        await temp_db.adjust_currency_balance(user.id, -50, reason="Deduct")

        # Verify still matches
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert updated_user.primary_currency_balance == ledger_sum
        assert updated_user.primary_currency_balance == 550  # 500+100-50

    asyncio.run(scenario())


def test_set_balance_creates_correct_ledger_delta(temp_db: Persistence):
    """Verify set_currency_balance maintains ledger consistency."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "setbalance@example.com")

        # Set balance to 1000
        await temp_db.set_currency_balance(
            user.id,
            new_balance_minor=1000,
            reason="Admin set"
        )

        # Verify ledger matches
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)
        assert updated_user.primary_currency_balance == 1000
        assert ledger_sum == 1000

        # Set to a different value
        await temp_db.set_currency_balance(
            user.id,
            new_balance_minor=600,
            reason="Admin adjustment"
        )

        # Verify ledger still matches (should have delta of -400)
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)
        assert updated_user.primary_currency_balance == 600
        assert ledger_sum == 600

    asyncio.run(scenario())


# ============================================================================
# Corruption Detection Tests
# ============================================================================

def test_detects_manual_balance_increase(temp_db: Persistence):
    """Verify we can detect when stored balance is manually increased."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "corrupt1@example.com")

        # Set legitimate balance
        await temp_db.adjust_currency_balance(user.id, 1000, reason="Legitimate")

        # Manually corrupt (increase without ledger entry)
        await _manually_corrupt_balance(temp_db, user.id, 1500)

        # Manual verification
        corrupted_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert corrupted_user.primary_currency_balance == 1500  # Corrupted value
        assert ledger_sum == 1000  # Ledger is correct
        assert corrupted_user.primary_currency_balance != ledger_sum  # Mismatch!

    asyncio.run(scenario())


def test_detects_manual_balance_decrease(temp_db: Persistence):
    """Verify we can detect when stored balance is manually decreased."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "corrupt2@example.com")

        # Set legitimate balance
        await temp_db.adjust_currency_balance(user.id, 1000, reason="Legitimate")

        # Manually corrupt (decrease without ledger entry)
        await _manually_corrupt_balance(temp_db, user.id, 500)

        # Manual verification
        corrupted_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert corrupted_user.primary_currency_balance == 500  # Corrupted value
        assert ledger_sum == 1000  # Ledger is correct
        assert corrupted_user.primary_currency_balance != ledger_sum  # Mismatch!

    asyncio.run(scenario())


def test_detects_missing_ledger_entries(temp_db: Persistence):
    """Verify we can detect when ledger entries are deleted."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "missing@example.com")

        # Create legitimate balance
        await temp_db.adjust_currency_balance(user.id, 1000, reason="Grant")

        # Manually delete ledger entries (simulating corruption/bug)
        cursor = temp_db._get_cursor()
        cursor.execute(
            "DELETE FROM user_currency_ledger WHERE user_id = ? AND reason = ?",
            (str(user.id), "Grant")
        )
        temp_db.conn.commit()

        # Verify mismatch
        user_after = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert user_after.primary_currency_balance == 1000  # Stored balance unchanged
        assert ledger_sum == 0  # Ledger was cleared
        assert user_after.primary_currency_balance != ledger_sum  # Mismatch!

    asyncio.run(scenario())


# ============================================================================
# Reconciliation Method Tests (if implemented)
# ============================================================================

@pytest.mark.skipif(
    not _has_reconciliation_methods(Persistence(Path("app/data/app.db"))),
    reason="verify_currency_balance method not yet implemented"
)
def test_verify_currency_balance_detects_mismatch(temp_db: Persistence):
    """Test verify_currency_balance method detects discrepancies."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "verify1@example.com")

        # Create legitimate balance
        await temp_db.adjust_currency_balance(user.id, 1000, reason="Grant")

        # Verify should pass
        result1 = await temp_db.verify_currency_balance(user.id, auto_fix=False)
        assert result1["matches"] is True
        assert result1["discrepancy"] == 0

        # Corrupt balance
        await _manually_corrupt_balance(temp_db, user.id, 1500)

        # Verify should now fail
        result2 = await temp_db.verify_currency_balance(user.id, auto_fix=False)
        assert result2["matches"] is False
        assert result2["stored_balance"] == 1500
        assert result2["ledger_balance"] == 1000
        assert result2["discrepancy"] == 500

    asyncio.run(scenario())


@pytest.mark.skipif(
    not _has_reconciliation_methods(Persistence(Path("app/data/app.db"))),
    reason="verify_currency_balance method not yet implemented"
)
def test_verify_currency_balance_auto_fix(temp_db: Persistence):
    """Test auto_fix parameter corrects discrepancies."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "autofix@example.com")

        # Create and corrupt balance
        await temp_db.adjust_currency_balance(user.id, 1000, reason="Grant")
        await _manually_corrupt_balance(temp_db, user.id, 999)

        # Auto-fix should correct the balance
        result = await temp_db.verify_currency_balance(user.id, auto_fix=True)
        assert result["matches"] is False  # Was mismatched before fix
        assert result["fixed"] is True

        # Verify it's now corrected
        fixed_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)
        assert fixed_user.primary_currency_balance == ledger_sum
        assert fixed_user.primary_currency_balance == 1000

    asyncio.run(scenario())


@pytest.mark.skipif(
    not _has_reconciliation_methods(Persistence(Path("app/data/app.db"))),
    reason="verify_all_balances method not yet implemented"
)
def test_verify_all_balances_bulk_check(temp_db: Persistence):
    """Test verify_all_balances checks multiple users."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        # Create multiple users
        users = []
        for i in range(5):
            user = await _create_user(temp_db, f"bulk{i}@example.com")
            await temp_db.adjust_currency_balance(user.id, 1000 + (i * 100), reason="Init")
            users.append(user)

        # Corrupt two users
        await _manually_corrupt_balance(temp_db, users[1].id, 999)
        await _manually_corrupt_balance(temp_db, users[3].id, 5000)

        # Verify all
        summary = await temp_db.verify_all_balances(auto_fix=False)

        assert summary["total_checked"] == 5
        assert summary["mismatches_found"] == 2
        assert len(summary["details"]) == 2

        # Check mismatch details
        mismatched_user_ids = {detail["user_id"] for detail in summary["details"]}
        assert str(users[1].id) in mismatched_user_ids
        assert str(users[3].id) in mismatched_user_ids

    asyncio.run(scenario())


@pytest.mark.skipif(
    not _has_reconciliation_methods(Persistence(Path("app/data/app.db"))),
    reason="verify_all_balances method not yet implemented"
)
def test_verify_all_balances_auto_fix_multiple(temp_db: Persistence):
    """Test auto_fix corrects multiple users at once."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        # Create users with corruption
        users = []
        for i in range(3):
            user = await _create_user(temp_db, f"multifix{i}@example.com")
            await temp_db.adjust_currency_balance(user.id, 1000, reason="Init")
            # Corrupt each one
            await _manually_corrupt_balance(temp_db, user.id, 500 + i)
            users.append(user)

        # Auto-fix all
        summary = await temp_db.verify_all_balances(auto_fix=True)

        assert summary["mismatches_found"] == 3
        assert summary["fixed"] == 3

        # Verify all are now correct
        for user in users:
            fixed_user = await temp_db.get_user_by_id(user.id)
            ledger_sum = await _calculate_ledger_sum(temp_db, user.id)
            assert fixed_user.primary_currency_balance == ledger_sum
            assert fixed_user.primary_currency_balance == 1000

    asyncio.run(scenario())


# ============================================================================
# Edge Cases
# ============================================================================

def test_zero_balance_reconciliation(temp_db: Persistence):
    """Verify reconciliation works with zero balance."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "zero@example.com")

        # User starts at zero
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)
        assert user.primary_currency_balance == 0
        assert ledger_sum == 0

    asyncio.run(scenario())


def test_negative_balance_reconciliation(temp_db: Persistence):
    """Verify reconciliation works with negative balance when allowed."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 100
    config.PRIMARY_CURRENCY_ALLOW_NEGATIVE = True

    async def scenario():
        user = await _create_user(temp_db, "negative@example.com")

        # Adjust into negative
        await temp_db.adjust_currency_balance(user.id, -150, reason="Overdraft")

        # Verify balance matches ledger
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert updated_user.primary_currency_balance == -50
        assert ledger_sum == -50
        assert updated_user.primary_currency_balance == ledger_sum

    asyncio.run(scenario())


def test_large_balance_reconciliation(temp_db: Persistence):
    """Verify reconciliation works with large balances."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "large@example.com")

        # Set very large balance
        large_amount = 999_999_999_999  # Nearly 1 trillion minor units
        await temp_db.adjust_currency_balance(user.id, large_amount, reason="Large grant")

        # Verify balance matches ledger
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert updated_user.primary_currency_balance == large_amount
        assert ledger_sum == large_amount
        assert updated_user.primary_currency_balance == ledger_sum

    asyncio.run(scenario())


def test_reconciliation_across_many_transactions(temp_db: Persistence):
    """Verify reconciliation works after many small transactions."""
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = await _create_user(temp_db, "many@example.com")

        # Perform 100 small adjustments
        expected_total = 0
        for i in range(100):
            delta = (i % 10) - 5  # Mix of positive and negative
            await temp_db.adjust_currency_balance(user.id, delta, reason=f"Transaction {i}")
            expected_total += delta

        # Verify balance matches ledger
        updated_user = await temp_db.get_user_by_id(user.id)
        ledger_sum = await _calculate_ledger_sum(temp_db, user.id)

        assert updated_user.primary_currency_balance == expected_total
        assert ledger_sum == expected_total
        assert updated_user.primary_currency_balance == ledger_sum

    asyncio.run(scenario())


# ============================================================================
# Documentation Tests
# ============================================================================

def test_reconciliation_requirements_documented():
    """Document the reconciliation invariant that must always hold."""
    invariant = """
    RECONCILIATION INVARIANT:

    At all times, the following must be true for every user:

        users.primary_currency_balance == SUM(user_currency_ledger.delta WHERE user_id = ?)

    This invariant ensures:
    1. The stored balance is always the source of truth for queries
    2. The ledger provides a complete audit trail
    3. Any discrepancy indicates a bug or data corruption
    4. The system can be verified and self-healed

    Methods that modify balance MUST:
    - Use transactions (BEGIN IMMEDIATE)
    - Update users.primary_currency_balance
    - Insert into user_currency_ledger with correct delta
    - Commit atomically

    Methods that should maintain this invariant:
    - Persistence.create_user (if initial_balance != 0)
    - Persistence.adjust_currency_balance
    - Persistence.set_currency_balance
    """

    # This test always passes; it exists to document the requirement
    assert True, invariant
