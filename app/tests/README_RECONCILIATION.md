# Currency Balance Reconciliation Tests

## Overview

The file `test_currency_reconciliation.py` contains comprehensive tests to ensure that the **stored balance** in the `users` table always matches the **sum of ledger deltas** in the `user_currency_ledger` table.

## The Reconciliation Invariant

```
users.primary_currency_balance == SUM(user_currency_ledger.delta WHERE user_id = ?)
```

This invariant MUST hold true at all times. Any violation indicates:
- A bug in balance adjustment logic
- Data corruption
- Manual database tampering
- Missing transaction atomicity

## Test Categories

### 1. **Core Reconciliation Tests** (✅ Work Now)
Tests that verify the invariant holds after legitimate operations:
- `test_balance_matches_ledger_after_single_adjustment` - Single transaction
- `test_balance_matches_ledger_after_multiple_adjustments` - Multiple transactions
- `test_balance_matches_ledger_with_initial_balance` - With initial balance
- `test_set_balance_creates_correct_ledger_delta` - Using set_balance()

### 2. **Corruption Detection Tests** (✅ Work Now)
Tests that verify we can detect when data becomes inconsistent:
- `test_detects_manual_balance_increase` - Stored balance increased without ledger
- `test_detects_manual_balance_decrease` - Stored balance decreased without ledger
- `test_detects_missing_ledger_entries` - Ledger entries deleted

### 3. **Reconciliation Method Tests** (⏭️ Skipped Until Methods Implemented)
Tests for automated reconciliation methods (require implementation):
- `test_verify_currency_balance_detects_mismatch` - Detection method
- `test_verify_currency_balance_auto_fix` - Auto-repair functionality
- `test_verify_all_balances_bulk_check` - Bulk verification
- `test_verify_all_balances_auto_fix_multiple` - Bulk auto-repair

These tests are **skipped** until the following methods are added to `Persistence`:
```python
async def verify_currency_balance(
    self,
    user_id: uuid.UUID,
    *,
    auto_fix: bool = False
) -> dict[str, Any]:
    """
    Verify that stored balance matches ledger sum.

    Returns:
        {
            'matches': bool,
            'stored_balance': int,
            'ledger_balance': int,
            'discrepancy': int,
            'fixed': bool
        }
    """
    pass

async def verify_all_balances(
    self,
    *,
    auto_fix: bool = False
) -> dict[str, Any]:
    """
    Verify all users' balances.

    Returns:
        {
            'total_checked': int,
            'mismatches_found': int,
            'fixed': int,
            'details': list[dict]
        }
    """
    pass
```

### 4. **Edge Cases** (✅ Work Now)
Tests for boundary conditions:
- `test_zero_balance_reconciliation` - Zero balance
- `test_negative_balance_reconciliation` - Negative balances (when allowed)
- `test_large_balance_reconciliation` - Very large balances
- `test_reconciliation_across_many_transactions` - 100+ transactions

## Running the Tests

```bash
# Run all reconciliation tests
pytest tests/test_currency_reconciliation.py -v

# Run only tests that work now (skip unimplemented methods)
pytest tests/test_currency_reconciliation.py -v -k "not verify_"

# Run specific test
pytest tests/test_currency_reconciliation.py::test_balance_matches_ledger_after_multiple_adjustments -v
```

## Test Results Interpretation

### All Tests Pass ✅
Balance system is working correctly and maintaining data integrity.

### Some Tests Fail ❌
- **Immediate Action Required**: Data corruption or logic bug detected
- Check failed test names to identify which operation broke the invariant
- Review recent code changes to balance adjustment logic
- Run reconciliation fix if data corruption occurred

### Tests Skipped ⏭️
Reconciliation methods not yet implemented. Tests will automatically activate once methods are added.

## Implementation Checklist

To make all tests pass, implement these in order:

### Phase 1: Core Verification (Required)
- [ ] Add `verify_currency_balance()` method to `Persistence`
- [ ] Add SQL query to sum ledger deltas
- [ ] Compare stored balance to ledger sum
- [ ] Return detailed mismatch info

### Phase 2: Auto-Fix (Optional but Recommended)
- [ ] Add `auto_fix` parameter support
- [ ] Correct stored balance to match ledger
- [ ] Log correction in ledger metadata
- [ ] Wrap in transaction for atomicity

### Phase 3: Bulk Operations (For Production)
- [ ] Add `verify_all_balances()` method
- [ ] Iterate over all users
- [ ] Collect mismatch summaries
- [ ] Support bulk auto-fix

### Phase 4: Tooling (For Ops)
- [ ] CLI script for manual reconciliation
- [ ] Admin UI button for verification
- [ ] Scheduled daily health checks
- [ ] Alerting on mismatches

## Security Considerations

1. **Reconciliation methods are READ operations** when `auto_fix=False`
   - Safe to run in production
   - No data modifications
   - Can be exposed to admins

2. **Auto-fix is a WRITE operation**
   - Should require admin/root role
   - Should log all corrections
   - Should use transactions
   - Consider requiring approval for bulk fixes

3. **Audit trail**
   - All auto-fixes should create ledger entries
   - Include metadata about what was corrected
   - Track who initiated the fix

## Performance Notes

- **Verification query** uses `SUM(delta)` - efficient with proper index
- **Index required**: `CREATE INDEX idx_currency_ledger_user_id_created ON user_currency_ledger(user_id, created_at DESC)`
- For large ledgers (>10K entries per user), query should still be fast (<100ms)
- Bulk verification iterates all users - can be slow with thousands of users
- Consider pagination for bulk operations in production

## False Positive Prevention

These scenarios are **NOT** reconciliation failures:
1. Active transaction in progress (wait for commit)
2. Concurrent updates using proper locking (transaction serialization works)
3. Race conditions between read and write (use `BEGIN IMMEDIATE`)

These scenarios **ARE** reconciliation failures:
1. Stored balance != ledger sum after transaction commits
2. Missing ledger entries for completed balance changes
3. Ledger entries exist but stored balance wasn't updated
4. Manual database edits that bypassed ledger

## Related Files

- `app/persistence.py` - Main persistence layer (add methods here)
- `app/data_models.py` - `CurrencyLedgerEntry` dataclass
- `tests/test_currency_persistence.py` - Related balance tests
- `tests/test_currency_api.py` - API endpoint tests
- `BASE_CURRENCY_V1.md` - Original implementation plan

## Monitoring Recommendations

In production, you should:
1. **Run daily reconciliation checks** (read-only, log mismatches)
2. **Alert on any mismatches** (immediate investigation required)
3. **Track reconciliation metrics** (mismatches over time)
4. **Audit auto-fixes** (review correction ledger entries monthly)
5. **Test after schema changes** (migration validation)

## Questions?

For implementation guidance, see the comprehensive method implementations in the initial analysis that suggested these tests. The methods include:
- Full SQL queries for verification
- Transaction handling for auto-fix
- Metadata logging for audit trail
- Error handling and edge cases
