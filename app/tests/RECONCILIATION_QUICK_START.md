# Balance Reconciliation - Quick Start Guide

## TL;DR

Your stored balances and ledger must always match. These tests verify that.

## The Rule

```
ALWAYS TRUE: stored_balance == sum_of_ledger_deltas
```

## Running Tests

```bash
# Check if reconciliation holds (runs tests that work now)
pytest tests/test_currency_reconciliation.py -v -k "not verify_"

# Once methods are implemented, run all tests
pytest tests/test_currency_reconciliation.py -v
```

## What Gets Tested

### Tests That Work Now ✅
- Balance matches ledger after adjustments
- Balance matches ledger after set_balance
- Can detect manual corruption
- Edge cases (zero, negative, large amounts)

### Tests Waiting on Implementation ⏭️
- Automated verification method
- Auto-fix corrupted balances
- Bulk verification across all users

## When to Run These Tests

Run these tests when you:
- ✅ Modify `adjust_currency_balance()`
- ✅ Modify `set_currency_balance()`
- ✅ Change the `user_currency_ledger` schema
- ✅ Perform database migrations
- ✅ Suspect data corruption
- ✅ Before deploying balance-related features

## Expected Results

### ✅ All Tests Pass
Your balance system is healthy. Ship it.

### ❌ Tests Fail
**DO NOT DEPLOY.** Something is broken.

Common failure causes:
1. **Forgot to add ledger entry** in balance adjustment code
2. **Transaction not atomic** - balance and ledger updated separately
3. **Wrong delta calculation** in set_balance()
4. **Race condition** - missing BEGIN IMMEDIATE

### ⏭️ Tests Skipped
Normal. Tests skip until reconciliation methods are implemented.

## Developer Checklist

When adding new balance operations:

- [ ] Does it modify `users.primary_currency_balance`?
- [ ] Does it insert into `user_currency_ledger`?
- [ ] Are both wrapped in a single transaction?
- [ ] Does the ledger `delta` match the balance change?
- [ ] Does the ledger `balance_after` match new stored balance?
- [ ] Do reconciliation tests still pass?

## Common Mistakes

### ❌ Updating balance without ledger
```python
# WRONG - No ledger entry!
cursor.execute(
    "UPDATE users SET primary_currency_balance = ? WHERE id = ?",
    (new_balance, user_id)
)
```

### ✅ Correct way
```python
# RIGHT - Update both atomically
await persistence.adjust_currency_balance(
    user_id,
    delta_minor=amount,
    reason="Purchase",
)
```

### ❌ Non-atomic updates
```python
# WRONG - Two separate operations
await update_balance(user_id, 1000)
await add_ledger_entry(user_id, 1000)  # Could fail!
```

### ✅ Correct way
```python
# RIGHT - Single transaction
self.conn.execute("BEGIN IMMEDIATE")
try:
    cursor.execute("UPDATE users SET primary_currency_balance = ? WHERE id = ?", ...)
    self._append_currency_ledger_entry(...)
    self.conn.commit()
except:
    self.conn.rollback()
    raise
```

## Debugging Failed Tests

### Test fails: `balance_matches_ledger_after_single_adjustment`
**Issue**: Basic adjustment operation is broken
**Fix**: Check `adjust_currency_balance()` creates ledger entry

### Test fails: `set_balance_creates_correct_ledger_delta`
**Issue**: `set_balance()` calculates wrong delta
**Fix**: Delta should be `new_balance - current_balance`

### Test fails: `balance_matches_ledger_with_initial_balance`
**Issue**: User creation doesn't record initial balance in ledger
**Fix**: Check `create_user()` calls `_append_currency_ledger_entry()` when initial > 0

### Test fails: `reconciliation_across_many_transactions`
**Issue**: Rounding errors or accumulation bug
**Fix**: Ensure all math uses integers (no floats)

## Next Steps

1. **Run tests now** to verify current implementation
2. **Keep tests passing** as you add features
3. **Implement reconciliation methods** when ready for production monitoring
4. **Add to CI/CD** to catch issues before deployment

## Need Help?

- See `README_RECONCILIATION.md` for full documentation
- See `test_currency_reconciliation.py` for test code
- Check existing passing tests in `test_currency_persistence.py`
