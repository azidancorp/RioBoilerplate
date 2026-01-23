# Pulling Upstream Updates from RioBoilerplate

This guide explains how to get updates from the RioBoilerplate template after you've integrated it into your project.

---

## Which Setup Do You Have?

**Type A (Root Structure)** - The boilerplate IS your project root. You see `app/`, `requirements.txt`, `README.md` at the top level.

**Type B (Subdirectory Structure)** - The boilerplate lives in a subdirectory like `webapp/`, `backend/`, etc. Your project has other things at the root level.

Most users have Type A. If unsure, you probably have Type A.

---

## Type A: Root Structure

This is the simple case. You merge updates directly from the boilerplate remote.

### First-Time Setup

If you haven't already added the boilerplate as a remote:

```bash
git remote add boilerplate git@github.com:azidancorp/RioBoilerplate.git
```

Verify it's set up:
```bash
git remote -v
# Should show both 'origin' (your repo) and 'boilerplate' (the template)
```

### Pulling Updates

```bash
# 1. Fetch latest from boilerplate
git fetch boilerplate

# 2. See what's new (optional)
git log HEAD..boilerplate/main --oneline

# 3. Merge
git merge boilerplate/main
```

If there are no conflicts, you're done. If there are conflicts, see [Resolving Conflicts](#resolving-conflicts) below.

### That's It

For Type A, updating is just `git fetch boilerplate && git merge boilerplate/main`. No special flags, no tracking branches, no complexity.

---

## Type B: Subdirectory Structure

If the boilerplate lives in a subdirectory (e.g., `webapp/`), you need `git subtree`.

### First-Time Setup

If you're adding the boilerplate to a subdirectory for the first time:

```bash
# Add remote
git remote add boilerplate git@github.com:azidancorp/RioBoilerplate.git

# Add as subtree (replace 'webapp' with your directory name)
git subtree add --prefix=webapp boilerplate main --squash
```

### Pulling Updates

```bash
# Fetch and merge into your subdirectory
git subtree pull --prefix=webapp boilerplate main --squash
```

The `--squash` flag keeps your history clean by combining upstream commits into one.

### Note on Subtree

`git subtree` is more complex than regular merges. If you frequently need updates, consider restructuring to Type A (boilerplate at root).

---

## Resolving Conflicts

When git can't automatically merge, it marks conflicts in the affected files:

```python
<<<<<<< HEAD
your_code = "your version"
=======
upstream_code = "upstream version"
>>>>>>> boilerplate/main
```

### Steps to Resolve

1. **Find conflicted files:**
   ```bash
   git status
   # Look for "both modified" files
   ```

2. **Edit each file** - Choose which code to keep (yours, theirs, or both), then delete the conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`)

3. **Stage resolved files:**
   ```bash
   git add path/to/resolved/file.py
   ```

4. **Complete the merge:**
   ```bash
   git commit
   ```

### Common Conflict Scenarios

| Scenario | Usually Keep |
|----------|--------------|
| You customized a config value | Yours |
| Upstream added new imports | Both (combine them) |
| Upstream fixed a bug in code you didn't modify | Theirs |
| Both modified the same function | Merge carefully - understand both changes |

### If Things Go Wrong

```bash
# Abort and start over (before committing)
git merge --abort

# Undo a completed merge (before pushing)
git reset --hard HEAD~1
```

---

## Best Practices

1. **Commit your work first** - Always start with a clean working tree
2. **Pull updates regularly** - Small frequent merges are easier than big infrequent ones
3. **Test after merging** - Run `rio run` and verify your app works
4. **Review what's coming** - Use `git log HEAD..boilerplate/main` before merging

---

## Quick Reference

```bash
# Setup (one time)
git remote add boilerplate git@github.com:azidancorp/RioBoilerplate.git

# Update (Type A - root structure)
git fetch boilerplate
git merge boilerplate/main

# Update (Type B - subdirectory)
git subtree pull --prefix=webapp boilerplate main --squash

# See what's new before merging
git log HEAD..boilerplate/main --oneline

# Abort a merge in progress
git merge --abort
```

---

## Troubleshooting

**"fatal: refusing to merge unrelated histories"**

Add `--allow-unrelated-histories` to your merge command. This happens on the first merge if you set up your project independently.

**Merge succeeded but app won't start**

1. Check `requirements.txt` - you may need to `pip install -r requirements.txt` for new dependencies
2. Check for database schema changes in the upstream commits

**Too many conflicts to handle**

Consider whether you've diverged too far from the boilerplate. You might:
- Accept upstream versions for files you haven't customized (`git checkout --theirs path/to/file`)
- Keep your versions for heavily customized files (`git checkout --ours path/to/file`)

---

**Last Updated:** 2026-01-23
