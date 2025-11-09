# RioBoilerplate Upstream Merge Guide

**A step-by-step guide for safely merging upstream RioBoilerplate updates into your active project**

---

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Setup: Tracking the Upstream](#setup-tracking-the-upstream)
4. [Pre-Merge Checklist](#pre-merge-checklist)
5. [The Merge Process](#the-merge-process)
6. [Conflict Resolution](#conflict-resolution)
7. [Post-Merge Verification](#post-merge-verification)
8. [Common Issues & Recovery](#common-issues--recovery)
9. [Best Practices](#best-practices)

---

## Overview

When you base your project on RioBoilerplate, you start with the template files in a subdirectory (e.g., `nnw/`) and build custom features on top. Over time, the upstream RioBoilerplate template gets updates (bug fixes, new features, security patches) that you want to integrate into your project.

**The Challenge:** Merge upstream improvements WITHOUT losing your custom work.

**The Solution:** Git subtree merge with manual conflict resolution.

---

## Prerequisites

### Repository Structure
Your repository should have:
- **Main branch:** Contains your full project with the boilerplate in a subdirectory (e.g., `nnw/`)
- **Upstream tracking branch:** A branch that tracks RioBoilerplate updates (e.g., `rioboilerplate-upstream`)
- **Git remote:** A remote pointing to the RioBoilerplate repository

### Required Knowledge
- Basic Git operations (commit, add, status)
- Understanding of merge conflicts
- Text editor capable of handling conflict markers

---

## Setup: Tracking the Upstream

### First-Time Setup

If you haven't already set up upstream tracking:

```bash
# 1. Add RioBoilerplate as a remote
git remote add rioboilerplate https://github.com/azidancorp/RioBoilerplate.git

# 2. Fetch the upstream repository
git fetch rioboilerplate

# 3. Create a tracking branch
git checkout -b rioboilerplate-upstream rioboilerplate/main
git push -u origin rioboilerplate-upstream

# 4. Switch back to your main branch
git checkout main
```

### Updating the Upstream Branch

Before each merge, update your upstream tracking branch:

```bash
# Switch to upstream branch
git checkout rioboilerplate-upstream

# Pull latest changes from RioBoilerplate
git pull rioboilerplate main

# Push to your repository
git push origin rioboilerplate-upstream

# Return to main branch
git checkout main
```

---

## Pre-Merge Checklist

**CRITICAL:** Complete ALL steps before starting the merge.

### 1. Commit All Work
```bash
git status
```
Ensure output shows:
```
nothing to commit, working tree clean
```

If you have uncommitted changes:
```bash
git add .
git commit -m "Your commit message"
```

### 2. Create a Backup Branch (Optional but Recommended)
```bash
git checkout -b backup-before-merge
git checkout main
```

This allows easy recovery if something goes wrong.

### 3. Document Current State

Take note of:
- Custom files you've created (pages, components, scripts)
- Modified configuration files
- Custom color schemes or styling
- Any project-specific data

**Example for this project:**
```bash
# List custom pages
ls nnw/app/app/pages/app_page/

# Expected custom files:
# - account.py
# - extract.py
# - matches.py
# - matchmaking.py
# - messages.py
# - profile.py
# - search.py
# - seek.py
```

### 4. Review Upstream Changes

Check what's new in the upstream:
```bash
git log main..rioboilerplate-upstream --oneline
```

This shows commits you'll be merging.

---

## The Merge Process

### Step 1: Initiate the Merge

Use the `--no-commit` flag to review changes before finalizing:

```bash
git merge --no-commit --allow-unrelated-histories -X subtree=nnw rioboilerplate-upstream
```

**Flags explained:**
- `--no-commit`: Don't auto-commit, allowing manual review
- `--allow-unrelated-histories`: Required because upstream and your branch have different roots
- `-X subtree=nnw`: Tells git the upstream root maps to your `nnw/` directory
  - **IMPORTANT:** Replace `nnw` with your actual subdirectory name

### Step 2: Initial Status Check

```bash
git status
```

You'll see three categories:
1. **Changes to be committed:** Files merged cleanly
2. **Unmerged paths:** Files with conflicts requiring manual resolution
3. **Working tree clean** or **uncommitted changes:** Shouldn't appear (if it does, something went wrong)

### Step 3: Verify Custom Files Preserved

**CRITICAL CHECK:** Ensure your custom files still exist:

```bash
# Example: Check custom pages
ls nnw/app/app/pages/app_page/
```

If custom files are missing, **ABORT THE MERGE** and see [Recovery Section](#recovery-from-failed-merge).

### Step 4: Check for Conflict Markers

Find all files with conflict markers:

```bash
find nnw -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null
```

This lists files needing manual resolution.

---

## Conflict Resolution

### Understanding Conflict Markers

When Git can't auto-merge, it inserts markers:

```python
<<<<<<< HEAD
# Your current code
your_variable = "your value"
=======
# Upstream code
upstream_variable = "upstream value"
>>>>>>> rioboilerplate-upstream
```

**Your job:** Choose which code to keep or merge both.

### Resolution Strategy

For each conflicted file:

1. **Open in your editor**
2. **Search for `<<<<<<<`** to find conflicts
3. **Decide what to keep:**
   - Keep your version only
   - Keep upstream version only
   - Merge both (combine features)
4. **Remove ALL markers:** `<<<<<<<`, `=======`, `>>>>>>>`
5. **Test the logic** if possible

### Common Conflict Patterns

#### Pattern 1: Import Statements
```python
<<<<<<< HEAD
from app.validation import SecuritySanitizer
=======
from app.validation import SecuritySanitizer
from app.api.auth_dependencies import get_current_user
>>>>>>> rioboilerplate-upstream
```

**Resolution:** Keep both (upstream adds new import)
```python
from app.validation import SecuritySanitizer
from app.api.auth_dependencies import get_current_user
```

#### Pattern 2: Configuration Values
```python
<<<<<<< HEAD
bg_color = rio.Color.from_rgb(0.2, 0, 0)  # Your custom red
=======
bg_color = theme.shade_color(theme.PRIMARY_COLOR, 0.9)  # Generic theme
>>>>>>> rioboilerplate-upstream
```

**Resolution:** Keep your custom value
```python
bg_color = rio.Color.from_rgb(0.2, 0, 0)  # Your custom red
```

#### Pattern 3: New Features
```python
<<<<<<< HEAD
# Your existing function
def process_data():
    return data
=======
# Upstream added error handling
def process_data():
    try:
        return data
    except Exception as e:
        log_error(e)
        raise
>>>>>>> rioboilerplate-upstream
```

**Resolution:** Merge both (add upstream improvements)
```python
def process_data():
    try:
        return data
    except Exception as e:
        log_error(e)
        raise
```

### Resolving Conflicts Efficiently

```bash
# 1. List all conflicted files
git diff --name-only --diff-filter=U

# 2. For each file, open in editor
# Edit the file, resolve conflicts, save

# 3. Stage resolved file
git add path/to/resolved/file.py

# 4. Verify no conflicts remain
find nnw -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null
```

**Expected output when done:** (empty)

---

## Post-Merge Verification

### 1. Final Conflict Check

```bash
# Should return no results
find nnw -type f -exec grep -l "<<<<<<< HEAD\|=======\|>>>>>>> rioboilerplate-upstream" {} \; 2>/dev/null
```

### 2. Verify Custom Work Preserved

Check that your custom files still exist and have correct content:

```bash
# List custom pages
ls nnw/app/app/pages/app_page/

# Check custom components
ls nnw/app/app/components/

# Verify custom data
ls nnw/app/app/data/
```

### 3. Check for Subtle Overwrites

**IMPORTANT:** Even if files exist, their content might have been overwritten.

Check critical customizations:

```bash
# Example: Verify color scheme in sidebar
grep -n "Color.from_rgb" nnw/app/app/components/sidebar.py

# Example: Verify custom configuration
grep -n "CUSTOM_" nnw/app/app/config.py
```

If customizations are lost, restore them from git history:

```bash
# View your version before merge
git show HEAD~1:nnw/app/app/components/sidebar.py

# Or compare
git diff HEAD~1:nnw/app/app/components/sidebar.py nnw/app/app/components/sidebar.py
```

### 4. Stage All Changes

Once everything is verified and resolved:

```bash
git add nnw/
git status
```

Expected output:
```
All conflicts fixed but you are still merging.
  (use "git commit" to conclude merge)

Changes to be committed:
    modified:   nnw/...
    new file:   nnw/...
    ...
```

### 5. Commit the Merge

```bash
git commit -m "$(cat <<'EOF'
Merge RioBoilerplate upstream updates into nnw/

Integrated [NUMBER] commits from RioBoilerplate template with custom features preserved.

New Features Added:
- [Feature 1]
- [Feature 2]
- [Feature 3]

Modified Files (conflicts resolved):
- [File 1]
- [File 2]

Custom Work Preserved:
- All custom pages: [list key pages]
- Custom configurations: [list key configs]
- Project-specific data and styling

Documentation:
- [New doc files]
EOF
)"
```

### 6. Verify Commit

```bash
git log --oneline -5
git status
```

Should show clean working tree.

### 7. Test the Application

**CRITICAL:** Test before pushing to production.

```bash
cd nnw/app
rio run --port 8000
```

Test checklist:
- [ ] Application starts without errors
- [ ] Login/authentication works
- [ ] Custom pages load correctly
- [ ] New features are accessible
- [ ] No visual regressions (colors, layout)
- [ ] Database operations work
- [ ] API endpoints respond correctly

### 8. Push to Remote

Once tested:

```bash
git push origin main
```

---

## Common Issues & Recovery

### Issue 1: Custom Files Deleted

**Symptom:** After merge, custom pages/files are missing.

**Cause:** Wrong merge strategy or subtree path.

**Recovery:**
```bash
# Abort the merge
git merge --abort

# Verify files are back
ls nnw/app/app/pages/app_page/

# Try again with correct flags
git merge --no-commit --allow-unrelated-histories -X subtree=nnw rioboilerplate-upstream
```

### Issue 2: Merge Already Committed (Can't Abort)

**Symptom:** You ran merge without `--no-commit` and custom files are gone.

**Recovery:**
```bash
# Reset to before merge (assumes merge was the last commit)
git reset --hard HEAD~1

# Verify files are restored
git status
ls nnw/app/app/pages/app_page/

# Try again with --no-commit flag
```

### Issue 3: Too Many Conflicts

**Symptom:** Dozens of conflicted files, overwhelming to resolve.

**Strategy:**

1. **Focus on critical files first:**
   - `__init__.py`
   - `persistence.py`
   - `data_models.py`

2. **Use a merge tool:**
   ```bash
   # Configure git mergetool (one-time setup)
   git config merge.tool vimdiff  # or meld, kdiff3, etc.

   # Use it
   git mergetool
   ```

3. **Take breaks:** Resolve in batches, commit progress
   ```bash
   # After resolving 5-10 files
   git add resolved_files...
   # Continue with next batch
   ```

### Issue 4: Conflicting Dependencies

**Symptom:** `requirements.txt` has conflicts, unclear which to keep.

**Resolution:**
```bash
# View both versions
git show HEAD:nnw/requirements.txt > /tmp/yours.txt
git show rioboilerplate-upstream:requirements.txt > /tmp/upstream.txt

# Compare
diff /tmp/yours.txt /tmp/upstream.txt

# Strategy:
# 1. Keep all YOUR custom dependencies
# 2. Add NEW upstream dependencies
# 3. Update VERSION numbers for shared dependencies (use upstream versions)
```

### Issue 5: Application Won't Start After Merge

**Symptom:** `rio run` fails with import errors or runtime exceptions.

**Debugging steps:**

1. **Check imports:**
   ```bash
   python3 -c "import app"
   ```

2. **Check for missing dependencies:**
   ```bash
   pip install -r nnw/requirements.txt
   ```

3. **Check database schema:**
   ```bash
   # May need to update database if upstream changed schema
   # Check upstream migration notes
   ```

4. **Review merge commit:**
   ```bash
   git show HEAD --stat
   git diff HEAD~1 HEAD -- nnw/app/app/__init__.py
   ```

5. **If all else fails, revert:**
   ```bash
   git revert HEAD
   ```

---

## Best Practices

### 1. Merge Frequently
- Don't let upstream get too far ahead
- Smaller, frequent merges are easier than big, infrequent ones
- Aim for monthly or quarterly merges

### 2. Always Use --no-commit
```bash
# GOOD
git merge --no-commit --allow-unrelated-histories -X subtree=nnw rioboilerplate-upstream

# BAD (auto-commits, harder to verify)
git merge -s subtree rioboilerplate-upstream
```

### 3. Document Customizations
Maintain a file like `CUSTOMIZATIONS.md` listing:
- Custom files you created
- Configuration changes from defaults
- Styling/theme modifications
- Any deviations from the boilerplate

### 4. Use Feature Branches for Major Merges
```bash
git checkout -b merge-upstream-2025-01
git merge --no-commit --allow-unrelated-histories -X subtree=nnw rioboilerplate-upstream
# ... resolve conflicts ...
git commit
git push origin merge-upstream-2025-01
# Create PR, review, then merge to main
```

### 5. Read Upstream Changelog
Before merging:
```bash
# Check what's changed
git log main..rioboilerplate-upstream --oneline

# Read detailed changes
git log main..rioboilerplate-upstream

# Look for breaking changes in commit messages
git log main..rioboilerplate-upstream | grep -i "break\|deprecat\|remov"
```

### 6. Test Thoroughly
Create a test checklist based on your app:
- [ ] Core authentication flows
- [ ] All custom pages
- [ ] Database operations
- [ ] API endpoints
- [ ] External integrations
- [ ] Visual appearance
- [ ] Mobile responsiveness

### 7. Backup Before Merging
```bash
# Tag current state
git tag backup-before-upstream-merge-$(date +%Y%m%d)
git push --tags

# Or create a branch
git branch backup-before-merge
```

---

## Amending the Merge Commit

If you discover issues immediately after committing the merge (before pushing):

### Scenario 1: Forgot to Include a Fix

```bash
# Make your fix (e.g., restore color scheme)
# Edit the file

# Stage the fix
git add nnw/app/app/components/sidebar.py

# Amend the merge commit
git commit --amend --no-edit
```

### Scenario 2: Need to Fix Multiple Files

```bash
# Fix all issues
# Stage all fixes
git add nnw/

# Amend with updated message
git commit --amend
# Edit message in editor if needed
```

**WARNING:** Only amend commits that haven't been pushed yet!

---

## Quick Reference Commands

### Setup
```bash
git remote add rioboilerplate https://github.com/azidancorp/RioBoilerplate.git
git fetch rioboilerplate
git checkout -b rioboilerplate-upstream rioboilerplate/main
git push -u origin rioboilerplate-upstream
```

### Update Upstream
```bash
git checkout rioboilerplate-upstream
git pull rioboilerplate main
git push origin rioboilerplate-upstream
git checkout main
```

### Merge Process
```bash
# 1. Ensure clean state
git status

# 2. Merge without committing
git merge --no-commit --allow-unrelated-histories -X subtree=nnw rioboilerplate-upstream

# 3. Verify custom files preserved
ls nnw/app/app/pages/app_page/

# 4. Find conflicts
find nnw -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# 5. Resolve each conflict, then stage
git add path/to/resolved/file

# 6. Verify all resolved
find nnw -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# 7. Stage everything
git add nnw/

# 8. Commit
git commit

# 9. Test
cd nnw/app && rio run

# 10. Push
git push origin main
```

### Abort/Recover
```bash
# Abort in-progress merge
git merge --abort

# Undo last commit (not pushed)
git reset --hard HEAD~1

# View file from before merge
git show HEAD~1:path/to/file
```

---

## Troubleshooting Checklist

Before asking for help, verify:

- [ ] Used `--no-commit` flag
- [ ] Specified correct subtree path (`-X subtree=nnw`)
- [ ] Working tree was clean before merge
- [ ] All conflict markers removed
- [ ] Custom files still exist
- [ ] Application runs without errors
- [ ] Staged all changes before committing
- [ ] Tested thoroughly before pushing

---

## Conclusion

Merging upstream updates is a routine maintenance task that becomes easier with practice. The key principles:

1. **Prepare:** Clean state, backup, review changes
2. **Merge carefully:** Use `--no-commit` and `-X subtree`
3. **Verify thoroughly:** Check custom work preserved
4. **Resolve methodically:** One conflict at a time
5. **Test extensively:** Before pushing to production

Keep this guide handy for future merges. Each time you merge, you'll get faster and more confident with the process.

---

**Last Updated:** 2025-11-09
**Based on:** Actual merge of RioBoilerplate upstream into nikahnetwork/nnw
**Verified with:** Git 2.x, RioBoilerplate template structure
