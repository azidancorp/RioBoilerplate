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

When you base your project on RioBoilerplate, you integrate the template into your repository. This integration can follow one of two structures:

**Type A - Direct/Root Structure:** Your project root IS the RioBoilerplate webapp
- Structure: `ProjectRoot/app/app/...` (mirrors `RioBoilerplate/app/app/...`)
- Example: Your entire repository is a RioBoilerplate webapp

**Type B - Subdirectory Structure:** RioBoilerplate lives in a subdirectory
- Structure: `ProjectRoot/webapp/app/app/...` (or `nnw/`, `backend/`, etc.)
- Example: You have multiple apps/sections in your project (such as mobile, research, etc), and the RioBoilerplate webapp is just one subdirectory

Over time, the upstream RioBoilerplate template gets updates (bug fixes, new features, security patches) that you want to integrate into your project.

**The Challenge:** Merge upstream improvements WITHOUT losing your custom work, regardless of your project structure.

**The Solution:** Git subtree merge with manual conflict resolution, adapted to your specific structure.

---

## Prerequisites

### Repository Structure
Your repository should have:
- **Main branch:** Contains your full project (with or without RioBoilerplate in a subdirectory)
- **Upstream tracking branch:** A branch that tracks RioBoilerplate updates (e.g., `rioboilerplate-upstream`)
- **Git remote:** A remote pointing to the RioBoilerplate repository

### Required Knowledge
- Basic Git operations (commit, add, status)
- Understanding of merge conflicts
- Text editor capable of handling conflict markers

### Determining Your Project Structure

**CRITICAL:** Before merging, you MUST identify which structure type you have. The merge command differs significantly between them.

#### Step 1: Check Your Directory Layout

Run from your project root:
```bash
ls -la
```

**Type A Indicators (Direct/Root Structure):**
- You see `app/` and `requirements.txt` at the root level, and `rio.toml` lives inside that outer `app/` directory
- Your project root directly contains the Rio application (within `app/`)
- Structure looks like:
  ```
  ProjectRoot/
  ├── app/
  │   ├── rio.toml
  │   ├── app/
  │   │   ├── __init__.py
  │   │   ├── pages/
  │   │   ├── components/
  │   │   └── ...
  │   ├── assets/
  │   └── data/
  ├── requirements.txt
  └── ...
  ```

**Type B Indicators (Subdirectory Structure):**
- You see a subdirectory (e.g., `webapp/`, `nnw/`, `backend/`) that contains the Rio app, and inside that subdirectory's `app/` directory sits `rio.toml`
- Your project root has OTHER things besides the Rio app
- Structure looks like:
  ```
  ProjectRoot/
  ├── webapp/          # Or nnw/, backend/, etc.
  │   ├── app/
  │   │   ├── rio.toml
  │   │   ├── app/
  │   │   │   ├── __init__.py
  │   │   │   ├── pages/
  │   │   │   └── ...
  │   │   ├── assets/
  │   │   └── data/
  │   ├── requirements.txt
  ├── docs/
  ├── frontend/
  └── ...
  ```

#### Step 2: Confirm with rio.toml

Find your `rio.toml` file:

```bash
# Type A: In the outer app/ directory at the project root
cat app/rio.toml

# Type B: In the subdirectory's outer app/ directory
cat $WEBAPP_DIR/app/rio.toml  # Replace 'webapp' with your actual subdirectory name
```

If `app/rio.toml` exists directly under your project root → **Type A**
If you only find `rio.toml` under `$WEBAPP_DIR/app/` → **Type B**

#### Step 3: Set Your Variables

Based on your structure, set these variables for the rest of this guide:

**For Type A (Direct/Root Structure):**
```bash
export WEBAPP_DIR="."
export SUBTREE_FLAG=""
```

**For Type B (Subdirectory Structure):**
```bash
# Replace 'webapp' with YOUR actual subdirectory name (e.g., nnw, backend, etc.)
export WEBAPP_DIR="webapp"
export SUBTREE_FLAG="-X subtree=$WEBAPP_DIR"
```

**Verify your settings:**
```bash
echo "Webapp directory: $WEBAPP_DIR"
echo "Subtree flag: $SUBTREE_FLAG"

# Test that your paths work
ls $WEBAPP_DIR/app/app/pages/
```

If the last command shows your pages, you've configured correctly.

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

**Using the variables from "Determining Your Project Structure" above:**

```bash
# List custom pages (works for both Type A and Type B)
ls $WEBAPP_DIR/app/app/pages/app_page/

# List custom components
ls $WEBAPP_DIR/app/app/components/

# Check custom data files
ls $WEBAPP_DIR/app/app/data/
```

**Examples of custom files you might see:**
- Custom pages: `account.py`, `profile.py`, `dashboard_custom.py`
- Custom components: `custom_sidebar.py`, `custom_navbar.py`
- Custom data: `custom_data.csv`, `app.db`

### 4. Review Upstream Changes

Check what's new in the upstream:
```bash
git log main..rioboilerplate-upstream --oneline
```

This shows commits you'll be merging.

---

## The Merge Process

### Step 1: Initiate the Merge

Use the `--no-commit` flag to review changes before finalizing.

**IMPORTANT:** The merge command differs based on your project structure!

#### For Type A (Direct/Root Structure):

```bash
git merge --no-commit --allow-unrelated-histories rioboilerplate-upstream
```

#### For Type B (Subdirectory Structure):

```bash
# Using the variable you set earlier
git merge --no-commit --allow-unrelated-histories $SUBTREE_FLAG rioboilerplate-upstream

# Or explicitly (replace 'webapp' with YOUR subdirectory name)
git merge --no-commit --allow-unrelated-histories -X subtree=webapp rioboilerplate-upstream
```

**Flags explained:**
- `--no-commit`: Don't auto-commit, allowing manual review
- `--allow-unrelated-histories`: Required because upstream and your branch have different roots
- `-X subtree=<dir>`: **Only for Type B** - Tells git the upstream root maps to your subdirectory
  - Omit this flag entirely for Type A (direct/root structure)
  - For Type B, replace `<dir>` with your actual subdirectory name (e.g., `webapp`, `nnw`, `backend`)

### Step 2: Initial Status Check

```bash
git status
```

You'll see three categories:
1. **Changes to be committed:** Files merged cleanly
2. **Unmerged paths:** Files with conflicts requiring manual resolution
3. **Working tree clean** or **uncommitted changes:** Shouldn't appear (if it does, something went wrong)

### Step 3: Verify Custom Files Preserved

**CRITICAL CHECK:** Ensure your custom files still exist.

```bash
# Using the variable (works for both Type A and Type B)
ls $WEBAPP_DIR/app/app/pages/app_page/

# Type A example (if WEBAPP_DIR is ".")
ls app/app/pages/app_page/

# Type B example (if WEBAPP_DIR is "webapp")
ls webapp/app/app/pages/app_page/
```

If custom files are missing, **ABORT THE MERGE** and see [Recovery Section](#common-issues--recovery).

### Step 4: Check for Conflict Markers

Find all files with conflict markers:

```bash
# Using the variable (works for both Type A and Type B)
find $WEBAPP_DIR -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# Type A example (searches from root)
find . -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# Type B example (searches in subdirectory)
find webapp -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null
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

# 4. Verify no conflicts remain (using your $WEBAPP_DIR variable)
find $WEBAPP_DIR -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null
```

**Expected output when done:** (empty)

---

## Post-Merge Verification

### 1. Final Conflict Check

```bash
# Using the variable (works for both Type A and Type B)
find $WEBAPP_DIR -type f -exec grep -l "<<<<<<< HEAD\|=======\|>>>>>>> rioboilerplate-upstream" {} \; 2>/dev/null

# Type A example
find . -type f -exec grep -l "<<<<<<< HEAD\|=======\|>>>>>>> rioboilerplate-upstream" {} \; 2>/dev/null

# Type B example
find webapp -type f -exec grep -l "<<<<<<< HEAD\|=======\|>>>>>>> rioboilerplate-upstream" {} \; 2>/dev/null
```

**Expected result:** No output (all conflicts resolved)

### 2. Verify Custom Work Preserved

Check that your custom files still exist and have correct content:

```bash
# List custom pages (using variable)
ls $WEBAPP_DIR/app/app/pages/app_page/

# Check custom components
ls $WEBAPP_DIR/app/app/components/

# Verify custom data
ls $WEBAPP_DIR/app/app/data/
```

### 3. Check for Subtle Overwrites

**IMPORTANT:** Even if files exist, their content might have been overwritten.

Check critical customizations:

```bash
# Example: Verify color scheme in sidebar (using variable)
grep -n "Color.from_rgb" $WEBAPP_DIR/app/app/components/sidebar.py

# Example: Verify custom configuration
grep -n "CUSTOM_" $WEBAPP_DIR/app/app/config.py
```

If customizations are lost, restore them from git history:

```bash
# View your version before merge (replace path as needed)
git show HEAD~1:$WEBAPP_DIR/app/app/components/sidebar.py

# Or compare
git diff HEAD~1:$WEBAPP_DIR/app/app/components/sidebar.py $WEBAPP_DIR/app/app/components/sidebar.py
```

### 4. Stage All Changes

Once everything is verified and resolved:

**For Type A (Direct/Root):**
```bash
git add .
git status
```

**For Type B (Subdirectory):**
```bash
git add $WEBAPP_DIR/
# Or explicitly
git add webapp/
git status
```

Expected output:
```
All conflicts fixed but you are still merging.
  (use "git commit" to conclude merge)

Changes to be committed:
    modified:   ...
    new file:   ...
    ...
```

### 5. Commit the Merge

**For Type A (Direct/Root):**
```bash
git commit -m "$(cat <<'EOF'
Merge RioBoilerplate upstream updates

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

**For Type B (Subdirectory):**
```bash
git commit -m "$(cat <<'EOF'
Merge RioBoilerplate upstream updates into webapp/

Integrated [NUMBER] commits from RioBoilerplate template with custom features preserved.
Replace 'webapp/' with your actual subdirectory name in the title above.

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

**For Type A (Direct/Root):**
```bash
cd app  # Outer app/ directory that holds rio.toml
rio run --port 8000
```

**For Type B (Subdirectory):**
```bash
cd $WEBAPP_DIR/app  # Outer app/ directory inside your subdirectory
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

**Cause:** Wrong merge strategy or subtree path (most common for Type B projects).

**Recovery:**
```bash
# Abort the merge
git merge --abort

# Verify files are back (using your variable)
ls $WEBAPP_DIR/app/app/pages/app_page/

# Try again with correct flags
# For Type A (Direct/Root):
git merge --no-commit --allow-unrelated-histories rioboilerplate-upstream

# For Type B (Subdirectory):
git merge --no-commit --allow-unrelated-histories -X subtree=$WEBAPP_DIR rioboilerplate-upstream
```

**Common mistake for Type B:** Forgetting the `-X subtree=<dir>` flag or using the wrong directory name.

### Issue 2: Merge Already Committed (Can't Abort)

**Symptom:** You ran merge without `--no-commit` and custom files are gone.

**Recovery:**
```bash
# Reset to before merge (assumes merge was the last commit)
git reset --hard HEAD~1

# Verify files are restored
git status
ls $WEBAPP_DIR/app/app/pages/app_page/

# Try again with --no-commit flag (see Issue 1 for correct command)
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

**For Type A (Direct/Root):**
```bash
# View both versions
git show HEAD:requirements.txt > /tmp/yours.txt
git show rioboilerplate-upstream:requirements.txt > /tmp/upstream.txt

# Compare
diff /tmp/yours.txt /tmp/upstream.txt
```

**For Type B (Subdirectory):**
```bash
# View both versions (using variable)
git show HEAD:$WEBAPP_DIR/requirements.txt > /tmp/yours.txt
git show rioboilerplate-upstream:requirements.txt > /tmp/upstream.txt

# Compare
diff /tmp/yours.txt /tmp/upstream.txt
```

**Resolution Strategy (same for both types):**
1. Keep all YOUR custom dependencies
2. Add NEW upstream dependencies
3. Update VERSION numbers for shared dependencies (use upstream versions)

### Issue 5: Application Won't Start After Merge

**Symptom:** `rio run` fails with import errors or runtime exceptions.

**Debugging steps:**

1. **Check imports:**

   **Type A:**
   ```bash
   cd app
   python3 -c "import app"
   ```

   **Type B:**
   ```bash
   cd $WEBAPP_DIR/app
   python3 -c "import app"
   ```

2. **Check for missing dependencies:**

   **Type A:**
   ```bash
   pip install -r requirements.txt
   ```

   **Type B:**
   ```bash
   pip install -r $WEBAPP_DIR/requirements.txt
   ```

3. **Check database schema:**
   ```bash
   # May need to update database if upstream changed schema
   # Check upstream migration notes
   ```

4. **Review merge commit:**

   **Type A:**
   ```bash
   git show HEAD --stat
   git diff HEAD~1 HEAD -- app/app/__init__.py
   ```

   **Type B:**
   ```bash
   git show HEAD --stat
   git diff HEAD~1 HEAD -- $WEBAPP_DIR/app/app/__init__.py
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

**Type A (Direct/Root):**
```bash
# GOOD
git merge --no-commit --allow-unrelated-histories rioboilerplate-upstream

# BAD (auto-commits, harder to verify)
git merge rioboilerplate-upstream
```

**Type B (Subdirectory):**
```bash
# GOOD
git merge --no-commit --allow-unrelated-histories -X subtree=webapp rioboilerplate-upstream

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

**Type A (Direct/Root):**
```bash
git checkout -b merge-upstream-2025-01
git merge --no-commit --allow-unrelated-histories rioboilerplate-upstream
# ... resolve conflicts ...
git commit
git push origin merge-upstream-2025-01
# Create PR, review, then merge to main
```

**Type B (Subdirectory):**
```bash
git checkout -b merge-upstream-2025-01
git merge --no-commit --allow-unrelated-histories -X subtree=$WEBAPP_DIR rioboilerplate-upstream
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

**Type A (Direct/Root):**
```bash
# Make your fix (e.g., restore color scheme)
# Edit the file

# Stage the fix
git add app/app/components/sidebar.py

# Amend the merge commit
git commit --amend --no-edit
```

**Type B (Subdirectory):**
```bash
# Make your fix (e.g., restore color scheme)
# Edit the file

# Stage the fix
git add $WEBAPP_DIR/app/app/components/sidebar.py

# Amend the merge commit
git commit --amend --no-edit
```

### Scenario 2: Need to Fix Multiple Files

**Type A (Direct/Root):**
```bash
# Fix all issues
# Stage all fixes
git add .

# Amend with updated message
git commit --amend
# Edit message in editor if needed
```

**Type B (Subdirectory):**
```bash
# Fix all issues
# Stage all fixes
git add $WEBAPP_DIR/

# Amend with updated message
git commit --amend
# Edit message in editor if needed
```

**WARNING:** Only amend commits that haven't been pushed yet!

---

## Quick Reference Commands

### Setup (Same for Both Types)
```bash
git remote add rioboilerplate https://github.com/azidancorp/RioBoilerplate.git
git fetch rioboilerplate
git checkout -b rioboilerplate-upstream rioboilerplate/main
git push -u origin rioboilerplate-upstream
```

### Update Upstream (Same for Both Types)
```bash
git checkout rioboilerplate-upstream
git pull rioboilerplate main
git push origin rioboilerplate-upstream
git checkout main
```

### Determine Your Structure
```bash
# Check your layout
ls -la

# Set variables for Type A (Direct/Root)
export WEBAPP_DIR="."
export SUBTREE_FLAG=""

# OR set variables for Type B (Subdirectory - replace 'webapp' with your dir)
export WEBAPP_DIR="webapp"
export SUBTREE_FLAG="-X subtree=$WEBAPP_DIR"

# Verify
ls $WEBAPP_DIR/app/app/pages/
```

### Merge Process - Type A (Direct/Root)
```bash
# 1. Ensure clean state
git status

# 2. Merge without committing (NO subtree flag)
git merge --no-commit --allow-unrelated-histories rioboilerplate-upstream

# 3. Verify custom files preserved
ls app/app/pages/app_page/

# 4. Find conflicts
find . -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# 5. Resolve each conflict, then stage
git add path/to/resolved/file

# 6. Verify all resolved
find . -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# 7. Stage everything
git add .

# 8. Commit
git commit

# 9. Test
cd app && rio run

# 10. Push
git push origin main
```

### Merge Process - Type B (Subdirectory)
```bash
# 1. Ensure clean state
git status

# 2. Merge without committing (WITH subtree flag - replace 'webapp')
git merge --no-commit --allow-unrelated-histories -X subtree=webapp rioboilerplate-upstream
# Or using variable:
git merge --no-commit --allow-unrelated-histories $SUBTREE_FLAG rioboilerplate-upstream

# 3. Verify custom files preserved
ls webapp/app/app/pages/app_page/
# Or: ls $WEBAPP_DIR/app/app/pages/app_page/

# 4. Find conflicts
find webapp -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null
# Or: find $WEBAPP_DIR -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# 5. Resolve each conflict, then stage
git add path/to/resolved/file

# 6. Verify all resolved
find webapp -type f -exec grep -l "<<<<<<< HEAD" {} \; 2>/dev/null

# 7. Stage everything
git add webapp/
# Or: git add $WEBAPP_DIR/

# 8. Commit
git commit

# 9. Test
cd $WEBAPP_DIR/app
rio run

# 10. Push
git push origin main
```

### Abort/Recover (Same for Both Types)
```bash
# Abort in-progress merge
git merge --abort

# Undo last commit (not pushed)
git reset --hard HEAD~1

# View file from before merge (adjust path for your structure)
git show HEAD~1:path/to/file
```

---

## Troubleshooting Checklist

Before asking for help, verify:

- [ ] Identified your project structure (Type A or Type B)
- [ ] Used `--no-commit` flag
- [ ] **Type B only:** Specified correct subtree path (`-X subtree=<yourdir>`)
- [ ] **Type A only:** Did NOT use subtree flag (common mistake)
- [ ] Working tree was clean before merge
- [ ] All conflict markers removed
- [ ] Custom files still exist
- [ ] Application runs without errors
- [ ] Staged all changes before committing
- [ ] Tested thoroughly before pushing

---

## Conclusion

Merging upstream updates is a routine maintenance task that becomes easier with practice. The key principles:

1. **Identify structure:** Determine if you have Type A (Direct/Root) or Type B (Subdirectory)
2. **Prepare:** Clean state, backup, review changes
3. **Merge carefully:** Use `--no-commit` and correct flags for your structure
   - Type A: NO subtree flag
   - Type B: WITH `-X subtree=<yourdir>`
4. **Verify thoroughly:** Check custom work preserved
5. **Resolve methodically:** One conflict at a time
6. **Test extensively:** Before pushing to production

Keep this guide handy for future merges. Each time you merge, you'll get faster and more confident with the process.

**Key Takeaway:** The most common mistake is using the wrong merge command for your project structure. Always verify your structure type before running the merge!

---

**Last Updated:** 2025-11-11
**Based on:** Multiple successful merges covering both Type A and Type B structures
**Verified with:** Git 2.x, RioBoilerplate template in various project configurations
