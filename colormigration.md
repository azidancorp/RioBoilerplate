  # 🎨 Rio 0.10.x → 0.12.x Color Migration Guide

## Root Cause

Rio 0.11+ uses Oklab color space internally instead of RGB. This changes:

| Aspect | Old (0.10.x) | New (0.11+) |
|--------|--------------|-------------|
| `.red`, `.green`, `.blue` | Return sRGB values | Return linear RGB values |
| `from_rgb()` | Assumes sRGB input | Assumes linear RGB input |
| `from_hsv()` output | Matches HSV brightness | Oklab adjusts perceived brightness |

---

## Required Changes

### 1. theme.py - Color Helper Functions

**BEFORE:**

```python
def shade_color(base_color: rio.Color, factor: float) -> rio.Color:
    r, g, b = base_color.red, base_color.green, base_color.blue  # WRONG
    # ... manipulation ...
    return rio.Color.from_rgb(r, g, b, opacity)  # Missing srgb=True
```

**AFTER:**

```python
def shade_color(base_color: rio.Color, factor: float) -> rio.Color:
    r, g, b = base_color.srgb  # CORRECT - use srgb property
    # ... manipulation ...
    return rio.Color.from_rgb(r, g, b, opacity, srgb=True)  # Add srgb=True
```

### 2. Dark Theme Colors - Lower HSV Values

Oklab produces brighter colors from the same HSV values. Lower the value parameter:

**BEFORE:**

```python
BACKGROUND_COLOR_DARK = rio.Color.from_hsv(0.75, 0.9, 0.15)  # Too bright now
```

**AFTER:**

```python
BACKGROUND_COLOR_DARK = rio.Color.from_hsv(0.75, 0.9, 0.02)  # Much darker
```

> **Rule of thumb:** Divide your old HSV value by ~5-7 for similar perceived brightness.

### 3. All from_rgb() Calls - Add srgb=True

**Files to check:** Any file using `Color.from_rgb()`

**BEFORE:**

```python
rio.Color.from_rgb(0, 1, 0)        # Green
rio.Color.from_rgb(1, 0, 0)        # Red
rio.Color.from_rgb(1, 0.6, 0)      # Orange
rio.Color.from_rgb(red, green, 0)  # Dynamic
```

**AFTER:**

```python
rio.Color.from_rgb(0, 1, 0, srgb=True)
rio.Color.from_rgb(1, 0, 0, srgb=True)
rio.Color.from_rgb(1, 0.6, 0, srgb=True)
rio.Color.from_rgb(red, green, 0, srgb=True)
```

### 4. Theme Selection (Optional)

If you only want dark theme (not system-dependent):

**BEFORE:**

```python
app = rio.App(
    theme=(theme.LIGHT_THEME, theme.DARK_THEME),  # Both themes
)
```

**AFTER:**

```python
app = rio.App(
    theme=theme.DARK_THEME,  # Force dark only
)
```

---

## File-by-File Checklist

| File | Changes Needed |
|------|----------------|
| `app/theme.py` | Fix `shade_color()` to use `.srgb` and `srgb=True`; lower HSV values for dark colors |
| `app/__init__.py` | Optional: change to single theme |
| `app/scripts/utils.py` | Add `srgb=True` to `from_rgb()` in `get_password_strength_color()` |
| `app/pages/login.py` | Add `srgb=True` to all `from_rgb()` calls |
| `app/pages/settings.py` | Add `srgb=True` to all `from_rgb()` calls |
| Any other component files | Search for `from_rgb` and add `srgb=True` |

---

## Quick Fix Script

Run this to find all files needing changes:

```bash
grep -r "from_rgb" --include="*.py" . | grep -v "srgb=True"
grep -r "\.red\|\.green\|\.blue" --include="*.py" . | grep -v "\.srgb"
```

---

## Summary

The main fixes are:

1. `.srgb` instead of `.red/.green/.blue` when manipulating colors
2. `srgb=True` in all `from_rgb()` calls
3. Lower HSV values (especially `value`) for dark themes due to Oklab brightness perception