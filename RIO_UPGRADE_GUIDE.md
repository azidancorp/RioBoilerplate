# Upgrading `rio-ui` 0.12.0 → 0.12.2

Scope: the patch bump of the pinned `rio-ui` from `0.12.0` to `0.12.2` in `requirements.txt`. For a project derived from this boilerplate that is catching up to this pin.

This bump was validated in the boilerplate (full suite: **210 passed**, no code changes required). It is a patch bump with **no documented breaking API changes** — your only job is to confirm your *own* additions on top of the boilerplate still work, by running the regression suite below.

## What changed (0.12.0 → 0.12.2)

Internal reworks, bugfixes, and raised transitive ceilings:

- **Refresh system:** components depending on session attributes (e.g. `active_page_url`) now auto-rebuild when those change; state changes rebuild immediately. This *helps* the boilerplate's responsive/sidebar/login usage rather than breaking it.
- **`rio_internal` rework:** `Session._attachments` is now a `SessionAttachments` wrapper, not a plain dict.
- **Bugfixes:** `Text` underline/strikethrough; Tabs update / debug-mode crash; Tables can scroll; new `backend` parameter.
- **Security hardening (internal, not on boilerplate call paths):** URL schemes restricted to http/https; icon-registry path safety.
- **Transitive ceilings raised** (none pinned here, so they float up): fastapi `<0.137`, uvicorn `<0.49`, plus polars / playwright / tomlkit / isort / hatchling.
- **API:** added `rio.HttpOnly`; deprecated the `CursorStyle` enum in favor of string literals (unused here).

## Boilerplate touchpoints — verified present in 0.12.2

| Touchpoint | Location | Status |
|---|---|---|
| `rio.global_state` (`currently_building_component/session`, `key_to_component`) | `app/tests/test_admin_user_lifecycle.py:8` | ✅ present |
| Session attrs: `window_width`, `active_page_instances`, `active_page_url` | `responsive.py:44`, `sidebar.py:26`, `login.py:1381` | ✅ present |
| `_FakeSession` internals: `_attachments`, `client_ip`, `user_agent`, `http_headers`, `running_as_website`, `window_width`, `_date_format_string` | `app/tests/test_admin_user_lifecycle.py` | ✅ present by name |
| `rio.UserSettings` subclass + `default_attachments` + `session[UserSettings]` | `data_models.py:19`, `__init__.py:111`, `session_validation.py:35`, `login.py:90` | ✅ unchanged |

The only subtle change is `Session._attachments` (dict → `SessionAttachments`). The test `_FakeSession` mimics it as a plain dict but is standalone (doesn't subclass `rio.Session`) and supplies its own item protocol, so it is unaffected — confirmed by the admin lifecycle test passing.

## Upgrade steps

1. Set `rio-ui==0.12.2` in `requirements.txt` and reinstall (`pip install -r requirements.txt`).
2. Optionally capture transitive bumps: `pip freeze > before.txt` (pre-bump), again after, then `diff`.
3. Run the regression suite against your tree; stop on first failure:

```bash
pytest app/tests/test_smoke_pages.py -x            # component constructor / build() regressions
pytest app/tests/test_admin_user_lifecycle.py -x   # exercises rio.global_state + _FakeSession
pytest app/tests/test_two_factor_verification.py -x
pytest app/tests/test_currency_reconciliation.py -x
pytest                                             # full suite
cd app && timeout 5 rio run --port 8XXX            # boot check — must exit cleanly
```

4. Before deployment, run the release-mode boot check (occasionally surfaces issues hidden in dev):

```bash
cd app && rio run --port 8000 --release
```

If your custom code uses `rio.Color.hex` or relied on RGB color mixing, note those changed back in **0.11** (hex is 6-digit; colors use Oklab) — already absorbed by the boilerplate, but check your own additions if you skipped that range.

---

**Last Updated:** 2026-06-22
