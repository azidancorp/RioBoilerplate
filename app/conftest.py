"""Pytest bootstrap for execution from the outer app/ directory."""

import sqlite3
import sys
from pathlib import Path


OUTER_APP_DIR = Path(__file__).resolve().parent

if str(OUTER_APP_DIR) not in sys.path:
    sys.path.insert(0, str(OUTER_APP_DIR))


DEFAULT_APP_DB_PATH = (OUTER_APP_DIR / "app" / "data" / "app.db").resolve()
_original_sqlite_connect = sqlite3.connect


def _guard_default_app_db(database, *args, **kwargs):
    try:
        database_path = Path(database).resolve()
    except TypeError:
        database_path = None

    if database_path == DEFAULT_APP_DB_PATH:
        raise AssertionError(
            "Tests must not open the default local database at "
            f"{DEFAULT_APP_DB_PATH}. Use a tmp_path-backed db_path instead."
        )

    return _original_sqlite_connect(database, *args, **kwargs)


sqlite3.connect = _guard_default_app_db
