import asyncio
import concurrent.futures
import sqlite3
from collections import Counter
from pathlib import Path
from threading import Barrier

from app.data_models import AppUser
from app.permissions import get_default_role, get_first_user_role
from app.persistence import Persistence


def test_concurrent_first_user_creation_assigns_one_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "bootstrap-race.db"
    Persistence(db_path=db_path).close()

    thread_count = 2
    start_barrier = Barrier(thread_count)
    count_barrier = Barrier(thread_count)
    real_connect = sqlite3.connect

    class RaceCursor(sqlite3.Cursor):
        def execute(self, sql, parameters=(), /):
            normalized_sql = " ".join(str(sql).split()).upper()
            self._after_user_count = normalized_sql == "SELECT COUNT(*) FROM USERS"
            return super().execute(sql, parameters)

        def fetchone(self):
            row = super().fetchone()
            if (
                getattr(self, "_after_user_count", False)
                and row
                and row[0] == 0
                and not self.connection.in_transaction
            ):
                count_barrier.wait(timeout=10)
            self._after_user_count = False
            return row

    class RaceConnection(sqlite3.Connection):
        def cursor(self, *args, **kwargs):
            kwargs.setdefault("factory", RaceCursor)
            return super().cursor(*args, **kwargs)

    def patched_connect(*args, **kwargs):
        kwargs.setdefault("factory", RaceConnection)
        kwargs.setdefault("timeout", 30)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", patched_connect)

    def create_user(index: int) -> Exception | None:
        persistence = Persistence(db_path=db_path)
        try:
            user = AppUser.create_new_user_with_default_settings(
                email=f"bootstrap-race-{index}@example.com",
                password="password",
            )
            start_barrier.wait(timeout=10)
            asyncio.run(persistence.create_user(user))
            return None
        except Exception as exc:
            return exc
        finally:
            persistence.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        errors = [
            error
            for error in executor.map(create_user, range(thread_count))
            if error is not None
        ]

    assert errors == []

    with real_connect(db_path) as conn:
        roles = [
            row[0]
            for row in conn.execute("SELECT role FROM users ORDER BY email")
        ]

    role_counts = Counter(roles)
    assert role_counts[get_first_user_role()] == 1
    assert role_counts[get_default_role()] == thread_count - 1
