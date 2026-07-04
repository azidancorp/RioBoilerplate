import sqlite3

from fastapi.testclient import TestClient

import app as app_module
from app.api import health as health_module
from app.persistence import Persistence


def _client() -> TestClient:
    return TestClient(app_module.fastapi_app, raise_server_exceptions=False)


def _table_names(db_path):
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    return {row[0] for row in rows}


def test_health_returns_ok_for_initialized_temp_database(tmp_path, monkeypatch):
    db_path = tmp_path / "healthy.db"
    persistence = Persistence(db_path=db_path)
    persistence.close()
    monkeypatch.setattr(health_module, "HEALTH_DB_PATH", db_path)

    client = _client()
    try:
        response = client.get("/api/health")
    finally:
        client.close()

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "checks": {
            "app": "ok",
            "database": "ok",
            "schema": "ok",
        },
    }


def test_health_returns_503_for_missing_database_without_creating_it(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "missing.db"
    monkeypatch.setattr(health_module, "HEALTH_DB_PATH", db_path)

    client = _client()
    try:
        response = client.get("/api/health")
    finally:
        client.close()

    assert response.status_code == 503
    assert response.json() == {
        "status": "unhealthy",
        "checks": {
            "app": "ok",
            "database": "failed",
            "schema": "skipped",
        },
        "code": "db_missing",
    }
    assert not db_path.exists()


def test_health_returns_503_for_partial_schema_without_creating_tables(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "partial.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY)")

    before_tables = _table_names(db_path)
    monkeypatch.setattr(health_module, "HEALTH_DB_PATH", db_path)

    client = _client()
    try:
        response = client.get("/api/health")
    finally:
        client.close()

    assert response.status_code == 503
    assert response.json() == {
        "status": "unhealthy",
        "checks": {
            "app": "ok",
            "database": "ok",
            "schema": "failed",
        },
        "code": "schema_missing",
    }
    assert _table_names(db_path) == before_tables == {"users"}


def test_health_returns_503_for_corrupt_database(tmp_path, monkeypatch):
    db_path = tmp_path / "corrupt.db"
    db_path.write_text("not a sqlite database", encoding="utf-8")
    monkeypatch.setattr(health_module, "HEALTH_DB_PATH", db_path)

    client = _client()
    try:
        response = client.get("/api/health")
    finally:
        client.close()

    assert response.status_code == 503
    assert response.json()["code"] == "db_corrupt"
    assert response.json()["checks"] == {
        "app": "ok",
        "database": "failed",
        "schema": "skipped",
    }


def test_health_response_does_not_expose_paths_or_raw_errors(tmp_path, monkeypatch):
    db_path = tmp_path / "corrupt-secret-path.db"
    db_path.write_text("not a sqlite database", encoding="utf-8")
    monkeypatch.setattr(health_module, "HEALTH_DB_PATH", db_path)
    monkeypatch.setenv("SESSION_SECRET_KEY", "secret-health-test-value")

    client = _client()
    try:
        response = client.get("/api/health")
    finally:
        client.close()

    body = response.text
    lower_body = body.lower()
    assert response.status_code == 503
    assert str(db_path) not in body
    assert "secret-health-test-value" not in body
    assert "file is not a database" not in lower_body
    assert "traceback" not in lower_body


def test_health_request_does_not_instantiate_persistence(tmp_path, monkeypatch):
    db_path = tmp_path / "healthy.db"
    persistence = Persistence(db_path=db_path)
    persistence.close()
    monkeypatch.setattr(health_module, "HEALTH_DB_PATH", db_path)

    calls = []

    def fail_if_called(self, *args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("Health check must not instantiate Persistence")

    monkeypatch.setattr(Persistence, "__init__", fail_if_called)

    client = _client()
    try:
        response = client.get("/api/health")
    finally:
        client.close()

    assert response.status_code == 200
    assert calls == []


def test_health_does_not_rewrite_legacy_recovery_codes_table(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy-recovery-codes.db"
    with sqlite3.connect(db_path) as conn:
        table_names = health_module.REQUIRED_TABLES - {"two_factor_recovery_codes"}
        for table_name in table_names:
            conn.execute(f"CREATE TABLE {table_name} (id TEXT PRIMARY KEY)")
        conn.execute(
            """
            CREATE TABLE two_factor_recovery_codes (
                id INTEGER PRIMARY KEY,
                user_id TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                salt BLOB NOT NULL,
                created_at REAL NOT NULL,
                used_at REAL
            )
            """
        )

    monkeypatch.setattr(health_module, "HEALTH_DB_PATH", db_path)

    client = _client()
    try:
        response = client.get("/api/health")
    finally:
        client.close()

    assert response.status_code == 200
    with sqlite3.connect(db_path) as conn:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(two_factor_recovery_codes)")
        }
    assert "salt" in columns
    assert "valid_until" not in columns
