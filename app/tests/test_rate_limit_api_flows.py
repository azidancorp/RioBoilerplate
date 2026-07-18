from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import fastapi_app
from app.api import example as example_api
from app.api.auth_dependencies import get_persistence
from app.config import config
from app.persistence import Persistence


@pytest.fixture
def api_test_setup(tmp_path: Path):
    db_path = tmp_path / "api-rate-limits.db"
    setup_persistence = Persistence(db_path=db_path)

    async def override_get_persistence():
        db = Persistence(db_path=db_path)
        try:
            yield db
        finally:
            db.close()

    fastapi_app.dependency_overrides[get_persistence] = override_get_persistence
    client = TestClient(fastapi_app)
    try:
        yield client, setup_persistence
    finally:
        fastapi_app.dependency_overrides.clear()
        setup_persistence.close()
        client.close()


@pytest.fixture(autouse=True)
def rate_limit_config():
    original = {
        "RATE_LIMIT_CONTACT_IP_ATTEMPTS": config.RATE_LIMIT_CONTACT_IP_ATTEMPTS,
        "RATE_LIMIT_API_AUTH_IP_ATTEMPTS": config.RATE_LIMIT_API_AUTH_IP_ATTEMPTS,
    }
    config.RATE_LIMIT_CONTACT_IP_ATTEMPTS = 2
    config.RATE_LIMIT_API_AUTH_IP_ATTEMPTS = 2
    yield
    for key, value in original.items():
        setattr(config, key, value)


def test_contact_api_rate_limits_and_returns_retry_after(
    api_test_setup,
    monkeypatch: pytest.MonkeyPatch,
):
    client, _ = api_test_setup
    submissions: list[dict] = []

    def fake_create_contact_submission(*, name: str, email: str, message: str):
        submissions.append({"name": name, "email": email, "message": message})
        return {"id": len(submissions)}

    monkeypatch.setattr(example_api, "create_contact_submission", fake_create_contact_submission)

    payload = {
        "name": "Jordan",
        "email": "jordan@example.com",
        "message": "Need some help with the product.",
    }

    for _ in range(config.RATE_LIMIT_CONTACT_IP_ATTEMPTS):
        response = client.post("/api/contact", json=payload)
        assert response.status_code == 201

    blocked = client.post("/api/contact", json=payload)

    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert "Too many contact form submissions." in blocked.json()["detail"]
    assert len(submissions) == config.RATE_LIMIT_CONTACT_IP_ATTEMPTS


@pytest.mark.parametrize(
    ("headers", "expected_detail"),
    (
        ({}, "Missing authentication credentials"),
        (
            {"Authorization": "Basic invalid-token"},
            "Invalid authentication credentials format. Expected: 'Bearer <token>'",
        ),
        (
            {"Authorization": "Bearer invalid token"},
            "Invalid authentication credentials format. Expected: 'Bearer <token>'",
        ),
        (
            {"Authorization": "Bearer invalid-token"},
            "Invalid or expired authentication token",
        ),
    ),
)
def test_authentication_failures_are_rate_limited_by_ip(
    api_test_setup,
    headers,
    expected_detail,
):
    client, _ = api_test_setup

    for _ in range(config.RATE_LIMIT_API_AUTH_IP_ATTEMPTS):
        response = client.get(
            "/api/currency/balance",
            headers=headers,
        )
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.json()["detail"] == expected_detail

    blocked = client.get(
        "/api/currency/balance",
        headers=headers,
    )

    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert "Too many authentication attempts." in blocked.json()["detail"]


@pytest.mark.parametrize(
    ("authorization", "expected_detail"),
    (
        (None, "Missing authentication credentials"),
        ("", "Missing authentication credentials"),
        (
            "Basic token",
            "Invalid authentication credentials format. Expected: 'Bearer <token>'",
        ),
        (
            "Bearer",
            "Invalid authentication credentials format. Expected: 'Bearer <token>'",
        ),
        (
            "Bearer\tinvalid-token",
            "Invalid authentication credentials format. Expected: 'Bearer <token>'",
        ),
        (
            "Bearer invalid token",
            "Invalid authentication credentials format. Expected: 'Bearer <token>'",
        ),
        ("bearer invalid-token", "Invalid or expired authentication token"),
    ),
)
def test_bearer_header_parsing_keeps_custom_failure_contract(
    api_test_setup,
    authorization,
    expected_detail,
):
    client, _ = api_test_setup
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.get("/api/currency/balance", headers=headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["detail"] == expected_detail
