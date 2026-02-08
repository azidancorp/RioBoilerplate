import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import fastapi_app
from app.api.auth_dependencies import get_persistence
from app.config import config
from app.data_models import AppUser
from app.persistence import Persistence


@pytest.fixture
def api_test_setup(tmp_path: Path):
    db_path = tmp_path / "api.db"

    async def override_get_persistence():
        # TestClient runs the ASGI app in a different thread. Use a fresh
        # Persistence (and sqlite3.Connection) in that thread while pointing at
        # the same database file.
        db = Persistence(db_path=db_path)
        try:
            yield db
        finally:
            db.close()

    fastapi_app.dependency_overrides[get_persistence] = override_get_persistence
    client = TestClient(fastapi_app)
    persistence = Persistence(db_path=db_path)
    try:
        yield client, persistence
    finally:
        fastapi_app.dependency_overrides.clear()
        persistence.close()
        client.close()


@pytest.fixture(autouse=True)
def restore_currency_config():
    original = {
        "PRIMARY_CURRENCY_INITIAL_BALANCE": config.PRIMARY_CURRENCY_INITIAL_BALANCE,
        "PRIMARY_CURRENCY_ALLOW_NEGATIVE": config.PRIMARY_CURRENCY_ALLOW_NEGATIVE,
    }
    yield
    for key, value in original.items():
        setattr(config, key, value)


async def _create_user_with_session(persistence: Persistence, email: str) -> tuple[AppUser, str]:
    user = AppUser.create_new_user_with_default_settings(email=email, password="secret")
    await persistence.create_user(user)
    session = await persistence.create_session(user.id)
    return await persistence.get_user_by_id(user.id), session.id


def test_balance_and_adjust_endpoint(api_test_setup):
    client, persistence = api_test_setup
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    user, token = asyncio.run(_create_user_with_session(persistence, "api@example.com"))

    response = client.get(
        "/api/currency/balance",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["balance_minor"] == 0

    adjust_response = client.post(
        "/api/currency/adjust",
        json={
            "target_user_id": str(user.id),
            "amount": "25",
            "reason": "api test",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert adjust_response.status_code == 201, adjust_response.text
    payload = adjust_response.json()
    assert payload["balance_after_minor"] == 25

    response_after = client.get(
        "/api/currency/balance",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response_after.status_code == 200
    data_after = response_after.json()
    assert data_after["balance_minor"] == 25
