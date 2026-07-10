import asyncio
from pathlib import Path

import pytest
import pyotp
from fastapi.testclient import TestClient

from app import fastapi_app
from app.api.auth_dependencies import get_persistence
from app.config import config
from app.data_models import AppUser
from app.persistence import Persistence


@pytest.fixture
def api_test_setup(tmp_path: Path):
    db_path = tmp_path / "api.db"
    # Setup-only instance: used in the main test thread for creating users/sessions
    setup_persistence = Persistence(db_path=db_path)

    # Per-request instance: mimics production get_persistence() which creates
    # a fresh Persistence per request inside the ASGI worker thread
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
    user.role = "root"
    await persistence._create_user_unchecked(user)
    session = await persistence.create_session(user.id)
    return await persistence.get_user_by_id(user.id), session.id


async def _create_user_with_role(
    persistence: Persistence,
    email: str,
    role: str,
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password="secret")
    await persistence._create_user_unchecked(user)
    persistence.conn.execute(
        "UPDATE users SET role = ?, is_verified = 1 WHERE id = ?",
        (role, str(user.id)),
    )
    persistence.conn.commit()
    return await persistence.get_user_by_id(user.id)


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
            "step_up": {"password": "secret"},
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


def test_adjust_endpoint_requires_actor_step_up(api_test_setup):
    client, persistence = api_test_setup
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    user, token = asyncio.run(_create_user_with_session(persistence, "stepup@example.com"))

    missing_response = client.post(
        "/api/currency/adjust",
        json={
            "target_user_id": str(user.id),
            "amount": "25",
            "reason": "missing step-up",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert missing_response.status_code == 422

    wrong_response = client.post(
        "/api/currency/adjust",
        json={
            "target_user_id": str(user.id),
            "amount": "25",
            "reason": "wrong step-up",
            "step_up": {"password": "wrong"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert wrong_response.status_code == 403

    balance_after = client.get(
        "/api/currency/balance",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert balance_after.status_code == 200
    assert balance_after.json()["balance_minor"] == 0


def test_adjust_endpoint_enforces_target_role_hierarchy(api_test_setup):
    client, persistence = api_test_setup
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        root = await _create_user_with_role(persistence, "root-currency-api@example.com", "root")
        admin = await _create_user_with_role(persistence, "admin-currency-api@example.com", "admin")
        admin_session = await persistence.create_session(admin.id)
        return root, admin_session.id

    root, admin_token = asyncio.run(scenario())

    response = client.post(
        "/api/currency/adjust",
        json={
            "target_user_id": str(root.id),
            "amount": "25",
            "reason": "admin should not update root",
            "step_up": {"password": "secret"},
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "You do not have permission to update balances for users with role root."
    )
    root_after = asyncio.run(persistence.get_user_by_id(root.id))
    assert root_after.primary_currency_balance == 0


def test_ledger_endpoint_enforces_target_role_hierarchy(api_test_setup):
    client, persistence = api_test_setup

    async def scenario():
        root = await _create_user_with_role(persistence, "root-ledger-api@example.com", "root")
        admin = await _create_user_with_role(persistence, "admin-ledger-api@example.com", "admin")
        admin_session = await persistence.create_session(admin.id)
        await persistence.adjust_currency_balance(root.id, 10, reason="root private ledger")
        return root, admin_session.id

    root, admin_token = asyncio.run(scenario())

    response = client.get(
        f"/api/currency/ledger?user_id={root.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "You do not have permission to view currency ledger entries for users with role root."
    )


def test_set_endpoint_requires_actor_2fa_when_enabled(api_test_setup):
    client, persistence = api_test_setup
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    user, token = asyncio.run(_create_user_with_session(persistence, "totp-api@example.com"))
    secret = pyotp.random_base32()
    persistence.set_2fa_secret(user.id, secret)

    missing_2fa = client.post(
        "/api/currency/set",
        json={
            "target_user_id": str(user.id),
            "balance": "40",
            "reason": "missing 2fa",
            "step_up": {"password": "secret"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert missing_2fa.status_code == 403
    assert missing_2fa.json()["detail"] == "2FA code is required"

    ok_response = client.post(
        "/api/currency/set",
        json={
            "target_user_id": str(user.id),
            "balance": "40",
            "reason": "with 2fa",
            "step_up": {
                "password": "secret",
                "two_factor_code": pyotp.TOTP(secret).now(),
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ok_response.status_code == 201, ok_response.text
    assert ok_response.json()["balance_after_minor"] == 40


def test_set_endpoint_allows_oauth_actor_with_2fa_and_no_password(api_test_setup):
    client, persistence = api_test_setup
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0

    async def scenario():
        user = AppUser.create_new_user_with_default_settings(
            email="oauth-totp-api@example.com",
            password="unused-secret",
        )
        user.auth_provider = "google"
        user.auth_provider_id = "google-oauth-totp-api"
        user.role = "root"
        await persistence._create_user_unchecked(user)
        user = await persistence.get_user_by_id(user.id)
        session = await persistence.create_session(user.id)
        return user, session.id

    user, token = asyncio.run(scenario())
    secret = pyotp.random_base32()
    persistence.set_2fa_secret(user.id, secret)

    ok_response = client.post(
        "/api/currency/set",
        json={
            "target_user_id": str(user.id),
            "balance": "55",
            "reason": "oauth with 2fa",
            "step_up": {
                "two_factor_code": pyotp.TOTP(secret).now(),
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert ok_response.status_code == 201, ok_response.text
    assert ok_response.json()["balance_after_minor"] == 55


def test_inactive_user_bearer_token_is_rejected(api_test_setup):
    client, persistence = api_test_setup

    async def scenario():
        user = AppUser.create_new_user_with_default_settings(
            email="inactive-api-user@example.com",
            password="secret",
        )
        await persistence._create_user_unchecked(user)
        user = await persistence.get_user_by_id(user.id)
        session = await persistence.create_session(user.id)
        persistence.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(user.id),),
        )
        persistence.conn.commit()
        return session.id

    token = asyncio.run(scenario())

    response = client.get(
        "/api/currency/balance",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["detail"] == "User account is inactive"
