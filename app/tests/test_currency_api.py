import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pyotp
from fastapi.testclient import TestClient

from app import fastapi_app
from app.api import currency as currency_api
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
        "PRIMARY_CURRENCY_DECIMAL_PLACES": config.PRIMARY_CURRENCY_DECIMAL_PLACES,
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


def test_api_rejects_session_past_its_absolute_lifetime(
    api_test_setup,
    monkeypatch,
):
    client, persistence = api_test_setup
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0
    monkeypatch.setattr(config, "SESSION_ABSOLUTE_MAX_DAYS", 1)
    user, token = asyncio.run(
        _create_user_with_session(persistence, "absolute-api-session@example.com")
    )
    now = datetime.now(timezone.utc)
    persistence.conn.execute(
        """
        UPDATE user_sessions
        SET created_at = ?, valid_until = ?
        WHERE id = ?
        """,
        (
            (now - timedelta(days=2)).timestamp(),
            (now + timedelta(days=1)).timestamp(),
            persistence._hash_one_time_token(token),
        ),
    )
    persistence.conn.commit()

    read_response = client.get(
        "/api/currency/balance",
        headers={"Authorization": f"Bearer {token}"},
    )
    mutation_response = client.post(
        "/api/currency/adjust",
        json={
            "target_user_id": str(user.id),
            "amount": "25",
            "reason": "must not use absolute-expired session",
            "step_up": {"password": "secret"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert read_response.status_code == 401
    assert mutation_response.status_code == 401
    assert asyncio.run(
        persistence.get_user_by_id(user.id)
    ).primary_currency_balance == 0


def test_adjust_endpoint_rejects_amount_that_rounds_to_zero(api_test_setup):
    client, persistence = api_test_setup
    config.PRIMARY_CURRENCY_INITIAL_BALANCE = 0
    config.PRIMARY_CURRENCY_DECIMAL_PLACES = 0
    user, token = asyncio.run(
        _create_user_with_session(persistence, "zero-rounding-api@example.com")
    )
    before_timestamp = persistence.conn.execute(
        "SELECT primary_currency_updated_at FROM users WHERE id = ?",
        (str(user.id),),
    ).fetchone()[0]

    response = client.post(
        "/api/currency/adjust",
        json={
            "target_user_id": str(user.id),
            "amount": "0.4",
            "reason": "would round to zero",
            "step_up": {"password": "secret"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422
    assert "minor currency unit" in response.text
    refreshed = asyncio.run(persistence.get_user_by_id(user.id))
    assert refreshed.primary_currency_balance == 0
    assert persistence.conn.execute(
        "SELECT primary_currency_updated_at FROM users WHERE id = ?",
        (str(user.id),),
    ).fetchone()[0] == before_timestamp
    assert persistence.conn.execute(
        "SELECT COUNT(*) FROM user_currency_ledger WHERE user_id = ?",
        (str(user.id),),
    ).fetchone()[0] == 0
    assert persistence.conn.execute(
        "SELECT COUNT(*) FROM admin_audit_log WHERE target_user_id = ?",
        (str(user.id),),
    ).fetchone()[0] == 0


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


@pytest.mark.parametrize(
    ("route", "payload", "method_name"),
    [
        (
            "/api/currency/adjust",
            {"amount": "25", "reason": "denied adjustment"},
            "admin_adjust_currency_balance",
        ),
        (
            "/api/currency/set",
            {"balance": "25", "reason": "denied balance set"},
            "admin_set_currency_balance",
        ),
    ],
)
def test_currency_mutation_maps_transaction_authorization_denial_to_403(
    api_test_setup,
    monkeypatch,
    route,
    payload,
    method_name,
):
    client, persistence = api_test_setup
    user, token = asyncio.run(
        _create_user_with_session(persistence, "transaction-denial@example.com")
    )

    async def deny_mutation(*args, **kwargs):
        raise PermissionError("Administrator authorization changed. Please try again.")

    monkeypatch.setattr(Persistence, method_name, deny_mutation)

    response = client.post(
        route,
        json={
            "target_user_id": str(user.id),
            **payload,
            "step_up": {"password": "secret"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Administrator authorization changed. Please try again."
    )


@pytest.mark.parametrize("session_state", ["revoked", "expired"])
@pytest.mark.parametrize(
    ("route", "payload", "audit_action"),
    [
        (
            "/api/currency/adjust",
            {"amount": "25", "reason": "stale-session adjustment"},
            "currency_adjust",
        ),
        (
            "/api/currency/set",
            {"balance": "25", "reason": "stale-session balance set"},
            "currency_set",
        ),
    ],
)
def test_currency_mutation_maps_late_session_loss_to_401(
    api_test_setup,
    monkeypatch,
    session_state,
    route,
    payload,
    audit_action,
):
    client, persistence = api_test_setup
    user, token = asyncio.run(
        _create_user_with_session(persistence, "late-session-loss@example.com")
    )
    balance_before = user.primary_currency_balance

    async def lose_session_before_write(
        request_payload,
        current_session,
        current_user,
        db,
    ):
        if session_state == "revoked":
            await db.invalidate_session(current_session.id)
        else:
            db.conn.execute(
                "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
                (db._hash_one_time_token(current_session.id),),
            )
            db.conn.commit()

    monkeypatch.setattr(
        currency_api,
        "_require_step_up",
        lose_session_before_write,
    )

    response = client.post(
        route,
        json={
            "target_user_id": str(user.id),
            **payload,
            "step_up": {"password": "secret"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["detail"] == "Your admin session is no longer valid."
    refreshed = asyncio.run(persistence.get_user_by_id(user.id))
    assert refreshed.primary_currency_balance == balance_before
    assert persistence.list_admin_actions(
        action=audit_action,
        target_user_id=user.id,
    ) == []


@pytest.mark.parametrize(
    ("route", "payload", "method_name"),
    [
        (
            "/api/currency/adjust",
            {"amount": "25", "reason": "missing target adjustment"},
            "admin_adjust_currency_balance",
        ),
        (
            "/api/currency/set",
            {"balance": "25", "reason": "missing target balance set"},
            "admin_set_currency_balance",
        ),
    ],
)
def test_currency_mutation_maps_transaction_target_disappearance_to_404(
    api_test_setup,
    monkeypatch,
    route,
    payload,
    method_name,
):
    client, persistence = api_test_setup
    user, token = asyncio.run(
        _create_user_with_session(persistence, "transaction-target-missing@example.com")
    )

    async def lose_target(*args, **kwargs):
        raise KeyError("Target user not found.")

    monkeypatch.setattr(Persistence, method_name, lose_target)

    response = client.post(
        route,
        json={
            "target_user_id": str(user.id),
            **payload,
            "step_up": {"password": "secret"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Target user not found."


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
