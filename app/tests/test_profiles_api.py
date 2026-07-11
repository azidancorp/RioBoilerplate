import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import fastapi_app
from app.api.auth_dependencies import get_persistence
from app.data_models import AppUser
from app.persistence import Persistence


@pytest.fixture
def profile_api_setup(tmp_path: Path):
    db_path = tmp_path / "profiles-api.db"
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


async def _create_user_with_session(
    persistence: Persistence,
    *,
    email: str,
    role: str,
) -> tuple[AppUser, str]:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password="secret",
    )
    user.role = role
    await persistence._create_user_unchecked(user)
    session = await persistence.create_session(user.id)
    return await persistence.get_user_by_id(user.id), session.id


def test_user_cannot_read_another_users_private_profile(profile_api_setup):
    client, persistence = profile_api_setup

    async def scenario():
        reader, reader_token = await _create_user_with_session(
            persistence,
            email="profile-reader@example.com",
            role="user",
        )
        target, _ = await _create_user_with_session(
            persistence,
            email="private-profile@example.com",
            role="user",
        )
        await persistence.update_profile(
            str(target.id),
            phone="+44 7700 900123",
            address="Private address",
            bio="Private biography",
        )
        return reader, reader_token, target

    reader, reader_token, target = asyncio.run(scenario())
    assert reader.id != target.id

    response = client.get(
        f"/api/profiles/{target.id}",
        headers={"Authorization": f"Bearer {reader_token}"},
    )

    assert response.status_code == 403
    assert "Private address" not in response.text
    assert "+44 7700 900123" not in response.text


def test_user_can_read_own_private_profile(profile_api_setup):
    client, persistence = profile_api_setup
    user, token = asyncio.run(
        _create_user_with_session(
            persistence,
            email="own-profile@example.com",
            role="user",
        )
    )

    response = client.get(
        f"/api/profiles/{user.id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == str(user.id)
    assert response.json()["email"] == user.email


def test_admin_can_read_a_users_private_profile(profile_api_setup):
    client, persistence = profile_api_setup

    async def scenario():
        _, admin_token = await _create_user_with_session(
            persistence,
            email="profile-admin@example.com",
            role="admin",
        )
        target, _ = await _create_user_with_session(
            persistence,
            email="admin-readable-profile@example.com",
            role="user",
        )
        return admin_token, target

    admin_token, target = asyncio.run(scenario())

    response = client.get(
        f"/api/profiles/{target.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == str(target.id)
