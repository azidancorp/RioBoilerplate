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


def test_admin_cannot_read_a_root_private_profile(profile_api_setup):
    client, persistence = profile_api_setup

    async def scenario():
        _, admin_token = await _create_user_with_session(
            persistence,
            email="profile-read-hierarchy-admin@example.com",
            role="admin",
        )
        root, _ = await _create_user_with_session(
            persistence,
            email="private-root-profile@example.com",
            role="root",
        )
        await persistence.update_profile(
            str(root.id),
            address="Root-only private address",
        )
        return admin_token, root

    admin_token, root = asyncio.run(scenario())

    response = client.get(
        f"/api/profiles/{root.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 403
    assert "Root-only private address" not in response.text


def test_bulk_profile_reads_exclude_peer_and_higher_roles(profile_api_setup):
    client, persistence = profile_api_setup

    async def scenario():
        admin, admin_token = await _create_user_with_session(
            persistence,
            email="profile-list-admin@example.com",
            role="admin",
        )
        peer, _ = await _create_user_with_session(
            persistence,
            email="profile-list-peer@example.com",
            role="admin",
        )
        root, _ = await _create_user_with_session(
            persistence,
            email="profile-list-root@example.com",
            role="root",
        )
        user, _ = await _create_user_with_session(
            persistence,
            email="profile-list-user@example.com",
            role="user",
        )
        return admin, admin_token, peer, root, user

    admin, admin_token, peer, root, user = asyncio.run(scenario())

    response = client.get(
        "/api/profiles",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    visible_ids = {profile["user_id"] for profile in response.json()}
    assert visible_ids == {str(admin.id), str(user.id)}
    assert str(peer.id) not in visible_ids
    assert str(root.id) not in visible_ids


def test_bulk_profile_reads_remain_privileged(profile_api_setup):
    client, persistence = profile_api_setup
    _, token = asyncio.run(
        _create_user_with_session(
            persistence,
            email="profile-list-user-denied@example.com",
            role="user",
        )
    )

    response = client.get(
        "/api/profiles",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_admin_can_update_a_lower_role_profile(profile_api_setup):
    client, persistence = profile_api_setup

    async def scenario():
        _, admin_token = await _create_user_with_session(
            persistence,
            email="profile-editor@example.com",
            role="admin",
        )
        target, _ = await _create_user_with_session(
            persistence,
            email="profile-edit-target@example.com",
            role="user",
        )
        return admin_token, target

    admin_token, target = asyncio.run(scenario())

    response = client.put(
        f"/api/profiles/{target.id}",
        json={"full_name": "Managed User"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.json()["full_name"] == "Managed User"


@pytest.mark.parametrize("operation", ["create", "update", "delete"])
def test_admin_cannot_mutate_a_root_profile(profile_api_setup, operation):
    client, persistence = profile_api_setup

    async def scenario():
        _, admin_token = await _create_user_with_session(
            persistence,
            email=f"blocked-profile-admin-{operation}@example.com",
            role="admin",
        )
        target, _ = await _create_user_with_session(
            persistence,
            email=f"root-profile-{operation}@example.com",
            role="root",
        )
        original_profile = await persistence.get_profile_by_user_id(str(target.id))
        if operation == "create":
            await persistence.delete_profile(str(target.id))
        return admin_token, target, original_profile

    admin_token, target, original_profile = asyncio.run(scenario())
    headers = {"Authorization": f"Bearer {admin_token}"}

    if operation == "create":
        response = client.post(
            "/api/profiles",
            json={
                "user_id": str(target.id),
                "full_name": "Unauthorized recreation",
                "email": target.email,
            },
            headers=headers,
        )
    elif operation == "update":
        response = client.put(
            f"/api/profiles/{target.id}",
            json={"full_name": "Unauthorized update"},
            headers=headers,
        )
    else:
        response = client.delete(
            f"/api/profiles/{target.id}",
            headers=headers,
        )

    assert response.status_code == 403
    stored_profile = asyncio.run(
        persistence.get_profile_by_user_id(str(target.id))
    )
    if operation == "create":
        assert stored_profile is None
    else:
        assert stored_profile == original_profile


@pytest.mark.parametrize("operation", ["create", "update", "delete"])
def test_profile_mutation_revalidates_a_demoted_actor(
    profile_api_setup,
    monkeypatch,
    operation,
):
    client, persistence = profile_api_setup

    async def scenario():
        actor, actor_token = await _create_user_with_session(
            persistence,
            email="profile-demoted-admin@example.com",
            role="admin",
        )
        target, _ = await _create_user_with_session(
            persistence,
            email=f"profile-demotion-{operation}-target@example.com",
            role="user",
        )
        original_profile = await persistence.get_profile_by_user_id(str(target.id))
        if operation == "create":
            await persistence.delete_profile(str(target.id))
        return actor, actor_token, target, original_profile

    actor, actor_token, target, original_profile = asyncio.run(scenario())
    method_name = {
        "create": "create_profile_for_session",
        "update": "update_profile_for_session",
        "delete": "delete_profile_for_session",
    }[operation]
    original_mutation = getattr(Persistence, method_name)

    async def demote_then_mutate(request_db, **kwargs):
        request_db.conn.execute(
            "UPDATE users SET role = 'user' WHERE id = ?",
            (str(actor.id),),
        )
        request_db.conn.commit()
        return await original_mutation(request_db, **kwargs)

    monkeypatch.setattr(
        Persistence,
        method_name,
        demote_then_mutate,
    )

    headers = {"Authorization": f"Bearer {actor_token}"}
    if operation == "create":
        response = client.post(
            "/api/profiles",
            json={
                "user_id": str(target.id),
                "full_name": "Stale authorization recreation",
                "email": target.email,
            },
            headers=headers,
        )
    elif operation == "update":
        response = client.put(
            f"/api/profiles/{target.id}",
            json={"full_name": "Stale authorization update"},
            headers=headers,
        )
    else:
        response = client.delete(
            f"/api/profiles/{target.id}",
            headers=headers,
        )

    assert response.status_code == 403
    stored_profile = asyncio.run(
        persistence.get_profile_by_user_id(str(target.id))
    )
    if operation == "create":
        assert stored_profile is None
    else:
        assert stored_profile == original_profile


def test_user_can_delete_and_recreate_own_profile(profile_api_setup):
    client, persistence = profile_api_setup
    user, token = asyncio.run(
        _create_user_with_session(
            persistence,
            email="self-profile-mutation@example.com",
            role="user",
        )
    )
    headers = {"Authorization": f"Bearer {token}"}

    delete_response = client.delete(
        f"/api/profiles/{user.id}",
        headers=headers,
    )
    assert delete_response.status_code == 204

    create_response = client.post(
        "/api/profiles",
        json={
            "user_id": str(user.id),
            "full_name": "Recreated Self",
            "email": user.email,
        },
        headers=headers,
    )
    assert create_response.status_code == 201
    assert create_response.json()["full_name"] == "Recreated Self"
