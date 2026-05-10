import asyncio
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from fastapi.testclient import TestClient

import app as app_module
from app.api import oauth as oauth_module
from app.data_models import AppUser, RecoveryCodeUsage, UserSettings
from app.pages.login import LoginPage, SocialMFAForm
from app.persistence import Persistence


@pytest.fixture
def temp_db(tmp_path: Path):
    db_path = tmp_path / "test.db"
    persistence = Persistence(db_path=db_path)
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_password_user(
    persistence: Persistence,
    email: str,
    password: str = "password",
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(email=email, password=password)
    await persistence.create_user(user)
    return await persistence.get_user_by_id(user.id)


async def _create_social_user(
    persistence: Persistence,
    email: str,
    provider_user_id: str = "google-sub-123",
) -> AppUser:
    user = AppUser.create_social_user(
        email=email,
        provider="google",
        provider_user_id=provider_user_id,
        is_verified=True,
    )
    await persistence.create_user(user)
    return await persistence.get_user_by_id(user.id)


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeUrl:
    def __init__(self, query: dict[str, str]):
        self.query = query


class _FakeSession:
    def __init__(self, persistence: Persistence, query: dict[str, str]):
        self.active_page_url = _FakeUrl(query)
        self._store = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=""),
        }
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()
        self.navigated_to: str | None = None

    def __getitem__(self, key):
        if key in self._store:
            return self._store[key]
        raise KeyError(key)

    def attach(self, value) -> None:
        self._store[type(value)] = value

    def navigate_to(self, target: str) -> None:
        self.navigated_to = target

    def _register_dirty_component(self, component) -> None:
        pass


def _new_login_page(persistence: Persistence, query: dict[str, str]) -> LoginPage:
    page = object.__new__(LoginPage)
    page._session_ = _FakeSession(persistence, query)
    page._properties_assigned_after_creation_ = set()
    page.force_refresh = lambda: None
    page.current_form = "login"
    page.page_message = ""
    page.page_message_style = "success"
    page.reset_prefilled_email = ""
    page.reset_prefilled_token = ""
    page.reset_prefilled_message = ""
    page.reset_prefilled_message_style = "success"
    page.reset_prefilled_require_two_factor = False
    page.pending_social_user_id = ""
    return page


class _FakeOAuthClient:
    def __init__(self, userinfo: dict | None = None, error: Exception | None = None):
        self.userinfo = userinfo or {}
        self.error = error

    async def authorize_access_token(self, request):
        if self.error is not None:
            raise self.error
        return {"userinfo": self.userinfo}

    async def authorize_redirect(self, request, redirect_uri):
        from starlette.responses import RedirectResponse

        return RedirectResponse(f"https://accounts.google.test/auth?redirect_uri={redirect_uri}")


def _redirect_query(response) -> dict[str, list[str]]:
    location = response.headers["location"]
    return parse_qs(urlparse(location).query)


def _patch_app_persistence(monkeypatch, persistence: Persistence) -> None:
    # TestClient runs the ASGI app in a worker thread. Give that thread its own
    # SQLite connection while keeping the same tmp_path-backed database.
    def get_thread_persistence() -> Persistence:
        return Persistence(
            db_path=persistence.db_path,
            allow_username_login=persistence.allow_username_login,
        )

    monkeypatch.setattr(app_module, "get_persistence", get_thread_persistence)
    monkeypatch.setattr(oauth_module, "get_persistence", get_thread_persistence)


def test_oauth_handoff_tokens_are_hashed_single_use_and_expire(temp_db: Persistence):
    async def scenario():
        user = await _create_social_user(temp_db, "handoff@example.com")
        token = await temp_db.create_oauth_handoff(user_id=user.id, provider="google")
        token_hash = temp_db._hash_one_time_token(token)

        cursor = temp_db._get_cursor()
        cursor.execute(
            "SELECT 1 FROM oauth_login_handoffs WHERE token_hash = ?",
            (token_hash,),
        )
        assert cursor.fetchone() is not None
        cursor.execute(
            "SELECT 1 FROM oauth_login_handoffs WHERE token_hash = ?",
            (token,),
        )
        assert cursor.fetchone() is None

        consumed = await temp_db.consume_oauth_handoff(token)
        assert consumed.id == user.id
        with pytest.raises(KeyError):
            await temp_db.consume_oauth_handoff(token)

        expired_token = await temp_db.create_oauth_handoff(user_id=user.id, provider="google")
        expired_hash = temp_db._hash_one_time_token(expired_token)
        cursor.execute(
            "UPDATE oauth_login_handoffs SET valid_until = 0 WHERE token_hash = ?",
            (expired_hash,),
        )
        temp_db.conn.commit()
        with pytest.raises(KeyError):
            await temp_db.consume_oauth_handoff(expired_token)

    asyncio.run(scenario())


def test_get_user_by_provider_identity(temp_db: Persistence):
    async def scenario():
        user = await _create_social_user(
            temp_db,
            "provider@example.com",
            provider_user_id="google-stable-sub",
        )
        found = await temp_db.get_user_by_provider_identity("google", "google-stable-sub")
        assert found.id == user.id
        with pytest.raises(KeyError):
            await temp_db.get_user_by_provider_identity("google", "missing")

    asyncio.run(scenario())


def test_google_callback_creates_social_user_and_handoff(monkeypatch, temp_db: Persistence):
    fake_client = _FakeOAuthClient(
        {
            "sub": "google-new-user",
            "email": "new-google@example.com",
            "email_verified": True,
            "name": "New Google User",
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/google/callback", follow_redirects=False)

    assert response.status_code in {302, 307}
    query = _redirect_query(response)
    assert "social_login_token" in query

    async def scenario():
        user = await temp_db.get_user_by_provider_identity("google", "google-new-user")
        assert user.email == "new-google@example.com"
        handoff_user = await temp_db.consume_oauth_handoff(query["social_login_token"][0])
        assert handoff_user.id == user.id

    asyncio.run(scenario())


def test_google_callback_reuses_existing_provider_user(monkeypatch, temp_db: Persistence):
    async def setup():
        return await _create_social_user(
            temp_db,
            "existing-google@example.com",
            provider_user_id="google-existing",
        )

    existing = asyncio.run(setup())
    fake_client = _FakeOAuthClient(
        {
            "sub": "google-existing",
            "email": "changed-google@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/google/callback", follow_redirects=False)

    query = _redirect_query(response)
    assert "social_login_token" in query

    async def scenario():
        handoff_user = await temp_db.consume_oauth_handoff(query["social_login_token"][0])
        assert handoff_user.id == existing.id
        assert handoff_user.email == "existing-google@example.com"

    asyncio.run(scenario())


def test_google_callback_refuses_password_email_collision(monkeypatch, temp_db: Persistence):
    asyncio.run(_create_password_user(temp_db, "collision@example.com"))
    fake_client = _FakeOAuthClient(
        {
            "sub": "google-collision",
            "email": "collision@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/google/callback", follow_redirects=False)

    assert response.headers["location"] == "/login?oauth_error=account_exists"


def test_google_callback_refuses_unverified_or_missing_email(monkeypatch, temp_db: Persistence):
    fake_client = _FakeOAuthClient(
        {
            "sub": "google-unverified",
            "email": "unverified@example.com",
            "email_verified": False,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/google/callback", follow_redirects=False)

    assert response.headers["location"] == "/login?oauth_error=unverified_email"


def test_google_callback_provider_failure_redirects_to_login(monkeypatch, temp_db: Persistence):
    fake_client = _FakeOAuthClient(error=RuntimeError("state mismatch"))
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/google/callback", follow_redirects=False)

    assert response.headers["location"] == "/login?oauth_error=provider_failed"


def test_unconfigured_google_login_redirects_to_safe_error(monkeypatch, temp_db: Persistence):
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: None)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/google/login", follow_redirects=False)

    assert response.headers["location"] == "/login?oauth_error=provider_not_configured"


def test_disabled_provider_returns_404(monkeypatch, temp_db: Persistence):
    _patch_app_persistence(monkeypatch, temp_db)
    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/github/login", follow_redirects=False)

    assert response.status_code == 404


def test_login_page_consumes_social_handoff_and_creates_session(temp_db: Persistence):
    async def scenario():
        user = await _create_social_user(temp_db, "rio-handoff@example.com")
        token = await temp_db.create_oauth_handoff(user_id=user.id, provider="google")
        page = _new_login_page(temp_db, {"social_login_token": token})

        await LoginPage.on_populate(page)

        settings = page.session[UserSettings]
        assert settings.auth_token
        assert page.session.navigated_to == "/app/dashboard"
        session_user = page.session[AppUser]
        assert session_user.id == user.id

    asyncio.run(scenario())


def test_social_handoff_does_not_bypass_two_factor(temp_db: Persistence):
    async def scenario():
        user = await _create_social_user(temp_db, "social-2fa@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        token = await temp_db.create_oauth_handoff(user_id=user.id, provider="google")
        page = _new_login_page(temp_db, {"social_login_token": token})

        await LoginPage.on_populate(page)

        assert page.current_form == "social_mfa"
        assert page.pending_social_user_id == str(user.id)
        assert page.session[UserSettings].auth_token == ""
        assert page.session.navigated_to is None

        form = object.__new__(SocialMFAForm)
        form._session_ = page.session
        form._properties_assigned_after_creation_ = set()
        form.force_refresh = lambda: None
        form.pending_user_id = str(user.id)
        form.verification_code = pyotp.TOTP(secret).now()
        form.error_message = ""
        form.banner_style = "success"
        form._is_processing = False
        form.on_toggle_form = None

        await SocialMFAForm.complete_login(form)

        assert page.session[UserSettings].auth_token
        assert page.session.navigated_to == "/app/dashboard"

    asyncio.run(scenario())


def test_social_mfa_records_recovery_code_usage(temp_db: Persistence):
    async def scenario():
        user = await _create_social_user(temp_db, "social-recovery@example.com")
        temp_db.set_2fa_secret(user.id, pyotp.random_base32())
        code = temp_db.generate_recovery_codes(user.id, count=1)[0]
        form = object.__new__(SocialMFAForm)
        form._session_ = _FakeSession(temp_db, {})
        form._properties_assigned_after_creation_ = set()
        form.force_refresh = lambda: None
        form.pending_user_id = str(user.id)
        form.verification_code = code
        form.error_message = ""
        form.banner_style = "success"
        form._is_processing = False
        form.on_toggle_form = None

        await SocialMFAForm.complete_login(form)

        assert form.session[RecoveryCodeUsage].used_at_login is True
        assert form.session.navigated_to == "/app/dashboard"

    asyncio.run(scenario())
