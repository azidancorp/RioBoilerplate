import asyncio
import base64
import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import RedirectResponse

import app as app_module
from app.api import oauth as oauth_module
from app.api.auth_dependencies import get_persistence
from app.data_models import AppUser, RecoveryCodeUsage, UserSession, UserSettings
from app.oauth_clients import _google_registration_kwargs
from app.pages.login import LoginPage, SocialMFAForm
from app.persistence import Persistence
from app.rio_cookie_security import (
    browser_binding_digest,
    get_rio_cookie_security,
)


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    yield
    app_module.fastapi_app.dependency_overrides.clear()


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
    await persistence._create_user_unchecked(user)
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
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


async def _bootstrap_root(persistence: Persistence) -> AppUser:
    assert await persistence.create_verified_root_user_if_empty(
        email="root@example.com",
        password="VeryStrongPass!9",
    )
    return await persistence.get_user_by_email("root@example.com")


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeUrl:
    def __init__(self, query: dict[str, str]):
        self.query = query


class _FakeSession:
    def __init__(
        self,
        persistence: Persistence,
        query: dict[str, str],
        *,
        http_headers: Headers | None = None,
        app_server=None,
    ):
        self.active_page_url = _FakeUrl(query)
        self.http_headers = http_headers or Headers()
        self._app_server = app_server or app_module.fastapi_app
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


def _browser_binding_headers(binding: str) -> Headers:
    security = get_rio_cookie_security(app_module.fastapi_app)
    assert security is not None
    return Headers(
        {"cookie": f"{security.browser_binding_cookie_name}={binding}"}
    )


def _new_login_page(
    persistence: Persistence,
    query: dict[str, str],
    *,
    browser_binding: str | None = None,
) -> LoginPage:
    page = object.__new__(LoginPage)
    headers = (
        Headers()
        if browser_binding is None
        else _browser_binding_headers(browser_binding)
    )
    page._session_ = _FakeSession(
        persistence,
        query,
        http_headers=headers,
    )
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
        self.redirect_uri = None
        self.redirect_kwargs: dict = {}
        self.authorize_redirect_calls = 0
        self.authorize_access_token_calls = 0

    async def authorize_access_token(self, request):
        self.authorize_access_token_calls += 1
        if self.error is not None:
            raise self.error
        return {"userinfo": self.userinfo}

    async def authorize_redirect(self, request, redirect_uri, **kwargs):
        self.authorize_redirect_calls += 1
        self.redirect_uri = redirect_uri
        self.redirect_kwargs = kwargs
        return RedirectResponse(
            f"https://accounts.google.test/auth?redirect_uri={redirect_uri}",
            status_code=302,
        )


def _redirect_query(response) -> dict[str, list[str]]:
    return parse_qs(urlparse(response.headers["location"]).query)


def _assert_clean_login_redirect(
    response,
    *,
    error: str | None = None,
    social_login: bool = False,
    return_to: str | None = None,
) -> dict[str, list[str]]:
    assert response.status_code == 303
    location = response.headers["location"]
    parsed = urlparse(location)
    assert parsed.path == "/login"
    assert "social_login_token" not in location
    query = parse_qs(parsed.query)
    assert set(query) <= {"oauth_error", "social_login", "return_to"}
    if error is None:
        assert "oauth_error" not in query
    else:
        assert query["oauth_error"] == [error]
    if social_login:
        assert query["social_login"] == ["1"]
    else:
        assert "social_login" not in query
    if return_to is None:
        assert "return_to" not in query
    else:
        assert query["return_to"] == [return_to]
    return query


def _patch_app_persistence(monkeypatch, persistence: Persistence) -> None:
    # TestClient runs the ASGI app in a worker thread. Give that thread its own
    # SQLite connection while keeping the same tmp_path-backed database.
    async def override_get_persistence():
        db = Persistence(
            db_path=persistence.db_path,
            allow_username_login=persistence.allow_username_login,
        )
        try:
            yield db
        finally:
            db.close()

    app_module.fastapi_app.dependency_overrides[get_persistence] = (
        override_get_persistence
    )


def _set_browser_binding(client: TestClient, binding: str) -> None:
    security = get_rio_cookie_security(app_module.fastapi_app)
    assert security is not None
    client.cookies.set(security.browser_binding_cookie_name, binding)


def _bind_browser(client: TestClient) -> str:
    security = get_rio_cookie_security(app_module.fastapi_app)
    assert security is not None
    binding = security.new_browser_binding()
    _set_browser_binding(client, binding)
    return binding


def _start_google_login(
    client: TestClient,
    *,
    return_to: str | None = None,
):
    params = {} if return_to is None else {"return_to": return_to}
    response = client.get(
        "/auth/google/login",
        params=params,
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith(
        "https://accounts.google.test/auth?"
    )
    return response


def _pending_rows(persistence: Persistence) -> list[tuple[str, str, str]]:
    return persistence.conn.execute(
        """
        SELECT binding_digest, user_id, provider
        FROM oauth_pending_logins
        ORDER BY binding_digest
        """
    ).fetchall()


def test_google_registration_enables_s256_pkce_end_to_end(monkeypatch):
    registration = _google_registration_kwargs()
    client_kwargs = registration["client_kwargs"]
    assert isinstance(client_kwargs, dict)
    assert client_kwargs["code_challenge_method"] == "S256"

    registration = {
        **registration,
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "authorize_url": "https://accounts.google.test/auth",
        "access_token_url": "https://accounts.google.test/token",
    }
    registration.pop("server_metadata_url")
    test_oauth = OAuth()
    test_oauth.register(**registration)
    client = test_oauth.create_client("google")
    assert client is not None

    async def scenario():
        callback_uri = "https://app.test/auth/google/callback"
        authorization = await client.create_authorization_url(callback_uri)
        query = parse_qs(urlparse(authorization["url"]).query)
        verifier = authorization["code_verifier"]
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")

        assert query["code_challenge_method"] == ["S256"]
        assert query["code_challenge"] == [expected_challenge]

        session: dict[str, object] = {}
        start_request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/auth/google/login",
                "query_string": b"",
                "headers": [],
                "session": session,
            }
        )
        await client.save_authorize_data(
            start_request,
            redirect_uri=callback_uri,
            **authorization,
        )

        captured: dict[str, object] = {}

        async def capture_access_token(**kwargs):
            captured.update(kwargs)
            return {"access_token": "test-access-token"}

        monkeypatch.setattr(client, "fetch_access_token", capture_access_token)
        state = query["state"][0]
        callback_request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/auth/google/callback",
                "query_string": f"code=test-code&state={state}".encode(),
                "headers": [],
                "session": session,
            }
        )
        await client.authorize_access_token(callback_request)

        assert captured["code_verifier"] == verifier
        assert captured["redirect_uri"] == callback_uri
        assert session == {}

    asyncio.run(scenario())


def test_unknown_provider_404_does_not_require_session_middleware(monkeypatch):
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: None)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/auth/github/login",
            "query_string": b"",
            "headers": [],
        }
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            oauth_module.oauth_login(
                provider="github",
                request=request,
                return_to="",
            )
        )

    assert exc_info.value.status_code == 404


@pytest.mark.parametrize("binding_state", ["missing", "forged", "duplicate"])
def test_google_login_requires_one_valid_browser_binding(
    monkeypatch,
    binding_state: str,
):
    fake_client = _FakeOAuthClient()
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    security = get_rio_cookie_security(app_module.fastapi_app)
    assert security is not None

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        headers = None
        if binding_state == "forged":
            client.cookies.set(
                security.browser_binding_cookie_name,
                "forged-browser-binding",
            )
        elif binding_state == "duplicate":
            first = security.new_browser_binding()
            second = security.new_browser_binding()
            headers = {
                "cookie": (
                    f"{security.browser_binding_cookie_name}={first}; "
                    f"{security.browser_binding_cookie_name}={second}"
                )
            }

        response = client.get(
            "/auth/google/login",
            headers=headers,
            follow_redirects=False,
        )

    _assert_clean_login_redirect(response, error="browser_not_verified")
    assert fake_client.authorize_redirect_calls == 0


def test_unconfigured_google_login_redirects_without_browser_binding(monkeypatch):
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: None)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        response = client.get("/auth/google/login", follow_redirects=False)

    _assert_clean_login_redirect(response, error="provider_not_configured")


def test_google_callback_without_initiation_fails_before_token_exchange(
    monkeypatch,
    temp_db: Persistence,
):
    fake_client = _FakeOAuthClient()
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        _bind_browser(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, error="browser_changed")
    assert fake_client.authorize_access_token_calls == 0
    assert _pending_rows(temp_db) == []


def test_google_callback_binding_swap_fails_and_cannot_be_replayed(
    monkeypatch,
    temp_db: Persistence,
):
    fake_client = _FakeOAuthClient(
        {
            "sub": "binding-swap-sub",
            "email": "binding-swap@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)
    security = get_rio_cookie_security(app_module.fastapi_app)
    assert security is not None

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        original_binding = _bind_browser(client)
        _start_google_login(client)
        replacement_binding = security.new_browser_binding()
        _set_browser_binding(client, replacement_binding)

        swapped = client.get("/auth/google/callback", follow_redirects=False)
        _set_browser_binding(client, original_binding)
        replayed = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(swapped, error="browser_changed")
    _assert_clean_login_redirect(replayed, error="browser_changed")
    assert fake_client.authorize_access_token_calls == 0
    assert _pending_rows(temp_db) == []


def test_google_callback_creates_social_user_and_pending_login(
    monkeypatch,
    temp_db: Persistence,
):
    asyncio.run(_bootstrap_root(temp_db))
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
        binding = _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, social_login=True)
    user = asyncio.run(
        temp_db.get_user_by_provider_identity("google", "google-new-user")
    )
    assert user.email == "new-google@example.com"
    assert user.role == "user"
    assert _pending_rows(temp_db) == [
        (browser_binding_digest(binding), str(user.id), "google")
    ]


def test_google_callback_requires_operator_bootstrap(
    monkeypatch,
    temp_db: Persistence,
):
    fake_client = _FakeOAuthClient(
        {
            "sub": "google-first-user",
            "email": "first-google@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, error="bootstrap_required")
    assert temp_db.get_user_count() == 0
    assert _pending_rows(temp_db) == []


def test_login_page_explains_oauth_bootstrap_requirement(temp_db: Persistence):
    page = _new_login_page(temp_db, {"oauth_error": "bootstrap_required"})

    asyncio.run(LoginPage.on_populate(page))

    assert page.current_form == "login"
    assert page.page_message_style == "danger"
    assert "initialized by an operator" in page.page_message


def test_get_user_by_provider_identity(temp_db: Persistence):
    async def scenario():
        user = await _create_social_user(
            temp_db,
            "provider@example.com",
            provider_user_id="google-stable-sub",
        )
        found = await temp_db.get_user_by_provider_identity(
            "google",
            "google-stable-sub",
        )
        assert found.id == user.id
        with pytest.raises(KeyError):
            await temp_db.get_user_by_provider_identity("google", "missing")

    asyncio.run(scenario())


def test_google_callback_reuses_existing_provider_user(
    monkeypatch,
    temp_db: Persistence,
):
    existing = asyncio.run(
        _create_social_user(
            temp_db,
            "existing-google@example.com",
            provider_user_id="google-existing",
        )
    )
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
        binding = _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, social_login=True)
    assert _pending_rows(temp_db) == [
        (browser_binding_digest(binding), str(existing.id), "google")
    ]
    refreshed = asyncio.run(temp_db.get_user_by_id(existing.id))
    assert refreshed.email == "existing-google@example.com"


def test_google_callback_refuses_password_email_collision(
    monkeypatch,
    temp_db: Persistence,
):
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
        _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, error="account_exists")
    assert _pending_rows(temp_db) == []


def test_google_callback_refuses_unverified_email(
    monkeypatch,
    temp_db: Persistence,
):
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
        _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, error="unverified_email")
    assert _pending_rows(temp_db) == []


def test_google_callback_refuses_missing_provider_id(
    monkeypatch,
    temp_db: Persistence,
):
    fake_client = _FakeOAuthClient(
        {
            "email": "missing-sub@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, error="missing_provider_id")
    assert _pending_rows(temp_db) == []


def test_google_callback_provider_failure_redirects_to_login(
    monkeypatch,
    temp_db: Persistence,
):
    fake_client = _FakeOAuthClient(error=RuntimeError("state mismatch"))
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, error="provider_failed")
    assert fake_client.authorize_access_token_calls == 1
    assert _pending_rows(temp_db) == []


def test_google_callback_maps_inactive_account_to_clean_error(
    monkeypatch,
    temp_db: Persistence,
):
    user = asyncio.run(
        _create_social_user(
            temp_db,
            "inactive-google@example.com",
            provider_user_id="inactive-google-sub",
        )
    )
    temp_db.conn.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (str(user.id),),
    )
    temp_db.conn.commit()
    fake_client = _FakeOAuthClient(
        {
            "sub": "inactive-google-sub",
            "email": "inactive-google@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        _bind_browser(client)
        _start_google_login(client)
        response = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(response, error="account_inactive")
    assert _pending_rows(temp_db) == []


def test_google_login_round_trips_allowlisted_return_destination(
    monkeypatch,
    temp_db: Persistence,
):
    asyncio.run(
        _create_social_user(
            temp_db,
            "oauth-return-to@example.com",
            provider_user_id="oauth-return-to-sub",
        )
    )
    fake_client = _FakeOAuthClient(
        {
            "sub": "oauth-return-to-sub",
            "email": "oauth-return-to@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        binding = _bind_browser(client)
        _start_google_login(client, return_to="/app/settings")
        callback = client.get("/auth/google/callback", follow_redirects=False)

    _assert_clean_login_redirect(
        callback,
        social_login=True,
        return_to="/app/settings",
    )
    page = _new_login_page(
        temp_db,
        {"social_login": "1", "return_to": "/app/settings"},
        browser_binding=binding,
    )
    asyncio.run(LoginPage.on_populate(page))
    assert page.session.navigated_to == "/app/settings"


def test_google_login_ignores_unsafe_or_callback_injected_return_destinations(
    monkeypatch,
    temp_db: Persistence,
):
    asyncio.run(
        _create_social_user(
            temp_db,
            "oauth-unsafe-return@example.com",
            provider_user_id="oauth-unsafe-return-sub",
        )
    )
    fake_client = _FakeOAuthClient(
        {
            "sub": "oauth-unsafe-return-sub",
            "email": "oauth-unsafe-return@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        _bind_browser(client)
        _start_google_login(
            client,
            return_to="//example.com/app/settings",
        )
        callback = client.get(
            "/auth/google/callback?return_to=/app/settings",
            follow_redirects=False,
        )

    _assert_clean_login_redirect(callback, social_login=True)


def test_second_google_login_in_same_browser_replaces_pending_row(
    monkeypatch,
    temp_db: Persistence,
):
    first = asyncio.run(
        _create_social_user(
            temp_db,
            "first-pending@example.com",
            provider_user_id="first-pending-sub",
        )
    )
    second = asyncio.run(
        _create_social_user(
            temp_db,
            "second-pending@example.com",
            provider_user_id="second-pending-sub",
        )
    )
    fake_client = _FakeOAuthClient(
        {
            "sub": "first-pending-sub",
            "email": "first-pending@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        binding = _bind_browser(client)
        _start_google_login(client)
        first_callback = client.get(
            "/auth/google/callback",
            follow_redirects=False,
        )
        _assert_clean_login_redirect(first_callback, social_login=True)

        fake_client.userinfo = {
            "sub": "second-pending-sub",
            "email": "second-pending@example.com",
            "email_verified": True,
        }
        _start_google_login(client)
        second_callback = client.get(
            "/auth/google/callback",
            follow_redirects=False,
        )

    _assert_clean_login_redirect(second_callback, social_login=True)
    assert first.id != second.id
    assert _pending_rows(temp_db) == [
        (browser_binding_digest(binding), str(second.id), "google")
    ]


def test_two_browser_redemption_fails_without_destroying_pending_login(
    monkeypatch,
    temp_db: Persistence,
):
    user = asyncio.run(
        _create_social_user(
            temp_db,
            "two-browser@example.com",
            provider_user_id="two-browser-sub",
        )
    )
    fake_client = _FakeOAuthClient(
        {
            "sub": "two-browser-sub",
            "email": "two-browser@example.com",
            "email_verified": True,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)
    security = get_rio_cookie_security(app_module.fastapi_app)
    assert security is not None

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        owner_binding = _bind_browser(client)
        _start_google_login(client)
        callback = client.get("/auth/google/callback", follow_redirects=False)
    _assert_clean_login_redirect(callback, social_login=True)

    other_binding = security.new_browser_binding()
    attacker_page = _new_login_page(
        temp_db,
        {"social_login": "1"},
        browser_binding=other_binding,
    )
    asyncio.run(LoginPage.on_populate(attacker_page))
    assert "expired or was already used" in attacker_page.page_message
    assert _pending_rows(temp_db) == [
        (browser_binding_digest(owner_binding), str(user.id), "google")
    ]

    owner_page = _new_login_page(
        temp_db,
        {"social_login": "1"},
        browser_binding=owner_binding,
    )
    asyncio.run(LoginPage.on_populate(owner_page))
    assert owner_page.session[UserSettings].auth_token
    assert owner_page.session[AppUser].id == user.id
    assert owner_page.session.navigated_to == "/app/dashboard"
    assert _pending_rows(temp_db) == []

    replay_page = _new_login_page(
        temp_db,
        {"social_login": "1"},
        browser_binding=owner_binding,
    )
    asyncio.run(LoginPage.on_populate(replay_page))
    assert "expired or was already used" in replay_page.page_message
    assert replay_page.session[UserSettings].auth_token == ""


def test_pending_login_expiry_and_inactive_user_delete_row(temp_db: Persistence):
    async def scenario():
        security = get_rio_cookie_security(app_module.fastapi_app)
        assert security is not None
        user = await _create_social_user(
            temp_db,
            "pending-lifecycle@example.com",
            provider_user_id="pending-lifecycle-sub",
        )

        expired_digest = browser_binding_digest(security.new_browser_binding())
        await temp_db.create_oauth_pending_login(
            binding_digest=expired_digest,
            user_id=user.id,
            provider="google",
        )
        temp_db.conn.execute(
            "UPDATE oauth_pending_logins SET valid_until = 0 WHERE binding_digest = ?",
            (expired_digest,),
        )
        temp_db.conn.commit()
        with pytest.raises(KeyError):
            await temp_db.consume_oauth_pending_login(expired_digest)
        assert _pending_rows(temp_db) == []

        inactive_digest = browser_binding_digest(security.new_browser_binding())
        await temp_db.create_oauth_pending_login(
            binding_digest=inactive_digest,
            user_id=user.id,
            provider="google",
        )
        temp_db.conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (str(user.id),),
        )
        temp_db.conn.commit()
        with pytest.raises(KeyError):
            await temp_db.consume_oauth_pending_login(inactive_digest)
        assert _pending_rows(temp_db) == []

    asyncio.run(scenario())


def test_legacy_social_login_token_never_consumes_pending_login(
    temp_db: Persistence,
):
    async def scenario():
        security = get_rio_cookie_security(app_module.fastapi_app)
        assert security is not None
        user = await _create_social_user(
            temp_db,
            "legacy-link@example.com",
            provider_user_id="legacy-link-sub",
        )
        binding = security.new_browser_binding()
        digest = browser_binding_digest(binding)
        await temp_db.create_oauth_pending_login(
            binding_digest=digest,
            user_id=user.id,
            provider="google",
        )
        page = _new_login_page(
            temp_db,
            {
                "social_login_token": "legacy-url-token",
                "social_login": "1",
            },
            browser_binding=binding,
        )

        await LoginPage.on_populate(page)

        assert page.current_form == "login"
        assert page.page_message == (
            "This Google sign-in link is no longer supported. "
            "Please sign in with Google again."
        )
        assert _pending_rows(temp_db) == [
            (digest, str(user.id), "google")
        ]

    asyncio.run(scenario())


def test_social_login_marker_without_binding_fails_closed(temp_db: Persistence):
    page = _new_login_page(temp_db, {"social_login": "1"})

    asyncio.run(LoginPage.on_populate(page))

    assert page.current_form == "login"
    assert page.page_message_style == "danger"
    assert "browser could not be verified" in page.page_message


@pytest.mark.parametrize(
    ("error_code", "message_fragment"),
    [
        ("browser_not_verified", "browser could not be verified"),
        ("browser_changed", "browser where it started"),
    ],
)
def test_login_page_explains_browser_oauth_errors(
    temp_db: Persistence,
    error_code: str,
    message_fragment: str,
):
    page = _new_login_page(temp_db, {"oauth_error": error_code})

    asyncio.run(LoginPage.on_populate(page))

    assert page.current_form == "login"
    assert page.page_message_style == "danger"
    assert message_fragment in page.page_message


def test_oauth_login_handles_late_session_creation_rejection(
    monkeypatch: pytest.MonkeyPatch,
    temp_db: Persistence,
):
    async def scenario():
        security = get_rio_cookie_security(app_module.fastapi_app)
        assert security is not None
        user = await _create_social_user(
            temp_db,
            "late-oauth-rejection@example.com",
        )
        binding = security.new_browser_binding()
        await temp_db.create_oauth_pending_login(
            binding_digest=browser_binding_digest(binding),
            user_id=user.id,
            provider="google",
        )
        page = _new_login_page(
            temp_db,
            {"social_login": "1"},
            browser_binding=binding,
        )

        async def reject_session_creation(user_id):
            assert user_id == user.id
            raise KeyError(user_id)

        monkeypatch.setattr(temp_db, "create_session", reject_session_creation)

        await LoginPage.on_populate(page)

        assert page.current_form == "login"
        assert page.page_message_style == "danger"
        assert "changed or became inactive" in page.page_message
        assert page.session[UserSettings].auth_token == ""
        assert UserSession not in page.session._store
        assert AppUser not in page.session._store
        assert page.session.navigated_to is None

    asyncio.run(scenario())


def test_pending_social_login_does_not_bypass_two_factor(temp_db: Persistence):
    async def scenario():
        security = get_rio_cookie_security(app_module.fastapi_app)
        assert security is not None
        user = await _create_social_user(temp_db, "social-2fa@example.com")
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(user.id, secret)
        binding = security.new_browser_binding()
        await temp_db.create_oauth_pending_login(
            binding_digest=browser_binding_digest(binding),
            user_id=user.id,
            provider="google",
        )
        page = _new_login_page(
            temp_db,
            {"social_login": "1"},
            browser_binding=binding,
        )

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


def test_google_account_deletion_reauth_is_recent_and_session_bound(
    monkeypatch,
    temp_db: Persistence,
):
    async def setup():
        user = await _create_social_user(
            temp_db,
            "delete-google@example.com",
            provider_user_id="google-delete-sub",
        )
        user_session = await temp_db.create_session(user.id)
        challenge = await temp_db.create_oauth_account_deletion_challenge(
            user_id=user.id,
            provider="google",
            auth_token=user_session.id,
        )
        return user, user_session, challenge

    user, user_session, challenge = asyncio.run(setup())
    fake_client = _FakeOAuthClient(
        {
            "sub": "google-delete-sub",
            "auth_time": time.time(),
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        start = client.get(
            "/auth/google/delete-account",
            params={"deletion_challenge": challenge},
            follow_redirects=False,
        )
        callback = client.get(
            "/auth/google/delete-account/callback",
            follow_redirects=False,
        )

    assert start.status_code == 302
    assert fake_client.redirect_kwargs["prompt"] == "select_account"
    assert fake_client.redirect_kwargs["max_age"] == 0
    assert json.loads(fake_client.redirect_kwargs["claims"])["id_token"][
        "auth_time"
    ]["essential"] is True
    assert str(fake_client.redirect_uri).endswith(
        "/auth/google/delete-account/callback"
    )

    approval = _redirect_query(callback)["delete_account_oauth_token"][0]
    assert approval.startswith("DELETE-APPROVE-")

    async def finish_delete():
        assert await temp_db.delete_user(
            user.id,
            password=None,
            auth_token=user_session.id,
            oauth_reauth_token=approval,
        ) is True

    asyncio.run(finish_delete())


def test_google_account_deletion_reauth_rejects_stale_or_wrong_identity(
    monkeypatch,
    temp_db: Persistence,
):
    async def setup_challenge():
        user = await _create_social_user(
            temp_db,
            "reject-delete-google@example.com",
            provider_user_id="expected-delete-sub",
        )
        user_session = await temp_db.create_session(user.id)
        challenge = await temp_db.create_oauth_account_deletion_challenge(
            user_id=user.id,
            provider="google",
            auth_token=user_session.id,
        )
        return user, challenge

    user, challenge = asyncio.run(setup_challenge())
    fake_client = _FakeOAuthClient(
        {
            "sub": "expected-delete-sub",
            "auth_time": time.time() - 3600,
        }
    )
    monkeypatch.setattr(oauth_module, "get_oauth_client", lambda provider: fake_client)
    _patch_app_persistence(monkeypatch, temp_db)

    with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as client:
        missing_start = client.get(
            "/auth/google/delete-account/callback",
            follow_redirects=False,
        )
        client.get(
            "/auth/google/delete-account",
            params={"deletion_challenge": challenge},
            follow_redirects=False,
        )
        stale = client.get(
            "/auth/google/delete-account/callback",
            follow_redirects=False,
        )

        fake_client.userinfo = {
            "sub": "different-delete-sub",
            "auth_time": time.time(),
        }
        client.get(
            "/auth/google/delete-account",
            params={"deletion_challenge": challenge},
            follow_redirects=False,
        )
        wrong_identity = client.get(
            "/auth/google/delete-account/callback",
            follow_redirects=False,
        )

    assert _redirect_query(missing_start)["delete_account_oauth_error"] == [
        "invalid_challenge"
    ]
    assert _redirect_query(stale)["delete_account_oauth_error"] == [
        "reauth_stale"
    ]
    assert _redirect_query(wrong_identity)["delete_account_oauth_error"] == [
        "identity_mismatch"
    ]
    assert asyncio.run(temp_db.get_user_by_id(user.id)).id == user.id
    assert temp_db.conn.execute(
        "SELECT COUNT(*) FROM oauth_login_handoffs WHERE user_id = ?",
        (str(user.id),),
    ).fetchone()[0] == 1
