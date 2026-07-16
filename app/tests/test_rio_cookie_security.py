from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any, Mapping

import httpx
import pytest
import rio
from rio.data_models import InitialClientMessage
from rio.transports import MessageRecorderTransport
from starlette.datastructures import Headers
from starlette.requests import cookie_parser

import app.rio_cookie_security as cookie_security_module
from app.rio_cookie_security import canonical_http_origin, install_rio_cookie_security


_HTTPS_ORIGIN = "https://testserver"
_HTTP_ORIGIN = "http://testserver"
_COOKIE_WRITE_PATH = "/rio/cookies"
_CAPABILITY_HEADER = "x-rio-cookie-capability"
_SESSION_TOKEN_HEADER = "x-rio-session-token"
_WRITE_TOKEN_HEADER = "x-rio-cookie-write-token"


@dataclass
class _CookieSettings(rio.UserSettings):
    auth_token: rio.HttpOnly[str]
    other_cookie: rio.HttpOnly[str] = ""
    display_mode: str = "system"


class _MutableClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _new_server(
    *,
    secure: bool,
    capability_ttl_seconds: float = 30.0,
    clock: Any | None = None,
) -> tuple[Any, Any]:
    rio_app = rio.App(
        name="cookie-security-test",
        build=rio.Spacer,
        default_attachments=[
            _CookieSettings(auth_token="", other_cookie=""),
        ],
    )
    server = rio_app.as_fastapi()
    security = install_rio_cookie_security(
        server,
        secure_auth_cookie=secure,
        canonical_origin=_HTTPS_ORIGIN if secure else None,
        capability_ttl_seconds=capability_ttl_seconds,
        clock=clock or _MutableClock(),
    )
    return server, security


def _register_session(server: Any, session: rio.Session, token: str) -> None:
    server._active_session_tokens[token] = session
    server._active_tokens_by_session[session] = token


async def _create_rio_session(
    server: Any,
    security: Any,
    *,
    browser_binding: str,
    origin: str,
    register: bool = True,
    browser_cookie_header: str | None = None,
    browser_cookies: Mapping[str, str] | None = None,
) -> tuple[rio.Session, MessageRecorderTransport, str]:
    if browser_cookie_header is None:
        browser_cookie_header = (
            f"{security.browser_binding_cookie_name}={browser_binding}"
        )
    if browser_cookies is None:
        browser_cookies = cookie_parser(browser_cookie_header)

    recorder = MessageRecorderTransport()
    session = await server.create_session(
        InitialClientMessage.from_defaults(url=f"{origin}/"),
        transport=recorder,
        client_ip="127.0.0.1",
        client_port=43210,
        http_headers=Headers(
            {
                "cookie": browser_cookie_header,
                "user-agent": "Mozilla/5.0 cookie-security-test",
            }
        ),
        cookies=browser_cookies,
    )
    session_token = f"rio-session-{id(session)}"
    if register:
        _register_session(server, session, session_token)
    return session, recorder, session_token


def _cookie_write_headers(
    security: Any,
    *,
    capability: str,
    write_token: str,
    session_token: str,
    browser_binding: str,
    origin: str,
) -> dict[str, str]:
    return {
        "origin": origin,
        "sec-fetch-site": "same-origin",
        _CAPABILITY_HEADER: capability,
        _SESSION_TOKEN_HEADER: session_token,
        _WRITE_TOKEN_HEADER: write_token,
        "cookie": (f"{security.browser_binding_cookie_name}={browser_binding}"),
    }


async def _redeem(
    client: httpx.AsyncClient,
    security: Any,
    *,
    capability: str,
    write_token: str,
    session_token: str,
    browser_binding: str,
    origin: str,
    overrides: Mapping[str, str] | None = None,
) -> httpx.Response:
    headers = _cookie_write_headers(
        security,
        capability=capability,
        write_token=write_token,
        session_token=session_token,
        browser_binding=browser_binding,
        origin=origin,
    )
    if overrides is not None:
        headers.update(overrides)
    return await client.post(_COOKIE_WRITE_PATH, headers=headers)


def _cookie_morsels(response: httpx.Response) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for header in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(header)
        assert len(parsed) == 1
        name = next(iter(parsed))
        result[name] = parsed[name]
    return result


def _assert_cookie_attributes(
    morsel: Any,
    *,
    secure: bool,
    same_site: str,
) -> None:
    assert morsel["httponly"] is True
    assert bool(morsel["secure"]) is secure
    assert morsel["samesite"] == same_site
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""
    assert morsel["max-age"] == ""
    assert morsel["expires"] == ""


def _assert_deleted_cookie(morsel: Any, *, secure: bool) -> None:
    assert morsel.value == ""
    assert morsel["httponly"] is True
    assert bool(morsel["secure"]) is secure
    assert morsel["samesite"] == "lax"
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""
    assert morsel["max-age"] == "0"
    assert morsel["expires"]


def _cookie_write_javascript(
    recorder: MessageRecorderTransport,
) -> str:
    sources = [
        message["params"]["java_script_source"]
        for message in recorder.sent_messages
        if message.get("method") == "evaluateJavaScript"
        and _CAPABILITY_HEADER
        in message.get("params", {}).get("java_script_source", "")
    ]
    assert len(sources) == 1
    return sources[0]


def _javascript_header_value(source: str, header: str) -> str:
    match = re.search(rf"'{re.escape(header)}': '([^']+)'", source)
    assert match is not None
    return match.group(1)


def _browser_cookie_state(
    client: httpx.AsyncClient,
) -> tuple[str, dict[str, str]]:
    request = client.build_request("GET", "/")
    cookie_header = request.headers["cookie"]
    return cookie_header, cookie_parser(cookie_header)


def _request_cookie_value(value: str) -> str:
    """Render Rio's JSON string value as it appears in a Cookie header."""
    return json.dumps(json.dumps(value))


@pytest.mark.parametrize("accept", ["text/html", "*/*;q=.8"])
def test_browser_binding_is_seeded_in_direct_rio_response(accept: str) -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        transport = httpx.ASGITransport(app=server)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=_HTTPS_ORIGIN,
            headers={"user-agent": "Mozilla/5.0 cookie-security-test"},
        ) as client:
            first = await client.get(
                "/account?tab=security",
                headers={"accept": accept},
                follow_redirects=False,
            )

            assert first.status_code == 200

            cookies = _cookie_morsels(first)
            assert set(cookies) == {security.browser_binding_cookie_name}
            binding = cookies[security.browser_binding_cookie_name]
            assert security.is_valid_browser_binding(binding.value)
            _assert_cookie_attributes(
                binding,
                secure=True,
                same_site="lax",
            )
            assert len(server._latent_session_tokens) == 1
            retained_request = next(iter(server._latent_session_tokens.values()))
            assert (
                retained_request.cookies[security.browser_binding_cookie_name]
                == binding.value
            )

            second = await client.get(
                "/account?tab=security",
                headers={"accept": accept},
                follow_redirects=False,
            )

            assert second.status_code == 200
            assert second.headers.get_list("set-cookie") == []

    asyncio.run(scenario())


def test_duplicate_binding_cookies_are_normalized_and_can_redeem() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=False)
        stale_parent_binding = security.new_browser_binding()
        active_host_binding = security.new_browser_binding()
        cookie_name = security.browser_binding_cookie_name
        duplicate_cookie_header = (
            f"{cookie_name}={stale_parent_binding}; {cookie_name}={active_host_binding}"
        )
        session, _, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=active_host_binding,
            origin=_HTTP_ORIGIN,
        )

        try:
            issued = await security.issue_cookie_write(
                session,
                {"auth_token": json.dumps("owner-auth")},
            )
            assert issued is not None
            capability, write_token = issued

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server),
                base_url=_HTTP_ORIGIN,
                headers={"user-agent": "Mozilla/5.0 cookie-security-test"},
            ) as client:
                for _ in range(2):
                    response = await client.get(
                        "/account",
                        headers={
                            "accept": "text/html",
                            "cookie": duplicate_cookie_header,
                        },
                        follow_redirects=False,
                    )
                    assert response.status_code == 200
                    assert response.headers.get_list("set-cookie") == []

                retained_request = list(server._latent_session_tokens.values())[-1]
                normalized_binding = retained_request.cookies[cookie_name]
                assert normalized_binding == stale_parent_binding
                assert retained_request.headers.getlist("cookie") == [
                    f"{cookie_name}={normalized_binding}"
                ]

                redeemed = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=active_host_binding,
                    origin=_HTTP_ORIGIN,
                    overrides={"cookie": duplicate_cookie_header},
                )
                assert redeemed.status_code == 204
                assert security.pending_count() == 0
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("cookie_case", "expected_auth_token"),
    [
        ("physical-and-parent-domain", "owner-auth"),
        ("legacy-only", ""),
        ("duplicate-physical", ""),
    ],
)
def test_secure_auth_cookie_is_loaded_under_logical_rio_key_and_fails_closed(
    cookie_case: str,
    expected_auth_token: str,
) -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        assert security.auth_token_cookie_name.startswith("__Host-")
        physical_cookie = security.auth_token_cookie_name

        if cookie_case == "physical-and-parent-domain":
            cookie_header = (
                f"auth_token={_request_cookie_value('attacker-auth')}; "
                f"{physical_cookie}={_request_cookie_value('owner-auth')}"
            )
        elif cookie_case == "legacy-only":
            cookie_header = f"auth_token={_request_cookie_value('legacy-auth')}"
        else:
            cookie_header = (
                f"{physical_cookie}={_request_cookie_value('owner-auth')}; "
                f"{physical_cookie}={_request_cookie_value('attacker-auth')}; "
                f"auth_token={_request_cookie_value('attacker-auth')}"
            )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server),
            base_url=_HTTPS_ORIGIN,
            headers={"user-agent": "Mozilla/5.0 cookie-security-test"},
        ) as client:
            response = await client.get(
                "/account",
                headers={
                    "accept": "text/html",
                    "cookie": cookie_header,
                },
                follow_redirects=False,
            )

        assert response.status_code == 200
        response_cookies = _cookie_morsels(response)
        _assert_deleted_cookie(response_cookies["auth_token"], secure=True)

        retained_request = next(iter(server._latent_session_tokens.values()))
        retained_cookie_header = retained_request.headers["cookie"]
        assert physical_cookie not in retained_cookie_header
        assert "attacker-auth" not in retained_cookie_header

        recorder = MessageRecorderTransport()
        session = await server.create_session(
            InitialClientMessage.from_defaults(url=f"{_HTTPS_ORIGIN}/account"),
            transport=recorder,
            client_ip="127.0.0.1",
            client_port=43210,
            http_headers=retained_request.headers,
            cookies=retained_request.cookies,
        )
        try:
            assert session[_CookieSettings].auth_token == expected_auth_token
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_websocket_scope_receives_only_the_logical_host_cookie_value() -> None:
    async def scenario() -> None:
        _, security = _new_server(secure=True)
        physical_cookie = security.auth_token_cookie_name
        cookie_header = (
            f"auth_token={_request_cookie_value('attacker-auth')}; "
            f"{physical_cookie}={_request_cookie_value('owner-auth')}"
        )
        captured_scope: dict[str, Any] = {}

        async def downstream(
            scope: dict[str, Any],
            receive: Any,
            send: Any,
        ) -> None:
            captured_scope.update(scope)

        async def receive() -> dict[str, str]:
            return {"type": "websocket.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            raise AssertionError(f"Unexpected ASGI response: {message}")

        middleware = cookie_security_module._BrowserBindingMiddleware(
            downstream,
            security=security,
        )
        await middleware(
            {
                "type": "websocket",
                "headers": [(b"cookie", cookie_header.encode("latin-1"))],
            },
            receive,
            send,
        )

        rewritten_headers = Headers(raw=captured_scope["headers"])
        rewritten_cookie_header = rewritten_headers["cookie"]
        assert physical_cookie not in rewritten_cookie_header
        assert "attacker-auth" not in rewritten_cookie_header
        assert cookie_parser(rewritten_cookie_header) == {
            "auth_token": json.dumps("owner-auth")
        }

    asyncio.run(scenario())


def test_save_waits_for_registration_and_generates_hardened_post() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        browser_binding = security.new_browser_binding()
        session, recorder, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
            register=False,
        )

        try:
            settings = session[_CookieSettings]
            settings.auth_token = "auth-value-not-for-javascript"
            settings.other_cookie = "other-value-not-for-javascript"
            save_task = asyncio.create_task(session._save_settings_now())

            await asyncio.sleep(0.02)
            assert not save_task.done()
            assert security.pending_count() == 0

            _register_session(server, session, session_token)
            await asyncio.wait_for(save_task, timeout=1)

            source = _cookie_write_javascript(recorder)
            assert source.startswith("(async () => {")
            assert "fetch('/rio/cookies', {" in source
            assert "method: 'POST'" in source
            assert "credentials: 'same-origin'" in source
            assert "cache: 'no-store'" in source
            assert "keepalive: true" in source
            assert f"'{_SESSION_TOKEN_HEADER}': globalThis.SESSION_TOKEN" in source
            assert "globalThis.location.reload" not in source
            assert "for (let attempt = 0; attempt < 2" in source
            assert "if (attempt === 0) continue" in source
            assert "response.status < 500 || attempt === 1" in source
            assert "rio-cookie-write-failed" in source
            assert "rio-cookie-write-failure" in source
            assert "Your sign-in state could not be saved" in source
            assert "auth-value-not-for-javascript" not in source
            assert "other-value-not-for-javascript" not in source

            capability = _javascript_header_value(
                source,
                _CAPABILITY_HEADER,
            )
            write_token = _javascript_header_value(source, _WRITE_TOKEN_HEADER)
            assert security.pending_count() == 1

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server),
                base_url=_HTTPS_ORIGIN,
            ) as client:
                response = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )
            assert response.status_code == 204
            assert security.pending_count() == 0
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_terminal_unregistered_session_skips_cookie_delivery_promptly() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        browser_binding = security.new_browser_binding()
        session, recorder, _ = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
            register=False,
        )

        settings = session[_CookieSettings]
        settings.auth_token = "stale-auth"
        settings.display_mode = "dark"

        started = time.monotonic()
        await asyncio.wait_for(
            session._close(close_remote_session=False),
            timeout=1.0,
        )
        elapsed = time.monotonic() - started

        assert elapsed < 1.0
        assert session._was_closed
        assert recorder.is_closed
        assert session not in server._active_tokens_by_session
        assert security.pending_count() == 0
        assert not any(
            message.get("method") == "evaluateJavaScript"
            for message in recorder.sent_messages
        )
        settings_messages = [
            message
            for message in recorder.sent_messages
            if message.get("method") == "setUserSettings"
        ]
        assert settings_messages[-1]["params"]["delta_settings"] == {
            "display_mode": "dark"
        }
        assert settings._rio_dirty_attribute_names_ == set()

    asyncio.run(scenario())


def test_cookie_issue_failure_preserves_only_cookie_dirtiness() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        session, recorder, _ = await _create_rio_session(
            server,
            security,
            browser_binding="invalid-browser-binding",
            origin=_HTTPS_ORIGIN,
        )

        try:
            settings = session[_CookieSettings]
            settings.auth_token = "auth-that-must-be-retried"
            settings.display_mode = "dark"

            await session._save_settings_now()

            settings_messages = [
                message
                for message in recorder.sent_messages
                if message.get("method") == "setUserSettings"
            ]
            assert len(settings_messages) == 1
            assert settings_messages[0]["params"]["delta_settings"] == {
                "display_mode": "dark"
            }
            assert settings._rio_dirty_attribute_names_ == {"auth_token"}
            assert security.pending_count() == 0
            assert not any(
                message.get("method") == "evaluateJavaScript"
                for message in recorder.sent_messages
            )
        finally:
            settings._rio_dirty_attribute_names_.clear()
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_cookie_write_route_rejects_get_without_consuming_capability() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        browser_binding = security.new_browser_binding()
        session, _, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
        )
        try:
            capability, write_token = await security.issue_cookie_write(
                session,
                {"auth_token": json.dumps("owner-auth")},
            )
            headers = _cookie_write_headers(
                security,
                capability=capability,
                write_token=write_token,
                session_token=session_token,
                browser_binding=browser_binding,
                origin=_HTTPS_ORIGIN,
            )

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server),
                base_url=_HTTPS_ORIGIN,
            ) as client:
                for path in (_COOKIE_WRITE_PATH, "/rio/cookies/guessed"):
                    response = await client.get(path, headers=headers)
                    assert response.status_code == 405
                    assert response.headers["allow"] == "POST"
                    assert response.headers["cache-control"] == "no-store"
                    assert response.headers.get_list("set-cookie") == []
                    assert security.pending_count() == 1

                success = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )
            assert success.status_code == 204
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_wrong_binding_with_all_owner_tokens_does_not_consume() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        owner_binding = security.new_browser_binding()
        other_binding = security.new_browser_binding()
        session, _, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=owner_binding,
            origin=_HTTPS_ORIGIN,
        )
        try:
            capability, write_token = await security.issue_cookie_write(
                session,
                {"auth_token": json.dumps("owner-auth")},
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server),
                base_url=_HTTPS_ORIGIN,
            ) as client:
                rejected = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=other_binding,
                    origin=_HTTPS_ORIGIN,
                )
                assert rejected.status_code == 404
                assert rejected.headers.get_list("set-cookie") == []
                assert security.pending_count() == 1

                success = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=owner_binding,
                    origin=_HTTPS_ORIGIN,
                )
            assert success.status_code == 204
            assert security.pending_count() == 0
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("header_name", "wrong_value", "expected_status"),
    [
        ("origin", "https://attacker.example", 403),
        ("origin", "https://testserver/path", 403),
        ("origin", "https://testserver?query=1", 403),
        ("origin", "https://testserver/#fragment", 403),
        ("sec-fetch-site", "cross-site", 403),
        (_SESSION_TOKEN_HEADER, "wrong-rio-session", 404),
        (_WRITE_TOKEN_HEADER, "wrong-cookie-write-token", 404),
    ],
)
def test_wrong_request_proof_does_not_consume_capability(
    header_name: str,
    wrong_value: str,
    expected_status: int,
) -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        browser_binding = security.new_browser_binding()
        session, _, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
        )
        try:
            capability, write_token = await security.issue_cookie_write(
                session,
                {"auth_token": json.dumps("owner-auth")},
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server),
                base_url=_HTTPS_ORIGIN,
            ) as client:
                rejected = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                    overrides={header_name: wrong_value},
                )
                assert rejected.status_code == expected_status
                assert rejected.headers.get_list("set-cookie") == []
                assert security.pending_count() == 1

                success = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )
            assert success.status_code == 204
            assert security.pending_count() == 0
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_owner_redemption_sets_exact_cookie_policy_and_blocks_replay() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        browser_binding = security.new_browser_binding()
        session, _, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
        )
        try:
            capability, write_token = await security.issue_cookie_write(
                session,
                {
                    "auth_token": json.dumps("owner-auth"),
                    "other_cookie": json.dumps("companion-value"),
                },
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server),
                base_url=_HTTPS_ORIGIN,
            ) as client:
                success = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )

                assert success.status_code == 204
                assert success.headers["cache-control"] == "no-store"
                cookies = _cookie_morsels(success)
                assert set(cookies) == {
                    security.auth_token_cookie_name,
                    "auth_token",
                    "other_cookie",
                }
                auth_cookie = cookies[security.auth_token_cookie_name]
                assert auth_cookie.value == json.dumps("owner-auth")
                assert cookies["other_cookie"].value == json.dumps("companion-value")
                for morsel in (auth_cookie, cookies["other_cookie"]):
                    _assert_cookie_attributes(
                        morsel,
                        secure=True,
                        same_site="lax",
                    )
                _assert_deleted_cookie(cookies["auth_token"], secure=True)

                replay = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )
                assert replay.status_code == 404
                assert replay.headers.get_list("set-cookie") == []
                assert security.pending_count() == 0

                (
                    logout_capability,
                    logout_write_token,
                ) = await security.issue_cookie_write(
                    session,
                    {"auth_token": json.dumps("")},
                )
                logout = await _redeem(
                    client,
                    security,
                    capability=logout_capability,
                    write_token=logout_write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )
                assert logout.status_code == 204
                logout_cookies = _cookie_morsels(logout)
                assert set(logout_cookies) == {
                    security.auth_token_cookie_name,
                    "auth_token",
                }
                for morsel in logout_cookies.values():
                    _assert_deleted_cookie(morsel, secure=True)
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_capability_expires_at_ttl_boundary_with_mutable_clock() -> None:
    async def scenario() -> None:
        clock = _MutableClock()
        server, security = _new_server(
            secure=True,
            capability_ttl_seconds=3.0,
            clock=clock,
        )
        browser_binding = security.new_browser_binding()
        session, _, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
        )
        try:
            capability, write_token = await security.issue_cookie_write(
                session,
                {"auth_token": json.dumps("owner-auth")},
            )
            assert security.pending_count() == 1
            clock.advance(3.0)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server),
                base_url=_HTTPS_ORIGIN,
            ) as client:
                expired = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )
            assert expired.status_code == 404
            assert expired.headers.get_list("set-cookie") == []
            assert security.pending_count() == 0
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_abandoned_capability_is_actively_removed() -> None:
    async def scenario() -> None:
        server, security = _new_server(
            secure=True,
            capability_ttl_seconds=0.02,
            clock=time.monotonic,
        )
        browser_binding = security.new_browser_binding()
        session, _, _ = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
        )
        try:
            await security.issue_cookie_write(
                session,
                {"auth_token": json.dumps("short-lived-auth")},
            )
            assert security.pending_count() == 1

            await asyncio.sleep(0.1)

            assert security.pending_count() == 0
        finally:
            await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_pending_write_remains_redeemable_after_rio_session_closes() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=True)
        browser_binding = security.new_browser_binding()
        session, _, session_token = await _create_rio_session(
            server,
            security,
            browser_binding=browser_binding,
            origin=_HTTPS_ORIGIN,
        )
        capability, write_token = await security.issue_cookie_write(
            session,
            {"auth_token": json.dumps("")},
        )

        await session._close(close_remote_session=False)
        assert session not in server._active_tokens_by_session
        assert session_token not in server._active_session_tokens
        assert security.pending_count() == 1

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server),
            base_url=_HTTPS_ORIGIN,
        ) as client:
            success = await _redeem(
                client,
                security,
                capability=capability,
                write_token=write_token,
                session_token=session_token,
                browser_binding=browser_binding,
                origin=_HTTPS_ORIGIN,
            )
            assert success.status_code == 204
            assert security.pending_count() == 0

            replay = await _redeem(
                client,
                security,
                capability=capability,
                write_token=write_token,
                session_token=session_token,
                browser_binding=browser_binding,
                origin=_HTTPS_ORIGIN,
            )
        assert replay.status_code == 404

    asyncio.run(scenario())


def test_secure_https_cookie_round_trip_uses_only_the_host_prefixed_credential() -> (
    None
):
    async def scenario() -> None:
        server, security = _new_server(secure=True)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server),
            base_url=_HTTPS_ORIGIN,
            headers={"user-agent": "Mozilla/5.0 cookie-security-test"},
        ) as client:
            handshake = await client.get(
                "/",
                headers={"accept": "text/html"},
                follow_redirects=False,
            )
            browser_binding = _cookie_morsels(handshake)[
                security.browser_binding_cookie_name
            ].value
            cookie_header, browser_cookies = _browser_cookie_state(client)
            session, _, session_token = await _create_rio_session(
                server,
                security,
                browser_binding=browser_binding,
                origin=_HTTPS_ORIGIN,
                browser_cookie_header=cookie_header,
                browser_cookies=browser_cookies,
            )
            try:
                capability, write_token = await security.issue_cookie_write(
                    session,
                    {"auth_token": json.dumps("secure-auth")},
                )
                login = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTPS_ORIGIN,
                )
                assert login.status_code == 204

                _, persisted_cookies = _browser_cookie_state(client)
                assert persisted_cookies[security.auth_token_cookie_name] == json.dumps(
                    "secure-auth"
                )
                assert "auth_token" not in persisted_cookies

                page = await client.get(
                    "/account",
                    headers={"accept": "text/html"},
                    follow_redirects=False,
                )
                assert page.status_code == 200
                retained_request = list(server._latent_session_tokens.values())[-1]
                assert retained_request.cookies["auth_token"] == json.dumps(
                    "secure-auth"
                )
                assert security.auth_token_cookie_name not in retained_request.cookies

                restarted = await server.create_session(
                    InitialClientMessage.from_defaults(url=f"{_HTTPS_ORIGIN}/account"),
                    transport=MessageRecorderTransport(),
                    client_ip="127.0.0.1",
                    client_port=43210,
                    http_headers=retained_request.headers,
                    cookies=retained_request.cookies,
                )
                try:
                    assert restarted[_CookieSettings].auth_token == "secure-auth"
                finally:
                    await restarted._close(close_remote_session=False)
            finally:
                await session._close(close_remote_session=False)

    asyncio.run(scenario())


def test_local_http_cookie_round_trip_and_empty_overwrite() -> None:
    async def scenario() -> None:
        server, security = _new_server(secure=False)
        assert security.browser_binding_cookie_name == "rio-browser-binding"
        assert security.auth_token_cookie_name == "auth_token"

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server),
            base_url=_HTTP_ORIGIN,
            headers={"user-agent": "Mozilla/5.0 cookie-security-test"},
        ) as client:
            handshake = await client.get(
                "/",
                headers={"accept": "text/html"},
                follow_redirects=False,
            )
            assert handshake.status_code == 200
            binding_cookie = _cookie_morsels(handshake)[
                security.browser_binding_cookie_name
            ]
            _assert_cookie_attributes(
                binding_cookie,
                secure=False,
                same_site="lax",
            )
            browser_binding = binding_cookie.value

            cookie_header, browser_cookies = _browser_cookie_state(client)
            session, _, session_token = await _create_rio_session(
                server,
                security,
                browser_binding=browser_binding,
                origin=_HTTP_ORIGIN,
                browser_cookie_header=cookie_header,
                browser_cookies=browser_cookies,
            )
            try:
                capability, write_token = await security.issue_cookie_write(
                    session,
                    {
                        "auth_token": json.dumps("local-auth"),
                        "other_cookie": json.dumps("local-companion"),
                    },
                )
                login = await _redeem(
                    client,
                    security,
                    capability=capability,
                    write_token=write_token,
                    session_token=session_token,
                    browser_binding=browser_binding,
                    origin=_HTTP_ORIGIN,
                )
                assert login.status_code == 204
                login_cookies = _cookie_morsels(login)
                assert set(login_cookies) == {"auth_token", "other_cookie"}
                for morsel in login_cookies.values():
                    _assert_cookie_attributes(
                        morsel,
                        secure=False,
                        same_site="lax",
                    )

                cookie_header, browser_cookies = _browser_cookie_state(client)
                assert browser_cookies["auth_token"] == json.dumps("local-auth")
                fresh, _, fresh_token = await _create_rio_session(
                    server,
                    security,
                    browser_binding=browser_binding,
                    origin=_HTTP_ORIGIN,
                    browser_cookie_header=cookie_header,
                    browser_cookies=browser_cookies,
                )
                try:
                    assert fresh[_CookieSettings].auth_token == "local-auth"
                    assert fresh[_CookieSettings].other_cookie == "local-companion"

                    capability, write_token = await security.issue_cookie_write(
                        fresh,
                        {"auth_token": json.dumps("")},
                    )
                    logout = await _redeem(
                        client,
                        security,
                        capability=capability,
                        write_token=write_token,
                        session_token=fresh_token,
                        browser_binding=browser_binding,
                        origin=_HTTP_ORIGIN,
                    )
                    assert logout.status_code == 204
                    logout_cookie = _cookie_morsels(logout)["auth_token"]
                    assert logout_cookie.value == json.dumps("")
                    _assert_cookie_attributes(
                        logout_cookie,
                        secure=False,
                        same_site="lax",
                    )

                    cookie_header, browser_cookies = _browser_cookie_state(client)
                    assert browser_cookies["auth_token"] == json.dumps("")
                    restarted, _, _ = await _create_rio_session(
                        server,
                        security,
                        browser_binding=browser_binding,
                        origin=_HTTP_ORIGIN,
                        browser_cookie_header=cookie_header,
                        browser_cookies=browser_cookies,
                        register=False,
                    )
                    try:
                        assert restarted[_CookieSettings].auth_token == ""
                        assert (
                            restarted[_CookieSettings].other_cookie == "local-companion"
                        )
                    finally:
                        await restarted._close(close_remote_session=False)
                finally:
                    await fresh._close(close_remote_session=False)
            finally:
                await session._close(close_remote_session=False)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "canonical_origin",
    [
        "https://testserver/application",
        "https://testserver?environment=production",
        "https://testserver/#deployment",
        "https://testserver?",
        "https://testserver#",
        "https://testserver ",
        "https://testserver\\evil",
        "https://%74estserver",
        "https://téstserver",
        "https://-testserver",
        "https://testserver.",
        "https://0x7f000001",
        "https://0x7f.0.0.1",
        "https://example.123",
        "https://example.0x7f",
        "https://xn--a.example",
        "https://xn--abc.example",
        "https://xn--0.example",
        "https://[v1.a]",
        "https://0x",
        "https://1.0x",
        "https://example.0x",
        "https://xn--00b.example",
    ],
)
def test_installation_rejects_canonical_urls_that_are_not_origins(
    canonical_origin: str,
) -> None:
    rio_app = rio.App(name="origin-guard-test", build=rio.Spacer)
    server = rio_app.as_fastapi()

    with pytest.raises(ValueError, match="Invalid HTTP origin"):
        install_rio_cookie_security(
            server,
            secure_auth_cookie=True,
            canonical_origin=canonical_origin,
        )

    assert not hasattr(server, "_rioboilerplate_cookie_security")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://Example.TEST/", "https://example.test"),
        ("https://example.test:443", "https://example.test"),
        ("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
        (
            "https://[2001:0DB8:0:0:0:0:0:1]:443/",
            "https://[2001:db8::1]",
        ),
        ("https://xn--bcher-kva.example", "https://xn--bcher-kva.example"),
        ("https://xn--fa-hia.example", "https://xn--fa-hia.example"),
        (
            "https://xn--strae-oqa.example",
            "https://xn--strae-oqa.example",
        ),
    ],
)
def test_canonical_http_origin_normalizes_supported_origins(
    value: str,
    expected: str,
) -> None:
    assert canonical_http_origin(value) == expected


def test_installation_refuses_unreviewed_rio_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rio_app = rio.App(name="version-guard-test", build=rio.Spacer)
    server = rio_app.as_fastapi()
    monkeypatch.setattr(
        cookie_security_module,
        "version",
        lambda package: "0.12.3" if package == "rio-ui" else "unknown",
    )

    with pytest.raises(
        RuntimeError,
        match=r"supports rio-ui 0\.12\.2, found 0\.12\.3",
    ):
        install_rio_cookie_security(
            server,
            secure_auth_cookie=False,
        )

    assert not hasattr(server, "_rioboilerplate_cookie_security")
    rio_cookie_routes = [
        (route.path, route.methods)
        for route in server.router.routes
        if route.path.startswith("/rio/cookies")
    ]
    assert rio_cookie_routes == [("/rio/cookies/{url}", {"GET"})]
