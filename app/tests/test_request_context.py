import asyncio

import pytest
from starlette.requests import Request
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.config import config
import app.request_context as request_context
from app.request_context import context_from_fastapi_request, resolve_client_ip


@pytest.fixture(autouse=True)
def proxy_config():
    original = {
        "RATE_LIMIT_TRUST_PROXY_HEADERS": config.RATE_LIMIT_TRUST_PROXY_HEADERS,
        "RATE_LIMIT_TRUSTED_PROXIES": config.RATE_LIMIT_TRUSTED_PROXIES,
        "warning_emitted": request_context._ignored_proxy_headers_warning_emitted,
    }
    config.RATE_LIMIT_TRUST_PROXY_HEADERS = False
    config.RATE_LIMIT_TRUSTED_PROXIES = "127.0.0.1,::1"
    request_context._ignored_proxy_headers_warning_emitted = False
    yield
    config.RATE_LIMIT_TRUST_PROXY_HEADERS = original["RATE_LIMIT_TRUST_PROXY_HEADERS"]
    config.RATE_LIMIT_TRUSTED_PROXIES = original["RATE_LIMIT_TRUSTED_PROXIES"]
    request_context._ignored_proxy_headers_warning_emitted = original["warning_emitted"]


def test_resolve_client_ip_ignores_forwarded_headers_by_default(capsys):
    resolved = resolve_client_ip(
        peer_ip="127.0.0.1",
        headers={
            "X-Real-IP": "203.0.113.42",
            "X-Forwarded-For": "203.0.113.42",
        },
    )

    assert resolved == "127.0.0.1"
    assert "RATE_LIMIT_TRUST_PROXY_HEADERS is False" in capsys.readouterr().err


def test_resolve_client_ip_uses_forwarded_headers_when_configured():
    config.RATE_LIMIT_TRUST_PROXY_HEADERS = True

    resolved = resolve_client_ip(
        peer_ip="127.0.0.1",
        headers={
            "X-Real-IP": "203.0.113.42",
            "X-Forwarded-For": "198.51.100.10, 127.0.0.1",
        },
    )

    assert resolved == "203.0.113.42"


def test_uvicorn_proxy_middleware_resolves_client_before_request_context():
    seen: dict[str, str] = {}

    async def app(scope, receive, send):
        request = Request(scope, receive)
        seen["client_ip"] = context_from_fastapi_request(request).client_ip
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [
            (b"x-forwarded-for", b"203.0.113.42"),
            (b"x-real-ip", b"203.0.113.42"),
            (b"x-forwarded-proto", b"https"),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8000),
    }

    asyncio.run(middleware(scope, receive, send))

    assert seen["client_ip"] == "203.0.113.42"
