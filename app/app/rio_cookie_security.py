"""Harden Rio 0.12.2's HTTP-only user-setting cookie transport.

Rio 0.12.2 writes HTTP-only settings through an unbound, one-use GET URL and
does not expose cookie security attributes.  This compatibility layer keeps the
framework pin deployable while those concerns are fixed upstream:

* cookie writes are same-origin POST requests;
* every write is bound to the originating live Rio session and to an
  HTTP-only per-browser nonce;
* capabilities expire quickly and can be redeemed only once; and
* the authentication cookie uses a ``__Host-`` name in production, while Rio
  continues to receive its logical ``auth_token`` setting name.

The adapter deliberately refuses Rio versions other than the repository's
exact pin.  Rio's save hook is private, so a dependency upgrade must be
reviewed rather than silently running without these protections.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import ipaddress
import json
import logging
import re
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from importlib.metadata import version
from typing import Any
from urllib.parse import urlsplit

import idna
import rio
from fastapi import Request
from fastapi.routing import APIRoute
from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import cookie_parser
from starlette.responses import Response
from starlette.routing import Match
from starlette.types import ASGIApp, Receive, Scope, Send

from rio import inspection, serialization


_SUPPORTED_RIO_VERSION = "0.12.2"
_RIO_COOKIE_ROUTE = "/rio/cookies"
_RIO_COOKIE_ROUTE_PREFIX = "/rio/cookies/"
_CAPABILITY_HEADER = "x-rio-cookie-capability"
_SESSION_TOKEN_HEADER = "x-rio-session-token"
_WRITE_TOKEN_HEADER = "x-rio-cookie-write-token"
_DEFAULT_CAPABILITY_TTL_SECONDS = 30.0
_SESSION_REGISTRATION_TIMEOUT_SECONDS = 5.0
_SECURITY_STATE_ATTRIBUTE = "_rioboilerplate_cookie_security"
_ORIGINAL_SAVE_ATTRIBUTE = "_rioboilerplate_original_browser_settings_save"
_AUTH_TOKEN_LOGICAL_COOKIE_NAME = "auth_token"
_AUTH_TOKEN_SECURE_COOKIE_NAME = "__Host-rio-auth-token"
_DNS_LABEL_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)
_HEX_IPV4_LABEL_PATTERN = re.compile(r"0x[0-9a-f]*\Z", re.IGNORECASE)


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _PendingCookieWrite:
    cookies: Mapping[str, str]
    session_token: str
    browser_binding_digest: bytes
    origin: str
    write_token_digest: bytes
    expires_at: float


class _CookieWriteUnavailable(RuntimeError):
    """The live browser cannot safely redeem a cookie-write capability."""


def _cookie_values(headers: Headers, name: str) -> list[str]:
    values: list[str] = []
    for value in headers.getlist("cookie"):
        for chunk in value.split(";"):
            parsed = cookie_parser(chunk)
            if name in parsed:
                values.append(parsed[name])
    return values


def _single_cookie_value(headers: Headers, name: str) -> str | None:
    values = _cookie_values(headers, name)
    if len(values) != 1:
        return None
    return values[0]


def canonical_http_origin(value: str) -> str:
    """Validate and normalize an HTTP origin used at the browser boundary."""
    if (
        not value.isascii()
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in value
        )
        or any(delimiter in value for delimiter in ("?", "#", "\\", "%"))
    ):
        raise ValueError(f"Invalid HTTP origin: {value!r}")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid HTTP origin: {value!r}") from error

    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.netloc.endswith(":")
        or (port is not None and port == 0)
    ):
        raise ValueError(f"Invalid HTTP origin: {value!r}")

    host = parsed.hostname.lower()
    bracketed_host = parsed.netloc.startswith("[")
    if ":" in host:
        if not bracketed_host:
            raise ValueError(f"Invalid HTTP origin: {value!r}")
        try:
            ipv6_host = ipaddress.IPv6Address(host)
        except ValueError as error:
            raise ValueError(f"Invalid HTTP origin: {value!r}") from error
        host = f"[{ipv6_host.compressed}]"
    elif bracketed_host:
        raise ValueError(f"Invalid HTTP origin: {value!r}")
    elif host.replace(".", "").isdigit():
        try:
            host = str(ipaddress.IPv4Address(host))
        except ValueError as error:
            raise ValueError(f"Invalid HTTP origin: {value!r}") from error
    else:
        labels = host.split(".")
        if (
            len(host) > 253
            or host.endswith(".")
            or labels[-1].isdigit()
            or any(
                _DNS_LABEL_PATTERN.fullmatch(label) is None
                or _HEX_IPV4_LABEL_PATTERN.fullmatch(label) is not None
                or not _is_valid_idna_label(label)
                for label in labels
            )
        ):
            raise ValueError(f"Invalid HTTP origin: {value!r}")

    default_port = 80 if parsed.scheme == "http" else 443
    port_suffix = "" if port in {None, default_port} else f":{port}"
    return f"{parsed.scheme}://{host}{port_suffix}"


def _is_valid_idna_label(label: str) -> bool:
    if not label.lower().startswith("xn--"):
        return True
    try:
        decoded = idna.decode(label, uts46=True, std3_rules=True)
        encoded = idna.encode(
            decoded,
            uts46=True,
            std3_rules=True,
        ).decode("ascii")
    except idna.IDNAError:
        return False
    return encoded.lower() == label.lower()


class _BrowserBindingMiddleware:
    """Seed the browser nonce in the initial Rio page request and response."""

    def __init__(self, app: ASGIApp, *, security: RioCookieSecurity) -> None:
        self.app = app
        self.security = security

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        legacy_auth_cookie_present = False
        if scope["type"] in {"http", "websocket"}:
            legacy_auth_cookie_present = self._normalize_auth_cookie(scope)

        if scope["type"] == "http" and legacy_auth_cookie_present:
            send = self._with_legacy_auth_cookie_expiration(send)

        if (
            scope["type"] == "http"
            and (
                scope.get("path", "") == _RIO_COOKIE_ROUTE
                or scope.get("path", "").startswith(_RIO_COOKIE_ROUTE_PREFIX)
            )
            and scope.get("method") != "POST"
        ):
            response = Response(
                status_code=405,
                headers={
                    "Allow": "POST",
                    "Cache-Control": "no-store",
                },
            )
            await response(scope, receive, send)
            return

        if scope["type"] != "http" or not self._is_rio_page_request(scope):
            await self.app(scope, receive, send)
            return

        headers = Headers(raw=scope.get("headers", ()))
        supplied_bindings = _cookie_values(
            headers,
            self.security.browser_binding_cookie_name,
        )
        existing_binding = next(
            (
                binding
                for binding in supplied_bindings
                if self.security.is_valid_browser_binding(binding)
            ),
            None,
        )
        browser_binding = existing_binding or self.security.new_browser_binding()
        self._replace_browser_binding(scope, browser_binding)

        if existing_binding is not None:
            await self.app(scope, receive, send)
            return

        cookie_response = Response()
        cookie_response.set_cookie(
            self.security.browser_binding_cookie_name,
            browser_binding,
            path="/",
            secure=self.security.secure_auth_cookie,
            httponly=True,
            samesite="lax",
        )
        set_cookie_headers = [
            value
            for name, value in cookie_response.raw_headers
            if name == b"set-cookie"
        ]
        if len(set_cookie_headers) != 1:  # pragma: no cover - Starlette guard
            raise RuntimeError("Starlette generated an unexpected cookie header")
        binding_cookie_header = set_cookie_headers[0].decode("latin-1")

        async def send_with_binding(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message = {
                    **message,
                    "headers": list(message.get("headers", ())),
                }
                MutableHeaders(scope=message).append(
                    "set-cookie",
                    binding_cookie_header,
                )
            await send(message)

        await self.app(scope, receive, send_with_binding)

    def _normalize_auth_cookie(self, scope: Scope) -> bool:
        """Translate the physical production cookie to Rio's logical key.

        Secure mode never trusts the old bare cookie. A sibling subdomain can
        create a parent-domain cookie with that name, so it is impossible to
        distinguish a legitimate legacy cookie from a fixation attempt. A
        single ``__Host-`` cookie is accepted; duplicates fail closed.
        """
        if not self.security.secure_auth_cookie:
            return False

        physical_name = self.security.auth_token_cookie_name
        physical_values: list[str] = []
        legacy_cookie_present = False
        rewritten_cookie_chunks: list[str] = []
        rewritten_headers: list[tuple[bytes, bytes]] = []

        raw_headers = scope.setdefault("headers", [])
        for header_name, header_value in raw_headers:
            if header_name.lower() != b"cookie":
                rewritten_headers.append((header_name, header_value))
                continue

            for chunk in header_value.decode("latin-1").split(";"):
                stripped = chunk.strip()
                if not stripped:
                    continue

                parsed = cookie_parser(stripped)
                if physical_name in parsed:
                    physical_values.append(parsed[physical_name])
                    continue
                if _AUTH_TOKEN_LOGICAL_COOKIE_NAME in parsed:
                    legacy_cookie_present = True
                    continue
                rewritten_cookie_chunks.append(stripped)

        if len(physical_values) == 1:
            logical_cookie = SimpleCookie()
            try:
                logical_cookie[_AUTH_TOKEN_LOGICAL_COOKIE_NAME] = physical_values[0]
            except CookieError:
                logger.warning("Ignoring an invalid production authentication cookie")
            else:
                rewritten_cookie_chunks.append(logical_cookie.output(header="").strip())
        elif len(physical_values) > 1:
            logger.warning("Ignoring duplicate production authentication cookies")

        if rewritten_cookie_chunks:
            rewritten_headers.append(
                (
                    b"cookie",
                    "; ".join(rewritten_cookie_chunks).encode("latin-1"),
                )
            )

        if isinstance(raw_headers, list):
            raw_headers[:] = rewritten_headers
        else:  # ASGI specifies an iterable; normalize unusual implementations.
            scope["headers"] = rewritten_headers

        return legacy_cookie_present

    def _with_legacy_auth_cookie_expiration(self, send: Send) -> Send:
        cookie_response = Response()
        self.security.expire_auth_cookie(
            cookie_response,
            _AUTH_TOKEN_LOGICAL_COOKIE_NAME,
        )
        set_cookie_headers = [
            value
            for name, value in cookie_response.raw_headers
            if name == b"set-cookie"
        ]
        if len(set_cookie_headers) != 1:  # pragma: no cover - Starlette guard
            raise RuntimeError("Starlette generated an unexpected cookie header")
        expiration_header = set_cookie_headers[0].decode("latin-1")

        async def send_with_expiration(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message = {
                    **message,
                    "headers": list(message.get("headers", ())),
                }
                MutableHeaders(scope=message).append(
                    "set-cookie",
                    expiration_header,
                )
            await send(message)

        return send_with_expiration

    def _is_rio_page_request(self, scope: Scope) -> bool:
        if scope.get("method") != "GET":
            return False

        for route in self.security.server.router.routes:
            match, _ = route.matches(scope)
            if match is Match.FULL:
                return (
                    getattr(route, "endpoint", None)
                    == self.security.server._serve_index
                )
        return False

    def _replace_browser_binding(self, scope: Scope, value: str) -> None:
        cookie_name = self.security.browser_binding_cookie_name
        rewritten_cookie_chunks: list[str] = []
        rewritten_headers: list[tuple[bytes, bytes]] = []

        raw_headers = scope.setdefault("headers", [])
        for header_name, header_value in raw_headers:
            if header_name.lower() != b"cookie":
                rewritten_headers.append((header_name, header_value))
                continue

            for chunk in header_value.decode("latin-1").split(";"):
                stripped = chunk.strip()
                if stripped and cookie_name not in cookie_parser(stripped):
                    rewritten_cookie_chunks.append(stripped)

        rewritten_cookie_chunks.append(f"{cookie_name}={value}")
        rewritten_headers.append(
            (
                b"cookie",
                "; ".join(rewritten_cookie_chunks).encode("latin-1"),
            )
        )

        if isinstance(raw_headers, list):
            raw_headers[:] = rewritten_headers
        else:  # ASGI specifies an iterable; normalize unusual implementations.
            scope["headers"] = rewritten_headers


class RioCookieSecurity:
    """Own the hardened cookie-write capabilities for one Rio server."""

    def __init__(
        self,
        server: Any,
        *,
        secure_auth_cookie: bool,
        canonical_origin: str | None = None,
        capability_ttl_seconds: float = _DEFAULT_CAPABILITY_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capability_ttl_seconds <= 0:
            raise ValueError("Cookie-write capability TTL must be positive")

        self.server = server
        self.secure_auth_cookie = secure_auth_cookie
        self.capability_ttl_seconds = capability_ttl_seconds
        self._clock = clock
        self._binding_signing_key = secrets.token_bytes(32)
        self._pending: dict[str, _PendingCookieWrite] = {}
        self._expiration_handles: dict[str, asyncio.TimerHandle] = {}

        if canonical_origin is None:
            self.canonical_origin = None
        else:
            self.canonical_origin = canonical_http_origin(canonical_origin)

        if secure_auth_cookie and (
            self.canonical_origin is None
            or not self.canonical_origin.startswith("https://")
        ):
            raise ValueError(
                "Secure production cookies require a canonical HTTPS origin"
            )

        if secure_auth_cookie:
            self.browser_binding_cookie_name = "__Host-rio-browser-binding"
            self.auth_token_cookie_name = _AUTH_TOKEN_SECURE_COOKIE_NAME
        else:
            self.browser_binding_cookie_name = "rio-browser-binding"
            self.auth_token_cookie_name = _AUTH_TOKEN_LOGICAL_COOKIE_NAME

    def new_browser_binding(self) -> str:
        nonce = secrets.token_urlsafe(32)
        signature = hmac.digest(
            self._binding_signing_key,
            nonce.encode("ascii"),
            "sha256",
        )
        encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
        return f"{nonce}.{encoded_signature.decode('ascii')}"

    def is_valid_browser_binding(self, value: str | None) -> bool:
        if value is None or not value.isascii():
            return False

        try:
            nonce, encoded_signature = value.split(".", 1)
            if len(nonce) != 43 or len(encoded_signature) != 43:
                return False
            signature = base64.urlsafe_b64decode(
                encoded_signature + "=" * (-len(encoded_signature) % 4)
            )
        except ValueError:
            return False

        expected = hmac.digest(
            self._binding_signing_key,
            nonce.encode("ascii"),
            "sha256",
        )
        return hmac.compare_digest(signature, expected)

    async def issue_cookie_write(
        self,
        session: rio.Session,
        cookies: Mapping[str, str],
    ) -> tuple[str, str] | None:
        session_token = await self._wait_for_session_registration(session)
        if session_token is None:
            return None

        if self.server._active_session_tokens.get(session_token) is not session:
            raise _CookieWriteUnavailable(
                "Refusing to issue cookies for a mismatched Rio session"
            )

        browser_binding = _single_cookie_value(
            session.http_headers,
            self.browser_binding_cookie_name,
        )
        if not self.is_valid_browser_binding(browser_binding):
            raise _CookieWriteUnavailable(
                "Refusing to issue cookies without a valid browser binding"
            )
        assert browser_binding is not None

        now = self._clock()
        self._discard_expired(now)
        capability = secrets.token_urlsafe(32)
        write_token = secrets.token_urlsafe(32)
        try:
            origin = self.canonical_origin or canonical_http_origin(
                str(session.base_url.origin())
            )
        except ValueError as error:
            raise _CookieWriteUnavailable(
                "Refusing to issue cookies without a valid session origin"
            ) from error
        pending = _PendingCookieWrite(
            cookies=dict(cookies),
            session_token=session_token,
            browser_binding_digest=self._digest(browser_binding),
            origin=origin,
            write_token_digest=self._digest(write_token),
            expires_at=now + self.capability_ttl_seconds,
        )
        self._pending[capability] = pending
        self._expiration_handles[capability] = asyncio.get_running_loop().call_later(
            self.capability_ttl_seconds,
            self._expire_capability,
            capability,
            pending,
        )
        return capability, write_token

    async def redeem_cookie_write(
        self,
        request: Request,
    ) -> Response:
        now = self._clock()
        self._discard_expired(now)

        capability = request.headers.get(_CAPABILITY_HEADER)
        if capability is None:
            return self._not_found()
        pending = self._pending.get(capability)
        if pending is None:
            return self._not_found()

        origin = request.headers.get("origin")
        try:
            request_origin = canonical_http_origin(origin) if origin else None
        except ValueError:
            request_origin = None
        if request_origin != pending.origin:
            return Response(status_code=403, headers={"Cache-Control": "no-store"})

        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site is not None and fetch_site != "same-origin":
            return Response(status_code=403, headers={"Cache-Control": "no-store"})

        supplied_session_token = request.headers.get(_SESSION_TOKEN_HEADER)
        if supplied_session_token != pending.session_token:
            return self._not_found()

        supplied_write_token = request.headers.get(_WRITE_TOKEN_HEADER)
        if supplied_write_token is None or not hmac.compare_digest(
            self._digest(supplied_write_token),
            pending.write_token_digest,
        ):
            return self._not_found()

        matching_browser_binding = any(
            self.is_valid_browser_binding(browser_binding)
            and hmac.compare_digest(
                self._digest(browser_binding),
                pending.browser_binding_digest,
            )
            for browser_binding in _cookie_values(
                request.headers,
                self.browser_binding_cookie_name,
            )
        )
        if not matching_browser_binding:
            return self._not_found()

        # Consume before constructing the response. There is no await between
        # lookup and pop, so two event-loop tasks cannot both redeem it.
        self._remove_pending(capability)

        response = Response(
            status_code=204,
            headers={"Cache-Control": "no-store"},
        )
        for logical_name, value in pending.cookies.items():
            physical_name = self._physical_cookie_name(logical_name)
            if (
                self.secure_auth_cookie
                and logical_name == _AUTH_TOKEN_LOGICAL_COOKIE_NAME
                and self._is_empty_auth_token(value)
            ):
                self.expire_auth_cookie(response, physical_name)
            else:
                response.set_cookie(
                    physical_name,
                    value,
                    path="/",
                    secure=self.secure_auth_cookie,
                    httponly=True,
                    samesite="lax",
                )

            if (
                self.secure_auth_cookie
                and logical_name == _AUTH_TOKEN_LOGICAL_COOKIE_NAME
            ):
                self.expire_auth_cookie(
                    response,
                    _AUTH_TOKEN_LOGICAL_COOKIE_NAME,
                )
        return response

    def expire_auth_cookie(self, response: Response, name: str) -> None:
        response.delete_cookie(
            name,
            path="/",
            secure=self.secure_auth_cookie,
            httponly=True,
            samesite="lax",
        )

    def _physical_cookie_name(self, logical_name: str) -> str:
        if logical_name == _AUTH_TOKEN_LOGICAL_COOKIE_NAME:
            return self.auth_token_cookie_name
        return logical_name

    @staticmethod
    def _is_empty_auth_token(value: str) -> bool:
        try:
            return json.loads(value) == ""
        except json.JSONDecodeError:
            return False

    def pending_count(self) -> int:
        """Expose only a count for focused lifecycle regression tests."""
        self._discard_expired(self._clock())
        return len(self._pending)

    def discard_cookie_write(self, capability: str) -> None:
        """Invalidate a capability whose client-side delivery failed."""
        self._remove_pending(capability)

    def _discard_expired(self, now: float) -> None:
        expired = [
            capability
            for capability, pending in self._pending.items()
            if pending.expires_at <= now
        ]
        for capability in expired:
            self._remove_pending(capability)

    async def _wait_for_session_registration(
        self,
        session: rio.Session,
    ) -> str | None:
        deadline = time.monotonic() + _SESSION_REGISTRATION_TIMEOUT_SECONDS
        while True:
            session_token = self.server._active_tokens_by_session.get(session)
            if session_token is not None:
                return session_token
            if session._was_closed or session._rio_transport.is_closed:
                return None
            if time.monotonic() >= deadline:
                raise _CookieWriteUnavailable(
                    "Rio session was not registered before the cookie-save timeout"
                )
            await asyncio.sleep(0.01)

    def _expire_capability(
        self,
        capability: str,
        expected: _PendingCookieWrite,
    ) -> None:
        if self._pending.get(capability) is expected:
            self._pending.pop(capability, None)
        self._expiration_handles.pop(capability, None)

    def _remove_pending(self, capability: str) -> None:
        self._pending.pop(capability, None)
        handle = self._expiration_handles.pop(capability, None)
        if handle is not None:
            handle.cancel()

    @staticmethod
    def _digest(value: str) -> bytes:
        return hashlib.sha256(value.encode("utf-8")).digest()

    @staticmethod
    def _not_found() -> Response:
        return Response(status_code=404, headers={"Cache-Control": "no-store"})


async def _save_settings_now_in_hardened_browser(
    self: rio.Session,
    settings_to_save: Iterable[tuple[Any, Iterable[str]]],
) -> None:
    security = getattr(self._app_server, _SECURITY_STATE_ATTRIBUTE, None)
    if security is None:
        original = getattr(type(self), _ORIGINAL_SAVE_ATTRIBUTE)
        await original(self, settings_to_save)
        return

    settings_records = [
        (settings, frozenset(dirty_attributes))
        for settings, dirty_attributes in settings_to_save
    ]
    delta_settings: dict[str, Any] = {}
    cookies: dict[str, str] = {}
    cookie_attributes: list[tuple[Any, frozenset[str]]] = []

    for settings, dirty_attributes in settings_records:
        prefix = f"{settings.section_name}:" if settings.section_name else ""
        annotations = inspection.get_resolved_type_annotations(type(settings))
        dirty_cookie_attributes = frozenset(
            dirty_attributes & settings._rio_attrs_to_save_as_cookies_
        )
        if dirty_cookie_attributes:
            cookie_attributes.append((settings, dirty_cookie_attributes))

        for attr_name in dirty_attributes:
            key = f"{prefix}{attr_name}"
            json_value = serialization.json_serde.as_json(
                getattr(settings, attr_name),
                as_type=annotations[attr_name],
            )

            if attr_name in settings._rio_attrs_to_save_as_cookies_:
                cookies[key] = json.dumps(json_value)
            else:
                delta_settings[key] = json_value

    if delta_settings:
        await self._remote_set_user_settings(delta_settings)

    if not cookies:
        return

    try:
        issued = await security.issue_cookie_write(self, cookies)
    except _CookieWriteUnavailable:
        _restore_cookie_dirty_attributes(self, cookie_attributes)
        logger.warning(
            "Rio HttpOnly settings could not be prepared for browser delivery",
            exc_info=True,
        )
        return

    # Crawler and other terminal server-rendered sessions have no browser
    # capable of redeeming a write. Their ordinary settings were still queued.
    if issued is None:
        return

    capability, write_token = issued
    java_script = _cookie_write_javascript(capability, write_token)
    try:
        await self._evaluate_javascript(java_script)
    except RuntimeError:
        security.discard_cookie_write(capability)
        _restore_cookie_dirty_attributes(self, cookie_attributes)
        logger.warning(
            "Rio HttpOnly settings could not be delivered to the browser",
            exc_info=True,
        )


def _restore_cookie_dirty_attributes(
    session: rio.Session,
    cookie_attributes: Iterable[tuple[Any, frozenset[str]]],
) -> None:
    if session._was_closed or session._rio_transport.is_closed:
        return
    for settings, dirty_attributes in cookie_attributes:
        if settings._rio_session_ is session:
            settings._rio_dirty_attribute_names_.update(dirty_attributes)


def _cookie_write_javascript(capability: str, write_token: str) -> str:
    return (
        "(async () => {"
        "const reportFailure = () => {"
        "console.error('Secure session cookie write failed');"
        "globalThis.dispatchEvent(new Event('rio-cookie-write-failed'));"
        "if (!globalThis.document || "
        "document.getElementById('rio-cookie-write-failure')) return;"
        "const notice = document.createElement('div');"
        "notice.id = 'rio-cookie-write-failure';"
        "notice.setAttribute('role', 'alert');"
        "notice.textContent = 'Your sign-in state could not be saved. ' + "
        "'Please refresh and sign in again.';"
        "notice.style.cssText = 'position:fixed;z-index:2147483647;' + "
        "'left:1rem;right:1rem;bottom:1rem;padding:1rem;' + "
        "'color:white;background:#8b1d1d;border-radius:.5rem;' + "
        "'font:600 14px system-ui,sans-serif;text-align:center';"
        "(document.body || document.documentElement).append(notice);"
        "};"
        "const writeCookie = () => fetch("
        f"{_RIO_COOKIE_ROUTE!r}, {{"
        "method: 'POST', "
        "credentials: 'same-origin', "
        "cache: 'no-store', "
        "keepalive: true, "
        "headers: {"
        f"'{_CAPABILITY_HEADER}': {capability!r}, "
        f"'{_WRITE_TOKEN_HEADER}': {write_token!r}, "
        f"'{_SESSION_TOKEN_HEADER}': globalThis.SESSION_TOKEN"
        "}"
        "});"
        "for (let attempt = 0; attempt < 2; attempt += 1) {"
        "let response;"
        "try { response = await writeCookie(); } catch (error) {"
        "if (attempt === 0) continue;"
        "reportFailure(); return;"
        "}"
        "if (response.ok) return;"
        "if (response.status < 500 || attempt === 1) {"
        "reportFailure(); return;"
        "}"
        "}"
        "})()"
    )


def _install_session_save_patch() -> None:
    session_type = rio.Session
    if not hasattr(session_type, _ORIGINAL_SAVE_ATTRIBUTE):
        original = session_type._save_settings_now_in_browser
        signature = inspect.signature(original)
        if tuple(signature.parameters) != ("self", "settings_to_save"):
            raise RuntimeError(
                "Rio's browser settings save hook has an unexpected signature"
            )
        setattr(session_type, _ORIGINAL_SAVE_ATTRIBUTE, original)

    session_type._save_settings_now_in_browser = (  # type: ignore[method-assign]
        _save_settings_now_in_hardened_browser
    )


def _replace_cookie_route(server: Any, security: RioCookieSecurity) -> None:
    routes = [
        route
        for route in server.router.routes
        if isinstance(route, APIRoute) and route.path == "/rio/cookies/{url}"
    ]
    if len(routes) != 1 or routes[0].methods != {"GET"}:
        raise RuntimeError("Rio's cookie route no longer matches version 0.12.2")

    server.router.routes.remove(routes[0])
    server.add_api_route(
        _RIO_COOKIE_ROUTE,
        security.redeem_cookie_write,
        methods=["POST"],
        include_in_schema=False,
        name="_secure_rio_cookie_write",
    )


def get_rio_cookie_security(server: Any) -> RioCookieSecurity | None:
    """Return the hardened cookie-security state installed on a Rio server."""
    return getattr(server, _SECURITY_STATE_ATTRIBUTE, None)


def browser_binding_digest(value: str) -> str:
    """Return the stable, storage-safe digest for one browser binding."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_browser_binding(
    headers: Headers,
    security: RioCookieSecurity | None,
) -> str | None:
    """Read one self-authenticating browser binding, failing closed otherwise."""
    if security is None:
        return None
    binding = _single_cookie_value(headers, security.browser_binding_cookie_name)
    if not security.is_valid_browser_binding(binding):
        return None
    return binding


def install_rio_cookie_security(
    server: Any,
    *,
    secure_auth_cookie: bool,
    canonical_origin: str | None = None,
    capability_ttl_seconds: float = _DEFAULT_CAPABILITY_TTL_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> RioCookieSecurity:
    """Install the hardened transport on one freshly created Rio server."""
    installed_version = version("rio-ui")
    if installed_version != _SUPPORTED_RIO_VERSION:
        raise RuntimeError(
            "Rio cookie security supports rio-ui "
            f"{_SUPPORTED_RIO_VERSION}, found {installed_version}. "
            "Review the upstream cookie implementation before changing the pin."
        )

    if getattr(server, _SECURITY_STATE_ATTRIBUTE, None) is not None:
        raise RuntimeError("Rio cookie security is already installed")

    security = RioCookieSecurity(
        server,
        secure_auth_cookie=secure_auth_cookie,
        canonical_origin=canonical_origin,
        capability_ttl_seconds=capability_ttl_seconds,
        clock=clock,
    )
    setattr(server, _SECURITY_STATE_ATTRIBUTE, security)
    _replace_cookie_route(server, security)
    _install_session_save_patch()
    server.add_middleware(_BrowserBindingMiddleware, security=security)
    return security
