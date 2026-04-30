from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.config import config
from app.data_models import AppUser, UserSession
from app.rate_limits import normalize_rate_limit_value


@dataclass(frozen=True)
class RequestContext:
    client_ip: str
    user_agent: str = ""
    session_id: str = ""
    user_id: str = ""
    identifier: str = ""
    source: str = "unknown"


def _headers_to_lower(headers: Mapping[str, Any] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _trusted_proxy_values() -> set[str]:
    return {
        normalize_rate_limit_value(value)
        for value in config.RATE_LIMIT_TRUSTED_PROXIES.split(",")
        if value.strip()
    }


def _is_trusted_proxy(peer_ip: str) -> bool:
    normalized = normalize_rate_limit_value(peer_ip)
    if normalized in _trusted_proxy_values():
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback and "127.0.0.1" in _trusted_proxy_values()
    except ValueError:
        return False


def _parse_forwarded_candidate(candidate: str) -> str | None:
    candidate = candidate.strip()
    if not candidate:
        return None
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def resolve_client_ip(
    *,
    peer_ip: str | None,
    headers: Mapping[str, Any] | None = None,
) -> str:
    fallback = normalize_rate_limit_value(peer_ip or "unknown")
    if not config.RATE_LIMIT_TRUST_PROXY_HEADERS or not _is_trusted_proxy(fallback):
        return fallback

    lower_headers = _headers_to_lower(headers)
    real_ip = lower_headers.get("x-real-ip")
    if real_ip:
        parsed = _parse_forwarded_candidate(real_ip)
        if parsed:
            return normalize_rate_limit_value(parsed)

    forwarded_for = lower_headers.get("x-forwarded-for")
    if forwarded_for:
        for candidate in forwarded_for.split(","):
            parsed = _parse_forwarded_candidate(candidate)
            if parsed:
                return normalize_rate_limit_value(parsed)

    return fallback


def context_from_rio_session(
    session: Any,
    *,
    identifier: str = "",
    user_id: object = "",
) -> RequestContext:
    headers = getattr(session, "http_headers", {}) or {}
    peer_ip = getattr(session, "client_ip", "") or "local-session"
    session_id = str(getattr(session, "id", "") or getattr(session, "session_id", "") or "")
    resolved_user_id = str(user_id or "")

    if not resolved_user_id:
        try:
            user_session = session[UserSession]
            resolved_user_id = str(user_session.user_id)
            if not session_id:
                session_id = user_session.id
        except KeyError:
            pass

    if not identifier:
        try:
            user = session[AppUser]
            identifier = user.email
            if not resolved_user_id:
                resolved_user_id = str(user.id)
        except KeyError:
            pass

    return RequestContext(
        client_ip=resolve_client_ip(peer_ip=str(peer_ip), headers=headers),
        user_agent=str(getattr(session, "user_agent", "") or headers.get("user-agent", "") or ""),
        session_id=session_id,
        user_id=resolved_user_id,
        identifier=identifier,
        source="rio",
    )


def context_from_fastapi_request(
    request: Any,
    *,
    identifier: str = "",
    user: AppUser | None = None,
    user_session: UserSession | None = None,
) -> RequestContext:
    peer_ip = ""
    if getattr(request, "client", None) and request.client.host:
        peer_ip = str(request.client.host)

    headers = getattr(request, "headers", {}) or {}
    session_id = user_session.id if user_session else ""
    user_id = str(user.id if user else user_session.user_id if user_session else "")
    if not identifier and user:
        identifier = user.email

    return RequestContext(
        client_ip=resolve_client_ip(peer_ip=peer_ip, headers=headers),
        user_agent=str(headers.get("user-agent", "") or ""),
        session_id=session_id,
        user_id=user_id,
        identifier=identifier,
        source="fastapi",
    )
