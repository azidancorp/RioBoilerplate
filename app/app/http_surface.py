from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from xml.etree import ElementTree

from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.routing import APIRoute
from starlette.routing import Match

from app.config import config
from app.navigation import APP_ROUTES, PUBLIC_NAV_ROUTES


_RIO_INDEX_ROUTE_NAME = "_serve_index"
_KNOWN_PAGE_PATHS = frozenset(
    route.path for route in (*PUBLIC_NAV_ROUTES, *APP_ROUTES)
)
_SITEMAP_NAMESPACE = "http://www.sitemaps.org/schemas/sitemap/0.9"


def _documented_routes(routes: Iterable[Any]) -> list[APIRoute]:
    return [
        route
        for route in routes
        if (
            isinstance(route, APIRoute)
            and route.include_in_schema
            and route.path.startswith(("/api/", "/auth/"))
        )
    ]


def _matches_explicit_route(app: FastAPI, request: Request) -> bool:
    for route in app.routes:
        if getattr(route, "name", None) == _RIO_INDEX_ROUTE_NAME:
            continue
        match, _ = route.matches(request.scope)
        if match in {Match.FULL, Match.PARTIAL}:
            return True
    return False


def _robots_response() -> PlainTextResponse:
    base_url = config.APP_URL.rstrip("/")
    body = "\n".join(
        (
            "User-agent: *",
            "Allow: /",
            "Disallow: /app/",
            "Disallow: /api/",
            "Disallow: /auth/",
            "Disallow: /rio/",
            "Disallow: /login",
            f"Sitemap: {base_url}/sitemap.xml",
            "",
        )
    )
    return PlainTextResponse(body)


def _public_sitemap_response() -> PlainTextResponse:
    base_url = config.APP_URL.rstrip("/")
    ElementTree.register_namespace("", _SITEMAP_NAMESPACE)
    urlset = ElementTree.Element(f"{{{_SITEMAP_NAMESPACE}}}urlset")
    for route in PUBLIC_NAV_ROUTES:
        if route.path == "/login":
            continue
        url = ElementTree.SubElement(urlset, f"{{{_SITEMAP_NAMESPACE}}}url")
        location = ElementTree.SubElement(
            url,
            f"{{{_SITEMAP_NAMESPACE}}}loc",
        )
        location.text = f"{base_url}{route.path}"
    xml = ElementTree.tostring(
        urlset,
        encoding="unicode",
        xml_declaration=False,
    )
    return PlainTextResponse(xml, media_type="application/xml")


def install_http_surface(app: FastAPI) -> None:
    """Expose API documentation and keep Rio's SPA fallback page-aware."""
    if getattr(app.state, "http_surface_installed", False):
        return
    app.state.http_surface_installed = True

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_document() -> JSONResponse:
        schema = get_openapi(
            title="RioBoilerplate API",
            version="1.0.0",
            routes=_documented_routes(app.routes),
        )
        return JSONResponse(schema)

    @app.get("/docs", include_in_schema=False)
    async def swagger_documentation():
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title="RioBoilerplate API documentation",
        )

    @app.get("/redoc", include_in_schema=False)
    async def redoc_documentation():
        return get_redoc_html(
            openapi_url="/openapi.json",
            title="RioBoilerplate API documentation",
        )

    @app.middleware("http")
    async def reject_unknown_http_paths(request: Request, call_next):
        path = request.url.path
        if path == "/robots.txt":
            return _robots_response()
        if path in {"/sitemap.xml", "/rio/sitemap.xml"}:
            return _public_sitemap_response()
        if path in _KNOWN_PAGE_PATHS or _matches_explicit_route(app, request):
            return await call_next(request)

        if path == "/api" or path.startswith("/api/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        if path == "/auth" or path.startswith("/auth/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        return PlainTextResponse("Not Found", status_code=404)
