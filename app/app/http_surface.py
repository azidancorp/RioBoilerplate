from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.routing import APIRoute
from starlette.routing import Match

from app.navigation import APP_ROUTES, PUBLIC_NAV_ROUTES


_RIO_INDEX_ROUTE_NAME = "_serve_index"
_KNOWN_PAGE_PATHS = frozenset(
    route.path for route in (*PUBLIC_NAV_ROUTES, *APP_ROUTES)
)


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
        if path in _KNOWN_PAGE_PATHS or _matches_explicit_route(app, request):
            return await call_next(request)

        if path == "/api" or path.startswith("/api/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        if path == "/auth" or path.startswith("/auth/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        return PlainTextResponse("Not Found", status_code=404)
