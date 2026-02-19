"""
Smoke tests that GET every registered page URL with a crawler User-Agent,
triggering Rio's SSR path. This exercises page imports, guards, and build().
"""
import pytest
from fastapi.testclient import TestClient

from app import fastapi_app
from app.navigation import PUBLIC_NAV_ROUTES, APP_ROUTES

CRAWLER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@pytest.fixture(scope="module")
def client():
    with TestClient(fastapi_app, raise_server_exceptions=False) as c:
        yield c


# Parametrize over public routes
@pytest.mark.parametrize("route", PUBLIC_NAV_ROUTES, ids=lambda r: r.path)
def test_public_page_renders(client, route):
    """Public pages should return 200 with rendered SSR content."""
    resp = client.get(route.path, headers={"User-Agent": CRAWLER_UA})
    assert resp.status_code == 200, f"{route.path} returned {resp.status_code}"
    assert "initialMessages" in resp.text


# Parametrize over authenticated routes
@pytest.mark.parametrize("route", APP_ROUTES, ids=lambda r: r.path)
def test_authenticated_page_guard(client, route):
    """Auth pages should redirect (guard) or return 200, never 500."""
    resp = client.get(
        route.path, headers={"User-Agent": CRAWLER_UA}, follow_redirects=False
    )
    assert resp.status_code != 500, f"{route.path} returned 500 (server error)"
