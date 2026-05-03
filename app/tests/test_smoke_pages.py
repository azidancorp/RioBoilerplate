"""
Smoke tests that GET every registered page URL with a crawler User-Agent,
triggering Rio's SSR path. This exercises page imports, guards, and build().
"""
import pytest
from fastapi.testclient import TestClient

import app as app_module
from app.navigation import PUBLIC_NAV_ROUTES, APP_ROUTES
from app.persistence import Persistence

CRAWLER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    smoke_db_path = tmp_path_factory.mktemp("smoke-db") / "app.db"
    original_init = Persistence.__init__
    original_attachments = list(app_module.app.default_attachments)
    original_attachment_ids = {id(attachment) for attachment in original_attachments}

    def init_with_smoke_db(self, db_path=None, *args, **kwargs):
        if db_path is None:
            db_path = smoke_db_path
        original_init(self, db_path, *args, **kwargs)

    Persistence.__init__ = init_with_smoke_db
    try:
        with TestClient(app_module.fastapi_app, raise_server_exceptions=False) as c:
            yield c
    finally:
        Persistence.__init__ = original_init
        for attachment in app_module.app.default_attachments:
            if id(attachment) not in original_attachment_ids and isinstance(
                attachment,
                Persistence,
            ):
                attachment.close()
        app_module.app.default_attachments[:] = original_attachments


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
