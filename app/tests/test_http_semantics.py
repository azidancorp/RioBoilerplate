from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient

import app as app_module
from app.config import config
from app.navigation import PUBLIC_NAV_ROUTES
from app.persistence import Persistence


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("http-semantics") / "app.db"
    original_init = Persistence.__init__
    original_attachments = list(app_module.app.default_attachments)
    original_attachment_ids = {id(value) for value in original_attachments}

    def init_with_temp_db(self, requested_path=None, *args, **kwargs):
        requested_path = requested_path or kwargs.pop("db_path", None) or db_path
        original_init(self, requested_path, *args, **kwargs)

    Persistence.__init__ = init_with_temp_db
    try:
        with TestClient(
            app_module.fastapi_app,
            raise_server_exceptions=False,
        ) as test_client:
            yield test_client
    finally:
        Persistence.__init__ = original_init
        for attachment in app_module.app.default_attachments:
            if (
                id(attachment) not in original_attachment_ids
                and isinstance(attachment, Persistence)
            ):
                attachment.close()
        app_module.app.default_attachments[:] = original_attachments


def test_unknown_browser_and_api_paths_return_real_404_responses(client):
    browser_response = client.get(
        "/does-not-exist",
        headers={"Accept": "text/html"},
    )
    api_response = client.get("/api/nope")
    auth_response = client.get("/auth/nope")

    assert browser_response.status_code == 404
    assert browser_response.headers["content-type"].startswith("text/plain")
    assert browser_response.text == "Not Found"
    assert api_response.status_code == 404
    assert api_response.json() == {"detail": "Not Found"}
    assert auth_response.status_code == 404
    assert auth_response.json() == {"detail": "Not Found"}


def test_known_pages_and_wrong_api_methods_keep_their_normal_semantics(client):
    public_page = client.get("/about")
    protected_page = client.get("/app/settings", follow_redirects=False)
    wrong_method = client.post("/api/health")

    assert public_page.status_code == 200
    assert public_page.headers["content-type"].startswith("text/html")
    assert protected_page.status_code in {200, 302, 307}
    assert wrong_method.status_code == 405


def test_docs_and_openapi_describe_only_the_application_api_surface(client):
    docs = client.get("/docs")
    redoc = client.get("/redoc")
    openapi = client.get("/openapi.json")

    assert docs.status_code == 200
    assert "SwaggerUIBundle" in docs.text
    assert redoc.status_code == 200
    assert "redoc" in redoc.text.lower()
    assert openapi.status_code == 200
    assert openapi.headers["content-type"].startswith("application/json")

    schema = openapi.json()
    assert schema["openapi"]
    assert "/api/health" in schema["paths"]
    assert "/auth/{provider}/login" in schema["paths"]
    assert all(
        path.startswith(("/api/", "/auth/"))
        for path in schema["paths"]
    )
    assert not any(path.startswith("/rio/") for path in schema["paths"])


def test_robots_points_to_the_canonical_public_sitemap(client):
    response = client.get("/robots.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert f"Sitemap: {config.APP_URL.rstrip('/')}/sitemap.xml" in response.text
    assert "/robots.txt/rio/sitemap.xml" not in response.text
    for private_prefix in ("/app/", "/api/", "/auth/", "/rio/", "/login"):
        assert f"Disallow: {private_prefix}" in response.text


def test_sitemap_contains_only_public_marketing_pages(client):
    public_sitemap = client.get("/sitemap.xml")
    legacy_sitemap = client.get("/rio/sitemap.xml")

    assert public_sitemap.status_code == 200
    assert public_sitemap.headers["content-type"].startswith("application/xml")
    assert legacy_sitemap.status_code == 200
    assert legacy_sitemap.text == public_sitemap.text

    root = ElementTree.fromstring(public_sitemap.text)
    namespace = {"sitemap": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locations = [
        node.text
        for node in root.findall("sitemap:url/sitemap:loc", namespace)
    ]
    expected = [
        f"{config.APP_URL.rstrip('/')}{route.path}"
        for route in PUBLIC_NAV_ROUTES
        if route.path != "/login"
    ]
    assert locations == expected
    assert all("/app/" not in location for location in locations)
