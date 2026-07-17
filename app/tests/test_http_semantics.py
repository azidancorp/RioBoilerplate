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
    api_post_response = client.post("/api/nope")
    auth_response = client.get("/auth/nope")
    browser_post_response = client.post("/does-not-exist")

    assert browser_response.status_code == 404
    assert browser_response.headers["content-type"].startswith("text/plain")
    assert browser_response.text == "Not Found"
    assert api_response.status_code == 404
    assert api_response.json() == {"detail": "Not Found"}
    assert api_post_response.status_code == 404
    assert api_post_response.json() == {"detail": "Not Found"}
    assert "allow" not in api_post_response.headers
    assert auth_response.status_code == 404
    assert auth_response.json() == {"detail": "Not Found"}
    assert browser_post_response.status_code == 404
    assert browser_post_response.text == "Not Found"
    assert "allow" not in browser_post_response.headers


def test_known_pages_keep_their_normal_semantics(client):
    public_page = client.get("/about")
    protected_page = client.get("/app/settings", follow_redirects=False)

    assert public_page.status_code == 200
    assert public_page.headers["content-type"].startswith("text/html")
    assert protected_page.status_code in {200, 302, 307}


@pytest.mark.parametrize(
    ("method", "path", "allow"),
    (
        ("GET", "/api/contact", "POST"),
        ("GET", "/api/currency/adjust", "POST"),
        ("GET", "/api/currency/set", "POST"),
        ("GET", "/rio/upload/probe", "PUT"),
        ("POST", "/api/health", "GET"),
        ("POST", "/auth/google/login", "GET"),
        ("POST", "/about", "GET"),
        ("POST", "/app/settings", "GET"),
        ("POST", "/rio/favicon.png", "GET"),
        ("PATCH", "/api/profiles", "GET, POST"),
        (
            "PATCH",
            "/api/profiles/00000000-0000-0000-0000-000000000000",
            "DELETE, GET, PUT",
        ),
        ("POST", "/robots.txt", "GET, HEAD"),
        ("POST", "/sitemap.xml", "GET, HEAD"),
        ("POST", "/rio/sitemap.xml", "GET, HEAD"),
    ),
)
def test_known_routes_reject_wrong_methods(client, method, path, allow):
    client.cookies.clear()
    response = client.request(method, path)

    assert response.status_code == 405
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["allow"] == allow
    assert response.json() == {"detail": "Method Not Allowed"}
    assert "rio-browser-binding" not in response.headers.get("set-cookie", "")


@pytest.mark.parametrize(
    "path",
    ("/robots.txt", "/sitemap.xml", "/rio/sitemap.xml"),
)
def test_crawler_files_answer_head_requests(client, path):
    client.cookies.clear()
    response = client.head(path)

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("GET", "/rio/cookies"),
        ("HEAD", "/rio/cookies"),
        ("GET", "/rio/cookies/guessed"),
        ("HEAD", "/rio/cookies/guessed"),
    ),
)
def test_cookie_write_wrong_methods_keep_hardened_response(client, method, path):
    client.cookies.clear()
    response = client.request(method, path)

    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert response.headers["cache-control"] == "no-store"
    assert response.content == b""
    assert response.headers.get_list("set-cookie") == []


def test_docs_and_openapi_describe_only_the_application_api_surface(client):
    client.cookies.clear()
    docs = client.get("/docs")
    redoc = client.get("/redoc")
    openapi = client.get("/openapi.json")

    assert docs.status_code == 200
    assert "SwaggerUIBundle" in docs.text
    assert "rio-browser-binding" not in docs.headers.get("set-cookie", "")
    assert redoc.status_code == 200
    assert "redoc" in redoc.text.lower()
    assert "rio-browser-binding" not in redoc.headers.get("set-cookie", "")
    assert openapi.status_code == 200
    assert openapi.headers["content-type"].startswith("application/json")
    assert "rio-browser-binding" not in openapi.headers.get("set-cookie", "")

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
