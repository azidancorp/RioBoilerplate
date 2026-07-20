from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

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
    ("method", "path", "expected_status"),
    (
        ("GET", "/login", 200),
        ("GET", "/login?probe=SENTINEL-not-a-real-value", 200),
        ("GET", "/login/?probe=SENTINEL-not-a-real-value", 404),
        ("GET", "/app/settings", 200),
        ("GET", "/app/settings/?probe=SENTINEL-not-a-real-value", 404),
        ("GET", "/auth/nope", 404),
        ("POST", "/login", 405),
    ),
)
def test_sensitive_paths_send_no_store_and_no_referrer(
    client, method, path, expected_status
):
    client.cookies.clear()
    response = client.request(method, path)

    assert response.status_code == expected_status
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


def _request_temporary_route(client, route_path, endpoint):
    routes = app_module.fastapi_app.router.routes
    original_routes = list(routes)

    try:
        app_module.fastapi_app.add_api_route(
            route_path,
            endpoint,
            methods=["GET"],
            include_in_schema=False,
        )
        # Rio's SPA catch-all route is already registered, so the test route
        # must sit in front of it to receive the request.
        routes.insert(0, routes.pop())
        return client.get(route_path, follow_redirects=False)
    finally:
        routes[:] = original_routes


def test_uncaught_errors_on_sensitive_paths_keep_no_store_headers(client):
    async def boom() -> None:
        raise RuntimeError("uncaught test error")

    response = _request_temporary_route(
        client,
        "/auth/_test_uncaught_error",
        boom,
    )

    assert response.status_code == 500
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_redirects_from_sensitive_paths_keep_no_store_headers(client):
    async def redirect_to_login() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    response = _request_temporary_route(
        client,
        "/auth/_test_sensitive_redirect",
        redirect_to_login,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


@pytest.mark.parametrize(
    "path",
    ("/", "/api/nope", "/login-old?probe=SENTINEL"),
)
def test_non_sensitive_paths_keep_default_referrer_policy(client, path):
    client.cookies.clear()
    response = client.get(path)

    assert "referrer-policy" not in response.headers
    assert "cache-control" not in response.headers


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


def test_openapi_declares_exact_bearer_security_boundary(client):
    client.cookies.clear()
    schema = client.get("/openapi.json").json()

    security_schemes = schema["components"]["securitySchemes"]
    assert set(security_schemes) == {"SessionBearer"}
    scheme = security_schemes["SessionBearer"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    assert "External API clients are not supported" in scheme["description"]
    assert "security" not in schema

    http_methods = {
        "get",
        "put",
        "post",
        "delete",
        "options",
        "head",
        "patch",
        "trace",
    }
    operations = {
        (method.upper(), path): operation
        for path, path_item in schema["paths"].items()
        for method, operation in path_item.items()
        if method in http_methods
    }
    protected = {
        ("GET", "/api/profiles"),
        ("POST", "/api/profiles"),
        ("GET", "/api/profiles/{user_id}"),
        ("PUT", "/api/profiles/{user_id}"),
        ("DELETE", "/api/profiles/{user_id}"),
        ("GET", "/api/currency/balance"),
        ("GET", "/api/currency/ledger"),
        ("POST", "/api/currency/adjust"),
        ("POST", "/api/currency/set"),
    }
    without_session_bearer = {
        ("GET", "/auth/{provider}/login"),
        ("GET", "/auth/{provider}/delete-account"),
        ("GET", "/auth/{provider}/delete-account/callback"),
        ("GET", "/auth/{provider}/mfa/{purpose}"),
        ("GET", "/auth/{provider}/mfa/{purpose}/callback"),
        ("GET", "/auth/{provider}/callback"),
        ("GET", "/api/test"),
        ("POST", "/api/contact"),
        ("GET", "/api/currency/config"),
        ("GET", "/api/health"),
    }

    assert set(operations) == protected | without_session_bearer
    for key in protected:
        assert operations[key]["security"] == [{"SessionBearer": []}]
    for key in without_session_bearer:
        assert "security" not in operations[key]

    parameter_groups = [
        path_item.get("parameters", ())
        for path_item in schema["paths"].values()
    ] + [
        operation.get("parameters", ())
        for operation in operations.values()
    ]
    for parameters in parameter_groups:
        assert not any(
            parameter.get("in") == "header"
            and parameter.get("name", "").casefold() == "authorization"
            for parameter in parameters
        )


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
