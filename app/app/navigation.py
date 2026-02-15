from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AppRoute:
    path: str
    allowed_roles: tuple[str, ...]
    sidebar_title: str | None = None
    sidebar_icon: str | None = None

    @property
    def show_in_sidebar(self) -> bool:
        return self.sidebar_title is not None and self.sidebar_icon is not None


@dataclass(frozen=True, slots=True)
class PublicNavRoute:
    title: str
    path: str
    show_in_desktop_nav: bool = True
    show_in_mobile_drawer: bool = True


APP_ROUTES: tuple[AppRoute, ...] = (
    AppRoute(
        path="/app/dashboard",
        allowed_roles=("*",),
        sidebar_title="Dashboard",
        sidebar_icon="dashboard",
    ),
    AppRoute(
        path="/app/admin",
        allowed_roles=("root", "admin"),
        sidebar_title="Admin",
        sidebar_icon="admin-panel-settings",
    ),
    AppRoute(
        path="/app/currency-playground",
        allowed_roles=("root", "admin"),
        sidebar_title="Currency",
        sidebar_icon="science",
    ),
    AppRoute(
        path="/app/news",
        allowed_roles=("root", "admin", "user"),
        sidebar_title="News",
        sidebar_icon="newspaper",
    ),
    AppRoute(
        path="/app/notifications",
        allowed_roles=("*",),
        sidebar_title="Notifications",
        sidebar_icon="notifications",
    ),
    AppRoute(
        path="/app/settings",
        allowed_roles=("*",),
        sidebar_title="Settings",
        sidebar_icon="settings",
    ),
    AppRoute(
        path="/app/enable-mfa",
        allowed_roles=("*",),
    ),
    AppRoute(
        path="/app/disable-mfa",
        allowed_roles=("*",),
    ),
    AppRoute(
        path="/app/recovery-codes",
        allowed_roles=("*",),
    ),
)


PUBLIC_NAV_ROUTES: tuple[PublicNavRoute, ...] = (
    PublicNavRoute(
        title="Home",
        path="/",
        show_in_desktop_nav=False,
    ),
    PublicNavRoute(
        title="About",
        path="/about",
    ),
    PublicNavRoute(
        title="FAQ",
        path="/faq",
    ),
    PublicNavRoute(
        title="Pricing",
        path="/pricing",
    ),
    PublicNavRoute(
        title="Contact",
        path="/contact",
    ),
    PublicNavRoute(
        title="Login / Signup",
        path="/login",
        show_in_desktop_nav=False,
    ),
)


def get_page_role_mapping(routes: tuple[AppRoute, ...] = APP_ROUTES) -> dict[str, list[str]]:
    return {route.path: list(route.allowed_roles) for route in routes}


def get_sidebar_links(routes: tuple[AppRoute, ...] = APP_ROUTES) -> list[tuple[str, str, str]]:
    links: list[tuple[str, str, str]] = []
    for route in routes:
        if route.sidebar_title is None or route.sidebar_icon is None:
            continue
        links.append((route.sidebar_title, route.path, route.sidebar_icon))
    return links


def get_public_desktop_links(
    routes: tuple[PublicNavRoute, ...] = PUBLIC_NAV_ROUTES,
) -> list[tuple[str, str]]:
    return [
        (route.title, route.path)
        for route in routes
        if route.show_in_desktop_nav
    ]


def get_public_mobile_drawer_links(
    routes: tuple[PublicNavRoute, ...] = PUBLIC_NAV_ROUTES,
) -> list[tuple[str, str]]:
    return [
        (route.title, route.path)
        for route in routes
        if route.show_in_mobile_drawer
    ]


def get_public_login_link(
    routes: tuple[PublicNavRoute, ...] = PUBLIC_NAV_ROUTES,
) -> tuple[str, str]:
    for route in routes:
        if route.path == "/login":
            return (route.title, route.path)
    raise ValueError("Missing public login route '/login'")


def _validate_routes(routes: tuple[AppRoute, ...] = APP_ROUTES) -> None:
    seen_paths: set[str] = set()
    for route in routes:
        if not route.path.startswith("/app/"):
            raise ValueError(f"Route path must start with '/app/': {route.path}")
        if route.path in seen_paths:
            raise ValueError(f"Duplicate route path: {route.path}")
        seen_paths.add(route.path)

        if route.show_in_sidebar:
            if not route.sidebar_title or not route.sidebar_icon:
                raise ValueError(
                    f"Sidebar route must set title and icon: {route.path}"
                )


def _validate_public_routes(routes: tuple[PublicNavRoute, ...] = PUBLIC_NAV_ROUTES) -> None:
    seen_paths: set[str] = set()
    login_route_count = 0

    for route in routes:
        if not route.path.startswith("/"):
            raise ValueError(f"Public route path must start with '/': {route.path}")

        if route.path in seen_paths:
            raise ValueError(f"Duplicate public route path: {route.path}")
        seen_paths.add(route.path)

        if route.path == "/login":
            login_route_count += 1

    if login_route_count != 1:
        raise ValueError("Expected exactly one public login route at '/login'")


_validate_routes()
_validate_public_routes()
