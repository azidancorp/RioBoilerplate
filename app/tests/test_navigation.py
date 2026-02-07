from app.navigation import (
    get_page_role_mapping,
    get_public_desktop_links,
    get_public_login_link,
    get_public_mobile_drawer_links,
    get_sidebar_links,
)
from app.permissions import PAGE_ROLE_MAPPING, get_all_roles


def test_page_role_mapping_is_derived_from_navigation():
    assert PAGE_ROLE_MAPPING == get_page_role_mapping()


def test_all_allowed_roles_exist():
    valid_roles = set(get_all_roles())
    mapping = get_page_role_mapping()

    for path, roles in mapping.items():
        assert roles, f"Expected roles for {path}"
        for role in roles:
            assert role == "*" or role in valid_roles


def test_sidebar_links_are_always_guarded():
    mapping = get_page_role_mapping()
    for _, path, _ in get_sidebar_links():
        assert path in mapping


def test_public_links_consistent_between_desktop_and_mobile():
    desktop_links = dict(get_public_desktop_links())
    mobile_links = dict(get_public_mobile_drawer_links())

    # The mobile drawer should include everything from the desktop public nav.
    for title, path in desktop_links.items():
        assert mobile_links.get(title) == path


def test_public_login_link_is_defined_in_mobile_nav():
    login_title, login_path = get_public_login_link()
    mobile_links = dict(get_public_mobile_drawer_links())

    assert login_path == "/login"
    assert mobile_links.get(login_title) == login_path
