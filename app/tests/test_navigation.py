from app.navigation import get_page_role_mapping, get_sidebar_links
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

