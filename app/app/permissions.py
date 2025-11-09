"""
Centralized Role Management System

This module is the SINGLE SOURCE OF TRUTH for all role definitions in the application.
All role-related logic should reference this module to ensure consistency.

To customize roles for your application:
1. Edit the ROLE_HIERARCHY dictionary below
2. Add/remove/rename roles as needed
3. Adjust the hierarchy levels (lower number = higher privilege)
4. All other parts of the application will automatically adapt

Example custom hierarchy:
    ROLE_HIERARCHY = {
        "owner": 1,
        "moderator": 2,
        "member": 3,
        "guest": 4
    }
"""

# Role hierarchy from highest to lowest privilege
# Lower number = higher privilege
ROLE_HIERARCHY = {
    "root": 1,
    "admin": 2,
    "user": 3
}

PAGE_ROLE_MAPPING = {
    "/app/dashboard": ["*"],
    "/app/settings": ["*"],
    "/app/enable-mfa": ["*"],
    "/app/disable-mfa": ["*"],
    "/app/recovery-codes": ["*"],
    "/app/notifications": ["*"],
    "/app/admin": ["root", "admin"],
    "/app/test": ["root", "admin"],
    "/app/news": ["root", "admin", "user"],
}

def get_role_level(role: str) -> int:
    """Get the hierarchy level of a role"""
    level = ROLE_HIERARCHY.get(role)
    if level is None:
        raise ValueError(f"Unknown role: {role}")
    return level

def can_manage_role(manager_role: str, target_role: str) -> bool:
    """Check if a user with manager_role can manage users with target_role"""
    return get_role_level(manager_role) < get_role_level(target_role)

def get_manageable_roles(user_role: str) -> list[str]:
    """Get list of roles that can be managed by the given user role"""
    user_level = get_role_level(user_role)
    return [role for role, level in ROLE_HIERARCHY.items() if level > user_level]

def check_access(current_page: str, user_role: str) -> bool:
    """
    Check if a user with the given role has access to the specified page.

    Args:
        current_page: The full path of the page including /app/ prefix
        user_role: The role of the user

    Returns:
        bool: True if the user has access, False otherwise
    """
    # Highest privilege role has access to all pages
    if user_role == get_highest_privilege_role():
        return True

    if current_page in PAGE_ROLE_MAPPING:
        allowed_roles = PAGE_ROLE_MAPPING[current_page]
        if "*" in allowed_roles:
            return True
        return user_role in allowed_roles
    return False

def get_all_roles() -> list[str]:
    """
    Get list of all valid roles defined in the system.

    Returns:
        list[str]: All role names from the hierarchy
    """
    return list(ROLE_HIERARCHY.keys())

def get_default_role() -> str:
    """
    Get the default role assigned to new users.
    This is the role with the lowest privilege (highest number).

    Returns:
        str: The default role name
    """
    return max(ROLE_HIERARCHY.items(), key=lambda x: x[1])[0]

def get_first_user_role() -> str:
    """
    Get the role assigned to the first user who registers.
    This is the role with the highest privilege (lowest number).

    Returns:
        str: The first user role name (typically admin/root)
    """
    return min(ROLE_HIERARCHY.items(), key=lambda x: x[1])[0]

def get_highest_privilege_role() -> str:
    """
    Get the role with the highest privilege level.
    This is the role with the lowest hierarchy number.

    Returns:
        str: The highest privilege role name
    """
    return min(ROLE_HIERARCHY.items(), key=lambda x: x[1])[0]

def validate_role(role: str) -> bool:
    """
    Check if a role is valid and exists in the role hierarchy.

    Args:
        role: The role name to validate

    Returns:
        bool: True if the role exists, False otherwise
    """
    return role in ROLE_HIERARCHY

def is_privileged_role(role: str, min_level: int = 2) -> bool:
    """
    Check if a role meets a minimum privilege threshold.
    Useful for checking if a user is an admin/moderator without hardcoding role names.

    Args:
        role: The role to check
        min_level: The minimum privilege level required (default: 2, typically admin level)
                  Lower numbers = higher privilege

    Returns:
        bool: True if the role's level is <= min_level (has sufficient privilege)

    Example:
        # Check if user is admin-level or higher
        is_privileged_role(user.role, min_level=2)  # True for root(1) and admin(2)
    """
    try:
        return get_role_level(role) <= min_level
    except ValueError:
        return False
