# Role hierarchy from highest to lowest
ROLE_HIERARCHY = {
    "user": 3,
    "admin": 2,
    "root": 1
}

PAGE_ROLE_MAPPING = {
    "/app/dashboard": ["root", "admin", "user"],
    "/app/news": ["root", "admin"],
    "/app/test": ["root", "admin", "user"],
    "/app/settings": ["root", "admin", "user"],
    "/app/enable-mfa": ["root", "admin", "user"],
    "/app/disable-mfa": ["root", "admin", "user"],
    "/app/admin": ["root", "admin", "user"],
    "/app/notifications": ["root", "admin", "user"],
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
    if current_page in PAGE_ROLE_MAPPING:
        allowed_roles = PAGE_ROLE_MAPPING[current_page]
        return user_role in allowed_roles
    return False