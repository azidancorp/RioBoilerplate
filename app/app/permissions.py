PAGE_ROLE_MAPPING = {
    "/app/dashboard": ["admin", "user"],
    "/app/news": ["admin"],
    "/app/test": ["admin", "user"],
    "/app/settings": ["admin", "user"],
    "/app/enable-mfa": ["admin", "user"],
    "/app/disable-mfa": ["admin", "user"],
    "/app/admin": ["admin", "user"],
}

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