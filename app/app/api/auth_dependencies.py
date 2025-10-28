"""
Authentication and Authorization Dependencies for FastAPI Endpoints

This module provides reusable FastAPI dependencies for securing API endpoints.
Since FastAPI runs outside Rio's session context, we need to validate sessions
via HTTP headers rather than Rio's session attachment system.

Usage:
    @router.get("/api/profile/{user_id}")
    async def get_profile(user_id: str, current_user = Depends(get_current_user)):
        # current_user is authenticated AppUser object
        ...

Client must send: Authorization: Bearer <session_token>
In Rio apps, token is stored in UserSettings.auth_token.
"""

from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status, Header

from app.data_models import AppUser, UserSession
from app.persistence import Persistence
from app.permissions import get_role_level, is_privileged_role


# ============================================================================
# Authentication Dependencies
# ============================================================================

async def get_persistence() -> AsyncGenerator[Persistence, None]:
    """
    Create a Persistence instance for database operations.

    Note: FastAPI endpoints run outside Rio's session context, so we cannot use
    session[Persistence]. Creating a new instance here is the correct pattern.
    """
    db = Persistence()
    try:
        yield db
    finally:
        db.close()


async def get_current_session(
    authorization: Annotated[str | None, Header()] = None,
    db: Persistence = Depends(get_persistence)
) -> UserSession:
    """
    Validate Bearer token from Authorization header and return UserSession.

    Raises HTTPException 401 if token is missing, invalid, or expired.
    """
    # Check if Authorization header is present
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract the Bearer token
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials format. Expected: 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]

    # Validate the session token
    try:
        user_session = await db.get_session_by_auth_token(token)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if the session is still valid
    if user_session.valid_until <= datetime.now(tz=timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user_session


async def get_current_user(
    session: UserSession = Depends(get_current_session),
    db: Persistence = Depends(get_persistence)
) -> AppUser:
    """
    Get full AppUser object for authenticated user.

    Raises HTTPException 401 if user not found.
    """
    try:
        user = await db.get_user_by_id(session.user_id)
        return user
    except KeyError:
        # This should never happen if the session is valid, but handle it anyway
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================================
# Authorization Helpers
# ============================================================================

def is_admin_or_root(user: AppUser) -> bool:
    """
    Check if user has admin or higher privileges.

    Uses the role hierarchy to determine if user has sufficient privileges
    without hardcoding role names.
    """
    return is_privileged_role(user.role, min_level=2)


def require_self_or_admin(
    target_user_id: str,
    current_user: AppUser
) -> None:
    """
    Verify user is accessing their own resource or has admin privileges.

    Primary authorization check for modify operations (update, delete).
    Users can only modify their own resources unless they're an admin/root.
    Raises HTTPException 403 if unauthorized.
    
    Example:
        ```python
        @router.put("/api/profile/{user_id}")
        async def update_profile(
            user_id: str,
            current_user: AppUser = Depends(get_current_user)
        ):
            require_self_or_admin(user_id, current_user)
            # User is authorized, proceed with update
            ...
        ```
    """
    current_user_id_str = str(current_user.id)
    is_self = current_user_id_str == target_user_id
    is_admin = is_admin_or_root(current_user)

    if not (is_self or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource"
        )


def check_role_hierarchy(
    manager_user: AppUser,
    target_role: str
) -> None:
    """
    Verify user has sufficient privileges to manage target_role.

    Uses role hierarchy from permissions.py. Users can only manage lower privilege levels.
    Example: admin (level 2) can manage users (level 3) but not root (level 1).
    Raises HTTPException 403 if insufficient privileges.
    """
    manager_level = get_role_level(manager_user.role)
    target_level = get_role_level(target_role)

    if manager_level >= target_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient privileges to manage users with role '{target_role}'"
        )


# ============================================================================
# Extension Points
# TODO: Review this section
# ============================================================================

"""
EXTENDING FOR PROFILE VISIBILITY:

To implement public/private profiles, you would:

1. Add a column to the profiles table:
   ```sql
   ALTER TABLE profiles ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT 0;
   ```

2. Create a visibility check function:
   ```python
   async def check_profile_visibility(
       target_user_id: str,
       current_user: AppUser,
       db: Persistence
   ) -> bool:
       # Admin/Root can always view
       if is_admin_or_root(current_user):
           return True

       # Users can always view their own profile
       if str(current_user.id) == target_user_id:
           return True

       # Check if the profile is public
       profile = await db.get_profile_by_user_id(target_user_id)
       if profile and profile.get('is_public', False):
           return True

       return False
   ```

3. Use it in endpoints:
   ```python
   @router.get("/api/profile/{user_id}")
   async def get_profile(
       user_id: str,
       current_user: AppUser = Depends(get_current_user),
       db: Persistence = Depends(get_persistence)
   ):
       if not await check_profile_visibility(user_id, current_user, db):
           raise HTTPException(status_code=403, detail="Profile is private")

       return await db.get_profile_by_user_id(user_id)
   ```


EXTENDING FOR CONNECTIONS/FRIENDS:

To implement connection-based access, you would:

1. Create a connections table:
   ```sql
   CREATE TABLE user_connections (
       id INTEGER PRIMARY KEY,
       user_id TEXT NOT NULL,
       connected_user_id TEXT NOT NULL,
       status TEXT NOT NULL DEFAULT 'pending',  -- 'pending', 'accepted', 'blocked'
       created_at REAL NOT NULL,
       FOREIGN KEY (user_id) REFERENCES users(id),
       FOREIGN KEY (connected_user_id) REFERENCES users(id),
       UNIQUE(user_id, connected_user_id)
   );
   ```

2. Create a connection check function:
   ```python
   async def are_users_connected(
       user_id1: str,
       user_id2: str,
       db: Persistence
   ) -> bool:
       cursor = db._get_cursor()
       cursor.execute(
           '''
           SELECT COUNT(*) FROM user_connections
           WHERE ((user_id = ? AND connected_user_id = ?)
                  OR (user_id = ? AND connected_user_id = ?))
           AND status = 'accepted'
           ''',
           (user_id1, user_id2, user_id2, user_id1)
       )
       count = cursor.fetchone()[0]
       return count > 0
   ```

3. Combine with visibility checks:
   ```python
   async def can_view_profile(
       target_user_id: str,
       current_user: AppUser,
       db: Persistence
   ) -> bool:
       # Self, admin, or public profile
       if await check_profile_visibility(target_user_id, current_user, db):
           return True

       # Check if they're connected
       if await are_users_connected(str(current_user.id), target_user_id, db):
           return True

       return False
   ```


ADVANCED PERMISSION SCENARIOS:

For more complex scenarios (e.g., team-based access, organization hierarchies):

1. Create permission tables:
   ```sql
   CREATE TABLE resource_permissions (
       id INTEGER PRIMARY KEY,
       resource_type TEXT NOT NULL,  -- 'profile', 'document', etc.
       resource_id TEXT NOT NULL,
       user_id TEXT NOT NULL,
       permission TEXT NOT NULL,  -- 'read', 'write', 'admin'
       granted_at REAL NOT NULL,
       FOREIGN KEY (user_id) REFERENCES users(id)
   );
   ```

2. Create flexible permission checks:
   ```python
   async def has_permission(
       user_id: str,
       resource_type: str,
       resource_id: str,
       required_permission: str,
       db: Persistence
   ) -> bool:
       cursor = db._get_cursor()
       cursor.execute(
           '''
           SELECT permission FROM resource_permissions
           WHERE user_id = ? AND resource_type = ? AND resource_id = ?
           ''',
           (user_id, resource_type, resource_id)
       )
       result = cursor.fetchone()
       if not result:
           return False

       # Define permission hierarchy
       permissions_hierarchy = {'read': 1, 'write': 2, 'admin': 3}
       user_permission_level = permissions_hierarchy.get(result[0], 0)
       required_level = permissions_hierarchy.get(required_permission, 999)

       return user_permission_level >= required_level
   ```
"""
