"""
Profile Management API Endpoints

Authentication: Bearer token in Authorization header (UserSettings.auth_token in Rio apps)

Authorization:
- GET /api/profiles: Admin/root managed profiles only (bulk profiles list)
- GET /api/profiles/{user_id}: Self or higher-role admin/root only
- POST /api/profiles: Create profile (self or admin/root)
- PUT /api/profiles/{user_id}: Update profile (self or admin/root)
- DELETE /api/profiles/{user_id}: Delete profile (self or admin/root)

Extension Points:
    See auth_dependencies.py for examples of implementing:
    - Profile visibility settings (public/private)
    - Connection-based access (friends can view each other)
    - Advanced permission systems
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import Dict, List
import sqlite3
from app.persistence import AdminSessionInvalidError, Persistence
from app.validation import (
    ProfileCreateRequest,
    ProfileUpdateRequest,
    ProfileResponse,
    SecuritySanitizer
)
from app.api.auth_dependencies import get_current_session, get_persistence
from app.data_models import UserSession

router = APIRouter()

# Database dependency
# Note: FastAPI endpoints run outside Rio's session context, so we cannot use
# session[Persistence]. Creating a new instance here is the correct pattern
# for API endpoints. Each request gets its own Persistence instance.

@router.get("/api/profiles", response_model=List[ProfileResponse])
async def get_profiles(
    current_session: UserSession = Depends(get_current_session),
    db: Persistence = Depends(get_persistence)
) -> List[Dict]:
    """
    Get manageable user profiles (admin/root only).

    Privileged users receive their own profile and profiles belonging to
    lower-role users. Peer and higher-role profiles remain private.

    Raises: 401 (auth fails), 403 (insufficient privileges).
    """
    try:
        return await db.get_profiles_for_session(
            auth_token=current_session.id,
        )
    except AdminSessionInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

@router.get("/api/profiles/{user_id}", response_model=ProfileResponse)
async def get_profile(
    user_id: str,
    current_session: UserSession = Depends(get_current_session),
    db: Persistence = Depends(get_persistence)
) -> Dict:
    """
    Get profile by user ID (requires authentication and authorization).

    Users can view their own private profile. Admin/root users can view profiles
    for support and account-management work.

    Raises: 401 (auth fails), 404 (not found), 422 (invalid ID).
    """
    # Validate and sanitize user_id
    try:
        sanitized_user_id = SecuritySanitizer.sanitize_string(user_id, 50)
        if not sanitized_user_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="User ID cannot be empty"
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid user ID format"
        )

    try:
        profile = await db.get_profile_for_session(
            auth_token=current_session.id,
            user_id=sanitized_user_id,
        )
    except AdminSessionInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {sanitized_user_id} does not exist",
        )

    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile for user {user_id} not found"
        )

    return profile

@router.post("/api/profiles", status_code=status.HTTP_201_CREATED, response_model=ProfileResponse)
async def create_profile(
    profile_data: ProfileCreateRequest,
    current_session: UserSession = Depends(get_current_session),
    db: Persistence = Depends(get_persistence)
) -> Dict:
    """
    Create user profile (requires auth and authorization).

    Users can only create their own profile (admin/root can create any).
    Note: Profiles auto-created during registration, this is for edge cases.

    Raises: 401 (auth fails), 403 (unauthorized), 400 (duplicate), 422 (validation), 500 (DB error).
    """
    try:
        return await db.create_profile_for_session(
            auth_token=current_session.id,
            user_id=profile_data.user_id,
            full_name=profile_data.full_name,
            email=profile_data.email,
            phone=profile_data.phone,
            address=profile_data.address,
            bio=profile_data.bio,
            avatar_url=profile_data.avatar_url
        )
    except AdminSessionInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {profile_data.user_id} does not exist",
        )
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: profiles.user_id" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"A profile with user ID {profile_data.user_id} already exists"
            )
        elif "UNIQUE constraint failed: profiles.email" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"A profile with email {profile_data.email} already exists"
            )
        elif "FOREIGN KEY constraint failed" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User {profile_data.user_id} does not exist"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the profile"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create profile"
        )

@router.put("/api/profiles/{user_id}", response_model=ProfileResponse)
async def update_profile(
    user_id: str,
    profile_data: ProfileUpdateRequest,
    current_session: UserSession = Depends(get_current_session),
    db: Persistence = Depends(get_persistence)
) -> Dict:
    """
    Update user profile (requires auth and authorization).

    Users can only update their own profile (admin/root can update any).

    Raises: 401 (auth fails), 403 (unauthorized), 404 (not found), 400 (duplicate email),
    422 (validation), 500 (DB error).
    """
    # Validate and sanitize user_id
    try:
        sanitized_user_id = SecuritySanitizer.sanitize_string(user_id, 50)
        if not sanitized_user_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="User ID cannot be empty"
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid user ID format"
        )

    try:
        updated_profile = await db.update_profile_for_session(
            auth_token=current_session.id,
            user_id=sanitized_user_id,
            full_name=profile_data.full_name,
            email=profile_data.email,
            phone=profile_data.phone,
            address=profile_data.address,
            bio=profile_data.bio,
            avatar_url=profile_data.avatar_url
        )

        if updated_profile is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Profile for user {sanitized_user_id} not found"
            )

        return updated_profile
    except HTTPException:
        raise
    except AdminSessionInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {sanitized_user_id} does not exist",
        )
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: profiles.email" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"A profile with email {profile_data.email} already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the profile"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )

@router.delete("/api/profiles/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    user_id: str,
    current_session: UserSession = Depends(get_current_session),
    db: Persistence = Depends(get_persistence)
) -> None:
    """
    Delete user profile (requires auth and authorization).

    Users can only delete their own profile (admin/root can delete any).
    Note: Deletes profile only, not user account. For full account deletion,
    use user deletion endpoint with password/2FA verification.

    Raises: 401 (auth fails), 403 (unauthorized), 404 (not found), 422 (validation).
    """
    # Validate and sanitize user_id
    try:
        sanitized_user_id = SecuritySanitizer.sanitize_string(user_id, 50)
        if not sanitized_user_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="User ID cannot be empty"
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid user ID format"
        )

    try:
        success = await db.delete_profile_for_session(
            auth_token=current_session.id,
            user_id=sanitized_user_id,
        )
    except AdminSessionInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {sanitized_user_id} does not exist",
        )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile for user {sanitized_user_id} not found"
        )
