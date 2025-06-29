from fastapi import APIRouter, HTTPException, Depends, status
from typing import Dict, List, Optional
import sqlite3
from app.data.profiles_db import ProfileDatabase, init_sample_data
from app.validation import (
    ProfileCreateRequest,
    ProfileUpdateRequest,
    ProfileResponse,
    SecuritySanitizer
)

router = APIRouter()

# Database dependency
async def get_profile_db():
    db = ProfileDatabase()
    return db

@router.get("/api/profile", response_model=List[ProfileResponse])
async def get_profiles(db: ProfileDatabase = Depends(get_profile_db)) -> List[Dict]:
    """
    Get all user profiles
    
    Returns:
        List[Dict]: List of all user profiles
    """
    return await db.get_profiles()

@router.get("/api/profile/{user_id}", response_model=ProfileResponse)
async def get_profile(user_id: str, db: ProfileDatabase = Depends(get_profile_db)) -> Dict:
    """
    Get a user's profile by user ID with input validation
    
    Args:
        user_id: The ID of the user whose profile to retrieve
        
    Returns:
        Dict: The user's profile data
        
    Raises:
        HTTPException: If profile is not found or user_id is invalid
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
    
    profile = await db.get_profile_by_user_id(sanitized_user_id)
    
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile for user {user_id} not found"
        )
        
    return profile

@router.post("/api/profile", status_code=status.HTTP_201_CREATED, response_model=ProfileResponse)
async def create_profile(
    profile_data: ProfileCreateRequest,
    db: ProfileDatabase = Depends(get_profile_db)
) -> Dict:
    """
    Create a new user profile with input validation and sanitization
    
    Args:
        profile_data: Validated profile data from request body
        
    Returns:
        Dict: The created profile data
        
    Raises:
        HTTPException: If validation fails or a profile with the user_id or email already exists
    """
    try:
        return await db.create_profile(
            user_id=profile_data.user_id,
            full_name=profile_data.full_name,
            email=profile_data.email,
            phone=profile_data.phone,
            address=profile_data.address,
            bio=profile_data.bio,
            avatar_url=profile_data.avatar_url
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the profile"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create profile: {str(e)}"
        )

@router.put("/api/profile/{user_id}", response_model=ProfileResponse)
async def update_profile(
    user_id: str,
    profile_data: ProfileUpdateRequest,
    db: ProfileDatabase = Depends(get_profile_db)
) -> Dict:
    """
    Update a user's profile with input validation and sanitization
    
    Args:
        user_id: The ID of the user whose profile to update
        profile_data: Validated profile update data from request body
        
    Returns:
        Dict: The updated profile data
        
    Raises:
        HTTPException: If the profile is not found or validation fails
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
        updated_profile = await db.update_profile(
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
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}"
        )

@router.delete("/api/profile/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    user_id: str,
    db: ProfileDatabase = Depends(get_profile_db)
) -> None:
    """
    Delete a user's profile with input validation
    
    Args:
        user_id: The ID of the user whose profile to delete
        
    Raises:
        HTTPException: If the profile is not found or user_id is invalid
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
    
    success = await db.delete_profile(sanitized_user_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile for user {sanitized_user_id} not found"
        )

# Initialize sample data on startup
@router.on_event("startup")
async def startup_event():
    await init_sample_data()
