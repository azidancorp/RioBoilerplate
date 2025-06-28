from fastapi import APIRouter, HTTPException, Depends, Body, status
from typing import Dict, List, Optional
import sqlite3
from app.data.profiles_db import ProfileDatabase, init_sample_data

router = APIRouter()

# Database dependency
async def get_profile_db():
    db = ProfileDatabase()
    return db

@router.get("/api/profile", response_model=List[Dict])
async def get_profiles(db: ProfileDatabase = Depends(get_profile_db)) -> List[Dict]:
    """
    Get all user profiles
    
    Returns:
        List[Dict]: List of all user profiles
    """
    return await db.get_profiles()

@router.get("/api/profile/{user_id}", response_model=Dict)
async def get_profile(user_id: str, db: ProfileDatabase = Depends(get_profile_db)) -> Dict:
    """
    Get a user's profile by user ID
    
    Args:
        user_id (str): The ID of the user whose profile to retrieve
        
    Returns:
        Dict: The user's profile data
        
    Raises:
        HTTPException: If profile is not found
    """
    profile = await db.get_profile_by_user_id(user_id)
    
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile for user {user_id} not found"
        )
        
    return profile

@router.post("/api/profile", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def create_profile(
    user_id: str = Body(..., embed=True),
    full_name: str = Body(..., embed=True),
    email: str = Body(..., embed=True),
    phone: Optional[str] = Body(None, embed=True),
    address: Optional[str] = Body(None, embed=True),
    bio: Optional[str] = Body(None, embed=True),
    avatar_url: Optional[str] = Body(None, embed=True),
    db: ProfileDatabase = Depends(get_profile_db)
) -> Dict:
    """
    Create a new user profile
    
    Args:
        user_id (str): The ID of the user this profile belongs to
        full_name (str): User's full name
        email (str): User's email address
        phone (str, optional): User's phone number
        address (str, optional): User's address
        bio (str, optional): Short bio/description
        avatar_url (str, optional): URL to user's avatar image
        
    Returns:
        Dict: The created profile data
        
    Raises:
        HTTPException: If a profile with the user_id or email already exists
    """
    try:
        return await db.create_profile(
            user_id=user_id,
            full_name=full_name,
            email=email,
            phone=phone,
            address=address,
            bio=bio,
            avatar_url=avatar_url
        )
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: profiles.user_id" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"A profile with user ID {user_id} already exists"
            )
        elif "UNIQUE constraint failed: profiles.email" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"A profile with email {email} already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the profile"
        )

@router.put("/api/profile/{user_id}", response_model=Dict)
async def update_profile(
    user_id: str,
    full_name: Optional[str] = Body(None, embed=True),
    email: Optional[str] = Body(None, embed=True),
    phone: Optional[str] = Body(None, embed=True),
    address: Optional[str] = Body(None, embed=True),
    bio: Optional[str] = Body(None, embed=True),
    avatar_url: Optional[str] = Body(None, embed=True),
    db: ProfileDatabase = Depends(get_profile_db)
) -> Dict:
    """
    Update a user's profile
    
    Args:
        user_id (str): The ID of the user whose profile to update
        full_name (str, optional): New full name
        email (str, optional): New email
        phone (str, optional): New phone number
        address (str, optional): New address
        bio (str, optional): New bio
        avatar_url (str, optional): New avatar URL
        
    Returns:
        Dict: The updated profile data
        
    Raises:
        HTTPException: If the profile is not found
    """
    updated_profile = await db.update_profile(
        user_id=user_id,
        full_name=full_name,
        email=email,
        phone=phone,
        address=address,
        bio=bio,
        avatar_url=avatar_url
    )
    
    if updated_profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile for user {user_id} not found"
        )
        
    return updated_profile

@router.delete("/api/profile/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    user_id: str,
    db: ProfileDatabase = Depends(get_profile_db)
) -> None:
    """
    Delete a user's profile
    
    Args:
        user_id (str): The ID of the user whose profile to delete
        
    Raises:
        HTTPException: If the profile is not found
    """
    success = await db.delete_profile(user_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile for user {user_id} not found"
        )

# Initialize sample data on startup
@router.on_event("startup")
async def startup_event():
    await init_sample_data()
