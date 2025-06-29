from fastapi import APIRouter, HTTPException, Depends, status
from typing import Dict, List, Optional
from app.data.items_db import ItemsDatabase, init_sample_data
from app.validation import (
    ItemCreateRequest, 
    ItemUpdateRequest, 
    ItemResponse
)

router = APIRouter()

# Database dependency
async def get_items_db():
    db = ItemsDatabase()
    return db

@router.get("/api/test")
def test_route():
    return {"message": "Hello, World!"}

@router.get("/api/items/{item_id}", response_model=ItemResponse)
async def get_item(item_id: int, db: ItemsDatabase = Depends(get_items_db)) -> Dict:
    """
    Get item details by ID
    
    Args:
        item_id (int): The ID of the item to retrieve
        
    Returns:
        Dict: Item details including id, name, description, and price
        
    Raises:
        HTTPException: If item is not found
    """
    item = await db.get_item(item_id)
    
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"Item {item_id} not found"
        )
        
    return item

@router.get("/api/items", response_model=List[ItemResponse])
async def get_items(db: ItemsDatabase = Depends(get_items_db)) -> List[Dict]:
    """
    Get all items
    
    Returns:
        List[Dict]: List of items with details
    """
    return await db.get_all_items()

@router.post("/api/items", status_code=status.HTTP_201_CREATED, response_model=ItemResponse)
async def create_item(
    item_data: ItemCreateRequest,
    db: ItemsDatabase = Depends(get_items_db)
) -> Dict:
    """
    Create a new item with input validation and sanitization
    
    Args:
        item_data: Validated item data from request body
        
    Returns:
        Dict: Created item details
        
    Raises:
        HTTPException: If validation fails or item creation fails
    """
    try:
        return await db.create_item(
            item_data.name, 
            item_data.description, 
            item_data.price
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create item: {str(e)}"
        )

@router.put("/api/items/{item_id}", response_model=ItemResponse)
async def update_item(
    item_id: int,
    item_data: ItemUpdateRequest,
    db: ItemsDatabase = Depends(get_items_db)
) -> Dict:
    """
    Update an existing item with input validation and sanitization
    
    Args:
        item_id: ID of the item to update
        item_data: Validated item update data from request body
        
    Returns:
        Dict: Updated item details
        
    Raises:
        HTTPException: If the item is not found or validation fails
    """
    try:
        updated_item = await db.update_item(
            item_id, 
            item_data.name, 
            item_data.description, 
            item_data.price
        )
        
        if updated_item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"Item {item_id} not found"
            )
            
        return updated_item
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update item: {str(e)}"
        )

@router.delete("/api/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(item_id: int, db: ItemsDatabase = Depends(get_items_db)) -> None:
    """
    Delete an item
    
    Args:
        item_id: ID of the item to delete
        
    Raises:
        HTTPException: If the item is not found
    """
    success = await db.delete_item(item_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"Item {item_id} not found"
        )

# Initialize sample data
@router.on_event("startup")
async def startup_event():
    await init_sample_data()
