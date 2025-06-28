from fastapi import APIRouter, HTTPException, Depends, Body
from typing import Dict, List, Optional
from app.data.items_db import ItemsDatabase, init_sample_data

router = APIRouter()

# Database dependency
async def get_items_db():
    db = ItemsDatabase()
    return db

@router.get("/api/test")
def test_route():
    return {"message": "Hello, World!"}

@router.get("/api/items/{item_id}")
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
        raise HTTPException(status_code=404, detail=f"Item {item_id} not found")
        
    return item

@router.get("/api/items")
async def get_items(db: ItemsDatabase = Depends(get_items_db)) -> List[Dict]:
    """
    Get all items
    
    Returns:
        List[Dict]: List of items with details
    """
    return await db.get_all_items()

@router.post("/api/items")
async def create_item(
    name: str = Body(...), 
    description: Optional[str] = Body(None), 
    price: Optional[float] = Body(None),
    db: ItemsDatabase = Depends(get_items_db)
) -> Dict:
    """
    Create a new item
    
    Args:
        name (str): Name of the item
        description (str, optional): Description of the item
        price (float, optional): Price of the item
        
    Returns:
        Dict: Created item details
    """
    return await db.create_item(name, description, price)

@router.put("/api/items/{item_id}")
async def update_item(
    item_id: int,
    name: Optional[str] = Body(None),
    description: Optional[str] = Body(None),
    price: Optional[float] = Body(None),
    db: ItemsDatabase = Depends(get_items_db)
) -> Dict:
    """
    Update an existing item
    
    Args:
        item_id (int): ID of the item to update
        name (str, optional): New name for the item
        description (str, optional): New description for the item
        price (float, optional): New price for the item
        
    Returns:
        Dict: Updated item details
        
    Raises:
        HTTPException: If the item is not found
    """
    updated_item = await db.update_item(item_id, name, description, price)
    
    if updated_item is None:
        raise HTTPException(status_code=404, detail=f"Item {item_id} not found")
        
    return updated_item

@router.delete("/api/items/{item_id}")
async def delete_item(item_id: int, db: ItemsDatabase = Depends(get_items_db)) -> Dict:
    """
    Delete an item
    
    Args:
        item_id (int): ID of the item to delete
        
    Returns:
        Dict: Success message
        
    Raises:
        HTTPException: If the item is not found
    """
    success = await db.delete_item(item_id)
    
    if not success:
        raise HTTPException(status_code=404, detail=f"Item {item_id} not found")
        
    return {"message": f"Item {item_id} deleted successfully"}

# Initialize sample data
@router.on_event("startup")
async def startup_event():
    await init_sample_data()
