from fastapi import APIRouter, HTTPException
from typing import Dict

router = APIRouter()

@router.get("/api/test")
def test_route():
    return {"message": "Hello, World!"}

@router.get("/api/items/{item_id}")
async def get_item(item_id: int) -> Dict:
    """
    Get item details by ID
    
    Args:
        item_id (int): The ID of the item to retrieve
        
    Returns:
        Dict: Item details including id and name
        
    Raises:
        HTTPException: If item is not found
    """
    # This is a mock database - in real application, you would query your database
    items = {
        1: {"id": 1, "name": "Item One"},
        2: {"id": 2, "name": "Item Two"},
        3: {"id": 3, "name": "Item Three"}
    }
    
    if item_id not in items:
        raise HTTPException(status_code=404, detail=f"Item {item_id} not found")
        
    return items[item_id]
