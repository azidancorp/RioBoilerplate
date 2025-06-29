import sqlite3
from pathlib import Path
from typing import Dict, List, Optional


class ItemsDatabase:
    """
    A class to handle database operations for items.
    
    Items data is stored in the 'items' table.
    
    ## Attributes
    
    `db_path`: Path to the SQLite database file
    """
    
    def __init__(self, db_path: Path = Path("app", "data", "items.db")) -> None:
        """
        Initialize the ItemsDatabase instance and ensure necessary tables exist.
        """
        self.db_path = db_path
        self.conn = None
        self._ensure_connection()
        self._create_items_table()
        
    def _ensure_connection(self) -> None:
        """
        Ensure database connection is active. Reconnect if needed.
        """
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            
    def _get_cursor(self):
        """
        Get a database cursor, ensuring connection is active.
        """
        self._ensure_connection()
        return self.conn.cursor()
        
    def close(self) -> None:
        """
        Close the database connection.
        """
        if self.conn:
            self.conn.close()
            self.conn = None
            
    def __del__(self) -> None:
        """
        Cleanup method to ensure connection is closed when object is destroyed.
        """
        self.close()
        
    def __enter__(self):
        """
        Context manager entry.
        """
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit - close connection.
        """
        self.close()

    def _create_items_table(self) -> None:
        """
        Create the 'items' table in the database if it does not exist.
        """
        cursor = self._get_cursor()
        
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                price REAL,
                created_at REAL NOT NULL
            )
            """
        )
        self.conn.commit()
        
    async def get_item(self, item_id: int) -> Optional[Dict]:
        """
        Retrieve an item from the database by ID.
        
        ## Parameters
        
        `item_id`: The ID of the item to retrieve.
        
        ## Returns
        
        Dict containing the item details if found, None otherwise.
        """
        cursor = self._get_cursor()
        cursor.execute(
            "SELECT id, name, description, price FROM items WHERE id = ? LIMIT 1",
            (item_id,),
        )
        
        row = cursor.fetchone()
        
        if row:
            return {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "price": row[3]
            }
        
        return None
    
    async def get_all_items(self) -> List[Dict]:
        """
        Retrieve all items from the database.
        
        ## Returns
        
        List of dictionaries containing item details.
        """
        cursor = self._get_cursor()
        cursor.execute("SELECT id, name, description, price FROM items")
        
        items = []
        for row in cursor.fetchall():
            items.append({
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "price": row[3]
            })
            
        return items
    
    async def create_item(self, name: str, description: str = None, price: float = None) -> Dict:
        """
        Add a new item to the database.
        
        ## Parameters
        
        `name`: The name of the item.
        `description`: Optional description of the item.
        `price`: Optional price of the item.
        
        ## Returns
        
        Dict containing the newly created item details.
        """
        from datetime import datetime, timezone
        
        cursor = self._get_cursor()
        created_at = datetime.now(timezone.utc).timestamp()
        
        cursor.execute(
            """
            INSERT INTO items (name, description, price, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (name, description, price, created_at),
        )
        self.conn.commit()
        
        # Get the ID of the newly inserted item
        item_id = cursor.lastrowid
        
        return {
            "id": item_id,
            "name": name,
            "description": description,
            "price": price
        }
    
    async def update_item(self, item_id: int, name: str = None, description: str = None, price: float = None) -> Optional[Dict]:
        """
        Update an existing item in the database.
        
        ## Parameters
        
        `item_id`: The ID of the item to update.
        `name`: Optional new name for the item.
        `description`: Optional new description for the item.
        `price`: Optional new price for the item.
        
        ## Returns
        
        Dict containing the updated item details if successful, None if item not found.
        """
        # First check if the item exists
        item = await self.get_item(item_id)
        if not item:
            return None
        
        # Update only the provided fields
        update_fields = []
        params = []
        
        if name is not None:
            update_fields.append("name = ?")
            params.append(name)
        
        if description is not None:
            update_fields.append("description = ?")
            params.append(description)
            
        if price is not None:
            update_fields.append("price = ?")
            params.append(price)
            
        if not update_fields:
            # No fields to update
            return item
            
        # Add item_id to params
        params.append(item_id)
        
        cursor = self._get_cursor()
        cursor.execute(
            f"""
            UPDATE items
            SET {', '.join(update_fields)}
            WHERE id = ?
            """,
            tuple(params),
        )
        self.conn.commit()
        
        # Return the updated item
        return await self.get_item(item_id)
    
    async def delete_item(self, item_id: int) -> bool:
        """
        Delete an item from the database.
        
        ## Parameters
        
        `item_id`: The ID of the item to delete.
        
        ## Returns
        
        True if the item was deleted, False if the item was not found.
        """
        cursor = self._get_cursor()
        cursor.execute(
            "DELETE FROM items WHERE id = ?",
            (item_id,),
        )
        self.conn.commit()
        
        # If rowcount is 0, no rows were deleted
        return cursor.rowcount > 0

# Initialize the database with some sample data
async def init_sample_data():
    db = ItemsDatabase()
    
    # Add sample items if the database is empty
    items = await db.get_all_items()
    if not items:
        await db.create_item("Item One", "This is the first item", 10.99)
        await db.create_item("Item Two", "This is the second item", 20.50)
        await db.create_item("Item Three", "This is the third item", 30.75)
    
    return db
