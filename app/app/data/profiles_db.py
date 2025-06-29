import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class ProfileDatabase:
    """
    A class to handle database operations for user profiles.
    
    Profiles data is stored in the 'profiles' table.
    
    ## Attributes
    
    `db_path`: Path to the SQLite database file
    """
    
    def __init__(self, db_path: Path = Path("app", "data", "profiles.db")) -> None:
        """
        Initialize the ProfilesDatabase instance and ensure necessary tables exist.
        """
        self.db_path = db_path
        self.conn = None
        self._ensure_connection()
        self._create_profiles_table()
        
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

    def _create_profiles_table(self) -> None:
        """
        Create the 'profiles' table in the database if it does not exist.
        """
        cursor = self.conn.cursor()
        
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                full_name TEXT,
                email TEXT UNIQUE,
                phone TEXT,
                address TEXT,
                bio TEXT,
                avatar_url TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        self.conn.commit()
    
    async def create_profile(self, user_id: str, full_name: str, email: str, 
                           phone: str = None, address: str = None, 
                           bio: str = None, avatar_url: str = None) -> Dict:
        """
        Create a new user profile.
        
        Args:
            user_id: The ID of the user this profile belongs to
            full_name: User's full name
            email: User's email address
            phone: User's phone number (optional)
            address: User's address (optional)
            bio: Short bio/description (optional)
            avatar_url: URL to user's avatar image (optional)
            
        Returns:
            Dict: The created profile data
            
        Raises:
            sqlite3.IntegrityError: If a profile with the user_id or email already exists
        """
        cursor = self.conn.cursor()
        now = datetime.now().timestamp()
        
        cursor.execute(
            """
            INSERT INTO profiles 
            (user_id, full_name, email, phone, address, bio, avatar_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, full_name, email, phone, address, bio, avatar_url, now, now)
        )
        self.conn.commit()
        
        return await self.get_profile_by_user_id(user_id)
    
    async def get_profile(self, profile_id: int) -> Optional[Dict]:
        """
        Retrieve a profile by its ID.
        
        Args:
            profile_id: The ID of the profile to retrieve
            
        Returns:
            Optional[Dict]: The profile data if found, None otherwise
        """
        cursor = self.conn.cursor()
        
        cursor.execute(
            """
            SELECT id, user_id, full_name, email, phone, address, bio, avatar_url, 
                   created_at, updated_at
            FROM profiles 
            WHERE id = ?
            """,
            (profile_id,)
        )
        
        row = cursor.fetchone()
        if not row:
            return None
            
        return {
            "id": row[0],
            "user_id": row[1],
            "full_name": row[2],
            "email": row[3],
            "phone": row[4],
            "address": row[5],
            "bio": row[6],
            "avatar_url": row[7],
            "created_at": row[8],
            "updated_at": row[9]
        }
    
    async def get_profile_by_user_id(self, user_id: str) -> Optional[Dict]:
        """
        Retrieve a profile by user ID.
        
        Args:
            user_id: The ID of the user whose profile to retrieve
            
        Returns:
            Optional[Dict]: The profile data if found, None otherwise
        """
        cursor = self.conn.cursor()
        
        cursor.execute(
            """
            SELECT id, user_id, full_name, email, phone, address, bio, avatar_url, 
                   created_at, updated_at
            FROM profiles 
            WHERE user_id = ?
            """,
            (user_id,)
        )
        
        row = cursor.fetchone()
        if not row:
            return None
            
        return {
            "id": row[0],
            "user_id": row[1],
            "full_name": row[2],
            "email": row[3],
            "phone": row[4],
            "address": row[5],
            "bio": row[6],
            "avatar_url": row[7],
            "created_at": row[8],
            "updated_at": row[9]
        }
    
    async def update_profile(
        self, 
        user_id: str, 
        full_name: str = None, 
        email: str = None, 
        phone: str = None, 
        address: str = None, 
        bio: str = None, 
        avatar_url: str = None
    ) -> Optional[Dict]:
        """
        Update a user's profile.
        
        Args:
            user_id: The ID of the user whose profile to update
            full_name: New full name (optional)
            email: New email (optional)
            phone: New phone number (optional)
            address: New address (optional)
            bio: New bio (optional)
            avatar_url: New avatar URL (optional)
            
        Returns:
            Optional[Dict]: The updated profile data if found, None otherwise
        """
        cursor = self.conn.cursor()
        now = datetime.now().timestamp()
        
        # Build the update query dynamically based on provided fields
        update_fields = []
        params = []
        
        if full_name is not None:
            update_fields.append("full_name = ?")
            params.append(full_name)
        if email is not None:
            update_fields.append("email = ?")
            params.append(email)
        if phone is not None:
            update_fields.append("phone = ?")
            params.append(phone)
        if address is not None:
            update_fields.append("address = ?")
            params.append(address)
        if bio is not None:
            update_fields.append("bio = ?")
            params.append(bio)
        if avatar_url is not None:
            update_fields.append("avatar_url = ?")
            params.append(avatar_url)
            
        if not update_fields:
            return await self.get_profile_by_user_id(user_id)
            
        # Add updated_at and user_id to params
        update_fields.append("updated_at = ?")
        params.extend([now, user_id])
        
        query = f"""
            UPDATE profiles 
            SET {', '.join(update_fields)}
            WHERE user_id = ?
            RETURNING id
        """
        
        cursor.execute(query, params)
        self.conn.commit()
        
        if cursor.rowcount == 0:
            return None
            
        return await self.get_profile_by_user_id(user_id)
    
    async def delete_profile(self, user_id: str) -> bool:
        """
        Delete a user's profile.
        
        Args:
            user_id: The ID of the user whose profile to delete
            
        Returns:
            bool: True if the profile was deleted, False if not found
        """
        cursor = self.conn.cursor()
        
        cursor.execute(
            "DELETE FROM profiles WHERE user_id = ?",
            (user_id,)
        )
        self.conn.commit()
        
        return cursor.rowcount > 0
    
    async def get_profiles(self) -> List[Dict]:
        """
        Retrieve all user profiles.
        
        Returns:
            List[Dict]: List of all profiles
        """
        cursor = self.conn.cursor()
        
        cursor.execute(
            """
            SELECT id, user_id, full_name, email, phone, address, bio, avatar_url, 
                   created_at, updated_at
            FROM profiles
            ORDER BY created_at DESC
            """
        )
        
        rows = cursor.fetchall()
        return [
            {
                "id": row[0],
                "user_id": row[1],
                "full_name": row[2],
                "email": row[3],
                "phone": row[4],
                "address": row[5],
                "bio": row[6],
                "avatar_url": row[7],
                "created_at": row[8],
                "updated_at": row[9]
            }
            for row in rows
        ]

# Initialize the database with some sample data
async def init_sample_data():
    """Initialize the database with sample profile data."""
    db = ProfileDatabase()
    
    # Add some sample profiles if the table is empty
    cursor = db.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM profiles")
    count = cursor.fetchone()[0]
    
    if count == 0:
        sample_profile = [
            ("user1", "John Doe", "john@example.com", "+1234567890", "123 Main St, Anytown", "Software Engineer", None),
            ("user2", "Jane Smith", "jane@example.com", "+1987654321", "456 Oak Ave, Somewhere", "Data Scientist", None),
            ("user3", "Bob Johnson", "bob@example.com", None, None, "Product Manager", None),
        ]
        
        for user_id, full_name, email, phone, address, bio, avatar_url in sample_profile:
            await db.create_profile(
                user_id=user_id,
                full_name=full_name,
                email=email,
                phone=phone,
                address=address,
                bio=bio,
                avatar_url=avatar_url
            )
    
    return db
