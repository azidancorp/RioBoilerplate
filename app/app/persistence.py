import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.data_models import AppUser, UserSession, PasswordResetCode
import pyotp


# Define the UserPersistence dataclass to handle database operations
class Persistence:
    """
    A class to handle database operations for users and sessions.

    User data is stored in the 'users' table, and session data is stored in the
    'user_sessions' table.

    You can adapt this class to your needs by adding more methods to interact
    with the database or support different databases like MongoDB.

    ## Attributes

    `db_path`: Path to the SQLite database file
    """

    def __init__(self, db_path: Path = Path("app", "data", "users.db")) -> None:
        """
        Initialize the Persistence instance and ensure necessary tables exist.
        """
        self.db_path = db_path
        self.conn = None
        self._ensure_connection()
        self._create_user_table()  # Ensure the users table exists
        self._create_session_table()  # Ensure the sessions table exists
        self._create_reset_codes_table()  # Ensure the reset codes table exists

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

    def _create_user_table(self) -> None:
        """
        Create the 'users' table in the database if it does not exist. The table
        stores user information including id, username, timestamps, and password
        data.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at REAL NOT NULL,
                password_hash BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                two_factor_secret TEXT,
                referral_code TEXT DEFAULT ''
            )
        """
        )
        self.conn.commit()

    def _create_session_table(self) -> None:
        """
        Create the 'user_sessions' table in the database if it does not exist.
        The table stores session information including session id, user id, and
        timestamps.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                valid_until REAL NOT NULL,
                role TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )
        self.conn.commit()

    def _create_reset_codes_table(self) -> None:
        """
        Create the 'password_reset_codes' table in the database if it does not exist.
        The table stores reset codes that allow users to reset their passwords.
        """
        cursor = self._get_cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_codes (
                code TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                valid_until REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )
        self.conn.commit()

    async def create_user(self, user: AppUser) -> None:
        """
        Add a new user to the database.

        ## Parameters

        `user`: The user object containing user details.
        """
        cursor = self._get_cursor()
        
        # Check if this is the first user
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        # If this is the first user, set their role to root
        if user_count == 0:
            user.role = "root"

        cursor.execute(
            """
            INSERT INTO users (id, username, created_at, password_hash, password_salt, role, is_verified, two_factor_secret, referral_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(user.id),
                user.username,
                user.created_at.timestamp(),
                user.password_hash,
                user.password_salt,
                user.role,
                user.is_verified,
                user.two_factor_secret,
                user.referral_code,
            ),
        )
        self.conn.commit()

    async def get_user_by_username(
        self,
        username: str,
    ) -> AppUser:
        """
        Retrieve a user from the database by username.


        ## Parameters

        `username`: The username of the user to retrieve.


        ## Raises

        `KeyError`: If there is no user with the specified username.
        """
        cursor = self._get_cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? LIMIT 1",
            (username,),
        )

        row = cursor.fetchone()

        if row:
            return AppUser(
                id=uuid.UUID(row[0]),
                username=row[1],
                created_at=datetime.fromtimestamp(row[2], tz=timezone.utc),
                password_hash=row[3],
                password_salt=row[4],
                role=row[5],
                is_verified=bool(row[6]),
                two_factor_secret=row[7],
                referral_code=row[8],
            )

        raise KeyError(username)

    async def get_user_by_id(
        self,
        id: uuid.UUID,
    ) -> AppUser:
        """
        Retrieve a user from the database by user ID.


        ## Parameters

        `id`: The UUID of the user to retrieve.


        ## Raises

        `KeyError`: If there is no user with the specified ID.
        """
        cursor = self._get_cursor()

        cursor.execute(
            "SELECT * FROM users WHERE id = ? LIMIT 1",
            (str(id),),
        )

        row = cursor.fetchone()

        if row:
            return AppUser(
                id=uuid.UUID(row[0]),
                username=row[1],
                created_at=datetime.fromtimestamp(row[2], tz=timezone.utc),
                password_hash=row[3],
                password_salt=row[4],
                role=row[5],
                is_verified=bool(row[6]),
                two_factor_secret=row[7],
                referral_code=row[8],
            )

        raise KeyError(id)

    async def create_session(
        self,
        user_id: uuid.UUID,
    ) -> UserSession:
        """
        Create a new user session and store it in the database.

        ## Parameters

        `user_id`: The UUID of the user for whom to create the session.
        """
        now = datetime.now(tz=timezone.utc)

        user = await self.get_user_by_id(user_id)
        
        session = UserSession(
            id=secrets.token_urlsafe(),
            user_id=user_id,
            created_at=now,
            valid_until=now + timedelta(days=1),
            role=user.role
        )

        cursor = self._get_cursor()
        cursor.execute(
            """
            INSERT INTO user_sessions (id, user_id, created_at, valid_until, role)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session.id,
                str(session.user_id),
                session.created_at.timestamp(),
                session.valid_until.timestamp(),
                session.role,
            ),
        )
        self.conn.commit()

        return session

    async def update_session_duration(
        self,
        session: UserSession,
        new_valid_until: datetime,
    ) -> None:
        """
        Extend the duration of an existing session. This will update the
        session's validity timestamp both in the given object and the database.

        ## Parameters

        `session`: The session whose duration to extend.

        `new_valid_until`: The new timestamp until which the session should be
            considered valid.
        """
        session.valid_until = new_valid_until

        cursor = self._get_cursor()

        cursor.execute(
            """
            UPDATE user_sessions
            SET valid_until = ?
            WHERE id = ?
            """,
            (
                session.valid_until.timestamp(),
                session.id,
            ),
        )
        self.conn.commit()

    async def get_session_by_auth_token(
        self,
        auth_token: str,
    ) -> UserSession:
        """
        Retrieve a user session from the database by authentication token.

        ## Parameters

        `auth_token`: The authentication token (session ID) of the session to
            retrieve.

        ## Raises

        `KeyError`: If there is no session with the specified authentication
        token.
        """
        cursor = self._get_cursor()

        cursor.execute(
            "SELECT id, user_id, created_at, valid_until, role FROM user_sessions WHERE id = ? ORDER BY created_at LIMIT 1",
            (auth_token,),
        )

        row = cursor.fetchone()

        if row is None:
            raise KeyError(f"No session found with auth token {auth_token}")

        return UserSession(
            id=row[0],
            user_id=uuid.UUID(row[1]),
            created_at=datetime.fromtimestamp(row[2], tz=timezone.utc),
            valid_until=datetime.fromtimestamp(row[3], tz=timezone.utc),
            role=row[4],
        )


    def verify_2fa(self, user_id: uuid.UUID, token: str) -> bool:
        """Verify a 2FA token for a user."""
        cursor = self._get_cursor()
        cursor.execute(
            "SELECT two_factor_secret FROM users WHERE id = ? AND two_factor_secret IS NOT NULL",
            (str(user_id),)
        )
        result = cursor.fetchone()
        
        if not result:
            return True  # If 2FA is not enabled, consider it verified
            
        secret = result[0]
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

    def is_2fa_enabled(self, user_id: uuid.UUID) -> bool:
        """Check if 2FA is enabled for a user."""
        cursor = self._get_cursor()
        cursor.execute("SELECT two_factor_secret FROM users WHERE id = ?", (str(user_id),))
        result = cursor.fetchone()
        return bool(result and result[0])

    def set_2fa_secret(self, user_id: uuid.UUID, secret: str | None) -> None:
        """Enable or Disable 2FA for a user.
        Set to str if enabling, or to None if disabling
        """
        cursor = self._get_cursor()
        cursor.execute(
            "UPDATE users SET two_factor_secret = ? WHERE id = ?",
            (secret, str(user_id)),
        )
        self.conn.commit()

    async def invalidate_all_sessions(
        self,
        user_id: uuid.UUID,
    ) -> None:
        """
        Invalidate all sessions for a given user by setting their valid_until
        timestamp to the current time.

        ## Parameters

        `user_id`: The UUID of the user whose sessions to invalidate.
        """
        cursor = self._get_cursor()
        now = datetime.now(timezone.utc).timestamp()

        cursor.execute(
            "UPDATE user_sessions SET valid_until = ? WHERE user_id = ?",
            (now, str(user_id)),
        )
        self.conn.commit()

    async def update_password(
        self,
        user_id: uuid.UUID,
        new_password: str,
    ) -> None:
        """
        Update a user's password hash and salt.
        
        ## Parameters
        
        `user_id`: The UUID of the user whose password to update
        `new_password`: The new password to set
        
        ## Raises
        
        `KeyError`: If the user does not exist
        """
        cursor = self._get_cursor()
        
        # First verify the user exists
        await self.get_user_by_id(user_id)  # Will raise KeyError if user doesn't exist
        
        # Generate new password hash and salt using AppUser's method
        password_salt = secrets.token_bytes(64)
        password_hash = AppUser.get_password_hash(new_password, password_salt)
        
        # Update the password in database
        cursor.execute(
            """
            UPDATE users 
            SET password_hash = ?, password_salt = ?
            WHERE id = ?
            """,
            (password_hash, password_salt, str(user_id))
        )
        self.conn.commit()
        
        # Invalidate all existing sessions for security
        await self.invalidate_all_sessions(user_id)

    async def create_reset_code(self, user_id: uuid.UUID) -> PasswordResetCode:
        """
        Create a new password reset code for a user.
        
        ## Parameters
        
        `user_id`: The UUID of the user to create a reset code for
        
        ## Returns
        
        The newly created reset code
        
        ## Raises
        
        `KeyError`: If the user does not exist
        """
        # First verify the user exists
        await self.get_user_by_id(user_id)
        
        # Create a new reset code
        reset_code = PasswordResetCode.create_new_reset_code(user_id)
        
        # Store it in the database
        cursor = self._get_cursor()
        cursor.execute(
            """
            INSERT INTO password_reset_codes (code, user_id, created_at, valid_until)
            VALUES (?, ?, ?, ?)
            """,
            (
                reset_code.code,
                str(reset_code.user_id),
                reset_code.created_at.timestamp(),
                reset_code.valid_until.timestamp(),
            ),
        )
        self.conn.commit()
        
        return reset_code

    async def get_user_by_reset_code(self, code: str) -> AppUser:
        """
        Find a user by their reset code. The code must be valid (not expired).
        
        ## Parameters
        
        `code`: The reset code to look up
        
        ## Returns
        
        The user associated with this reset code
        
        ## Raises
        
        `KeyError`: If the code is invalid, expired, or the associated user doesn't exist
        """
        cursor = self._get_cursor()
        
        # Get the reset code entry
        cursor.execute(
            """
            SELECT user_id, valid_until 
            FROM password_reset_codes 
            WHERE code = ?
            """,
            (code,)
        )
        
        row = cursor.fetchone()
        if not row:
            raise KeyError(f"Invalid reset code: {code}")
            
        # Check if the code is expired
        valid_until = datetime.fromtimestamp(row[1], tz=timezone.utc)
        if datetime.now(timezone.utc) >= valid_until:
            raise KeyError(f"Reset code has expired: {code}")
            
        # Get and return the associated user
        return await self.get_user_by_id(uuid.UUID(row[0]))

    async def clear_reset_code(self, user_id: uuid.UUID) -> None:
        """
        Delete all reset codes for a user.
        
        ## Parameters
        
        `user_id`: The UUID of the user whose reset codes to clear
        """
        cursor = self._get_cursor()
        cursor.execute(
            "DELETE FROM password_reset_codes WHERE user_id = ?",
            (str(user_id),)
        )
        self.conn.commit()

    def delete_user(self, user_id: uuid.UUID, password: str, two_factor_code: str | None = None) -> bool:
        """
        Delete a user and all their associated sessions from the database.
        
        ## Parameters
        
        `user_id`: The UUID of the user to delete
        `password`: The password for verification. For admin deletion, must match ADMIN_DELETION_PASSWORD
        `two_factor_code`: Optional 2FA code, required if 2FA is enabled for the user
        
        ## Returns
        
        `bool`: True if deletion was successful, False if authentication failed
        
        ## Raises
        
        `KeyError`: If the user does not exist
        """
        # First verify the user exists and get their data
        try:
            user = self.get_user_by_id(user_id)
        except KeyError:
            return False
            
        # Admin deletion password from environment variable
        ADMIN_DELETION_PASSWORD = os.getenv('ADMIN_DELETION_PASSWORD')
        if ADMIN_DELETION_PASSWORD is None:
            raise ValueError("ADMIN_DELETION_PASSWORD environment variable is not set. Please set it in your .env file or environment.")
        
        # For admin deletion, verify the admin deletion password
        if password != ADMIN_DELETION_PASSWORD:
            return False
            
        cursor = self._get_cursor()
        
        # First delete all sessions first (due to foreign key constraint)
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = ?",
            (str(user_id),)
        )
        
        # Delete all reset codes for this user
        cursor.execute(
            "DELETE FROM password_reset_codes WHERE user_id = ?",
            (str(user_id),)
        )
        
        # Delete the user
        cursor.execute(
            "DELETE FROM users WHERE id = ?",
            (str(user_id),)
        )
        
        self.conn.commit()
        return True