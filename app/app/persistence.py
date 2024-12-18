import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.data_models import AppUser, UserSession
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

    def __init__(self, db_path: Path = Path("user.db")) -> None:
        """
        Initialize the Persistence instance and ensure necessary tables exist.
        """
        self.conn = sqlite3.connect(db_path)
        self._create_user_table()  # Ensure the users table exists
        self._create_session_table()  # Ensure the sessions table exists

    def _create_user_table(self) -> None:
        """
        Create the 'users' table in the database if it does not exist. The table
        stores user information including id, username, timestamps, and password
        data.
        """
        cursor = self.conn.cursor()

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
                two_factor_secret TEXT
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
        cursor = self.conn.cursor()

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

    async def create_user(self, user: AppUser) -> None:
        """
        Add a new user to the database.

        ## Parameters

        `user`: The user object containing user details.
        """
        cursor = self.conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (id, username, created_at, password_hash, password_salt, role, is_verified, two_factor_secret)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        cursor = self.conn.cursor()
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
        cursor = self.conn.cursor()

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

        cursor = self.conn.cursor()
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

        cursor = self.conn.cursor()

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
        cursor = self.conn.cursor()

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
        cursor = self.conn.cursor()
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
        cursor = self.conn.cursor()
        cursor.execute("SELECT two_factor_secret FROM users WHERE id = ?", (str(user_id),))
        result = cursor.fetchone()
        return bool(result and result[0])

    def set_2fa_secret(self, user_id: uuid.UUID, secret: str | None) -> None:
        """Enable or Disable 2FA for a user.
        Set to str if enabling, or to None if disabling
        """
        cursor = self.conn.cursor()
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
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).timestamp()

        cursor.execute(
            "UPDATE user_sessions SET valid_until = ? WHERE user_id = ?",
            (now, str(user_id)),
        )
        self.conn.commit()

    async def delete_user(self, user_id: uuid.UUID, password: str, two_factor_code: str | None = None) -> bool:
        """
        Delete a user and all their associated sessions from the database.
        
        ## Parameters
        
        `user_id`: The UUID of the user to delete
        `password`: The user's password for verification
        `two_factor_code`: Optional 2FA code, required if 2FA is enabled for the user
        
        ## Returns
        
        `bool`: True if deletion was successful, False if authentication failed
        
        ## Raises
        
        `KeyError`: If the user does not exist
        """
        cursor = self.conn.cursor()
        
        # First verify the user exists and get their data
        try:
            user = await self.get_user_by_id(user_id)
        except KeyError:
            return False
            
        # Verify password
        if not user.verify_password(password):
            return False
            
        # Check if 2FA is required
        if user.two_factor_secret:
            if not two_factor_code or not self.verify_2fa(user_id, two_factor_code):
                return False
        
        # First delete all sessions first (due to foreign key constraint)
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = ?",
            (str(user_id),)
        )
        
        # Delete the user
        cursor.execute(
            "DELETE FROM users WHERE id = ?",
            (str(user_id),)
        )
        
        self.conn.commit()
        return True