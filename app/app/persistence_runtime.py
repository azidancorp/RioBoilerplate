from functools import lru_cache

from app.config import config
from app.persistence import Persistence


@lru_cache(maxsize=1)
def get_persistence() -> Persistence:
    """Return the process-wide persistence facade used by Rio and FastAPI."""
    return Persistence(allow_username_login=config.ALLOW_USERNAME_LOGIN)
