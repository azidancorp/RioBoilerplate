"""Pytest bootstrap for repository-root test execution."""

import os
import sys
from pathlib import Path


os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key")


APP_CONTAINER_DIR = Path(__file__).resolve().parent / "app"

if str(APP_CONTAINER_DIR) not in sys.path:
    sys.path.insert(0, str(APP_CONTAINER_DIR))
