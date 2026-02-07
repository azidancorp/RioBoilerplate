"""Pytest bootstrap for repository-root test execution."""

import sys
from pathlib import Path


APP_CONTAINER_DIR = Path(__file__).resolve().parent / "app"

if str(APP_CONTAINER_DIR) not in sys.path:
    sys.path.insert(0, str(APP_CONTAINER_DIR))
