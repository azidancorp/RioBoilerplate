"""Pytest bootstrap for execution from the outer app/ directory."""

import sys
from pathlib import Path


OUTER_APP_DIR = Path(__file__).resolve().parent

if str(OUTER_APP_DIR) not in sys.path:
    sys.path.insert(0, str(OUTER_APP_DIR))
