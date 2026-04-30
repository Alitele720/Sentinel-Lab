"""Package entrypoint for the modular IDS demo application."""

import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
VENDOR_DIR = BASE_DIR / ".vendor"

# Tests may import the package directly without going through app.py first.
if VENDOR_DIR.exists():
    sys.path.insert(0, str(VENDOR_DIR))

from .web import create_app

__all__ = ["create_app"]
