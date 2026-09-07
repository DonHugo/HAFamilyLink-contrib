"""Test configuration for the authentication service."""

from __future__ import annotations

import sys
from pathlib import Path

AUTH_SERVICE_ROOT = Path(__file__).parents[2] / "familylink-playwright"
sys.path.insert(0, str(AUTH_SERVICE_ROOT))
