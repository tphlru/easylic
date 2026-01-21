"""
Data persistence utilities.
"""

from __future__ import annotations

import json
from pathlib import Path

from easylic.common.models import SessionData


class DataPersistence:
    """Handles loading and saving persistent data."""

    @staticmethod
    def load_revoked_licenses(file_path: Path) -> dict[str, int]:
        """Load revoked licenses from file."""
        try:
            with file_path.open() as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    @staticmethod
    def save_revoked_licenses(
        file_path: Path, revoked_licenses: dict[str, int]
    ) -> None:
        """Save revoked licenses to file."""
        with file_path.open("w") as f:
            json.dump(revoked_licenses, f)

    @staticmethod
    def load_sessions(file_path: Path) -> dict[str, SessionData]:
        """Load sessions from file."""
        try:
            with file_path.open() as f:
                data = json.load(f)
                return {k: SessionData(**v) for k, v in data.items()}
        except FileNotFoundError:
            return {}

    @staticmethod
    def save_sessions(file_path: Path, sessions: dict[str, SessionData]) -> None:
        """Save sessions to file."""
        with file_path.open("w") as f:
            json.dump({k: v.model_dump() for k, v in sessions.items()}, f)
