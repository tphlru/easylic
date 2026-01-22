"""
Data persistence utilities.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path  # noqa: TC003
from typing import Any, cast

from easylic.common.models import SessionData


class DataPersistence:
    """Handles loading and saving persistent data."""

    @staticmethod
    def _serialize_session_data(session_data: SessionData) -> dict[str, Any]:
        """Serialize SessionData to JSON-serializable format."""
        data = session_data.model_dump()
        for key, value in data.items():
            if isinstance(value, bytes):
                data[key] = base64.b64encode(value).decode("utf-8")
        return data

    @staticmethod
    def _deserialize_session_data(data: dict[str, Any]) -> SessionData:
        """Deserialize SessionData from JSON format."""
        for key, value in data.items():
            if (
                key
                in [
                    "session_key",
                    "root_secret",
                    "initial_nonce_prefix",
                    "last_cipher_hash",
                ]
                and value is not None
            ):
                data[key] = base64.b64decode(value)
        return SessionData(**data)

    @staticmethod
    def load_revoked_licenses(file_path: Path) -> dict[str, int]:
        """Load revoked licenses from file."""
        try:
            with file_path.open() as f:
                return cast("dict[str, int]", json.load(f))
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
                return {
                    k: DataPersistence._deserialize_session_data(v)
                    for k, v in data.items()
                }
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    @staticmethod
    def save_sessions(file_path: Path, sessions: dict[str, SessionData]) -> None:
        """Save sessions to file."""
        with file_path.open("w") as f:
            json.dump(
                {
                    k: DataPersistence._serialize_session_data(v)
                    for k, v in sessions.items()
                },
                f,
            )
