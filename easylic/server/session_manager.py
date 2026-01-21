"""
Session management for license server.
"""

from __future__ import annotations

import time
from pathlib import Path

from easylic.common.models import SessionData

from .persistence import DataPersistence

START_ATTEMPT_TTL = 60
USED_EPH_PUB_TTL = 60


class SessionManager:
    """Manages sessions and related state."""

    def __init__(self, max_used_eph_pubs_per_license: int, sessions_file_path: Path):
        self.sessions: dict[str, SessionData] = DataPersistence.load_sessions(
            sessions_file_path
        )
        self.start_attempts: dict[str, list[int]] = {}
        self.used_client_eph_pubs: dict[str, dict[bytes, int]] = {}
        self.max_used_eph_pubs_per_license = max_used_eph_pubs_per_license
        self.sessions_file_path = sessions_file_path

    def clean_expired_sessions(self) -> None:
        """Clean expired sessions and related data."""
        now = int(time.time())
        expired = [sid for sid, sess in self.sessions.items() if sess.expires_at < now]
        for sid in expired:
            self.sessions.pop(sid, None)

        # Clean expired start attempts (TTL 60s)
        for lid in list(self.start_attempts.keys()):
            self.start_attempts[lid] = [
                t for t in self.start_attempts[lid] if now - t < START_ATTEMPT_TTL
            ]
            if not self.start_attempts[lid]:
                del self.start_attempts[lid]

        # Clean expired used client eph pubs (TTL 60s)
        for lid in list(self.used_client_eph_pubs.keys()):
            for pub in list(self.used_client_eph_pubs[lid].keys()):
                if now - self.used_client_eph_pubs[lid][pub] > USED_EPH_PUB_TTL:
                    del self.used_client_eph_pubs[lid][pub]
            # Enforce upper bound to prevent memory exhaustion
            if len(self.used_client_eph_pubs[lid]) > self.max_used_eph_pubs_per_license:
                sorted_items = sorted(
                    self.used_client_eph_pubs[lid].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
                self.used_client_eph_pubs[lid] = dict(
                    sorted_items[: self.max_used_eph_pubs_per_license]
                )
            if not self.used_client_eph_pubs[lid]:
                del self.used_client_eph_pubs[lid]

    def get_active_sessions_count(self, license_id: str) -> int:
        """Get number of active sessions for a license."""
        return len([s for s in self.sessions.values() if s.license_id == license_id])

    def add_session(self, session_id: str, session_data: SessionData) -> None:
        """Add a new session."""
        self.sessions[session_id] = session_data
        self._save_sessions()

    def get_session(self, session_id: str) -> SessionData | None:
        """Get session by ID."""
        return self.sessions.get(session_id)

    def remove_session(self, session_id: str) -> None:
        """Remove a session."""
        self.sessions.pop(session_id, None)
        self._save_sessions()

    def _save_sessions(self) -> None:
        """Save sessions to file."""
        DataPersistence.save_sessions(self.sessions_file_path, self.sessions)

    def revoke_sessions_for_license(self, license_id: str) -> None:
        """Remove all sessions for a license."""
        expired_sessions = [
            sid for sid, sess in self.sessions.items() if sess.license_id == license_id
        ]
        for sid in expired_sessions:
            self.sessions.pop(sid, None)
        self._save_sessions()

    def check_start_attempt_rate(self, license_id: str, max_attempts: int) -> bool:
        """Check if start attempt is allowed."""
        now = int(time.time())
        if license_id not in self.start_attempts:
            self.start_attempts[license_id] = []
        self.start_attempts[license_id] = [
            t for t in self.start_attempts[license_id] if now - t < START_ATTEMPT_TTL
        ]
        if len(self.start_attempts[license_id]) >= max_attempts:
            return False
        self.start_attempts[license_id].append(now)
        return True

    def record_used_eph_pub(self, license_id: str, pub_bytes: bytes) -> None:
        """Record used ephemeral public key."""
        if license_id not in self.used_client_eph_pubs:
            self.used_client_eph_pubs[license_id] = {}
        self.used_client_eph_pubs[license_id][pub_bytes] = int(time.time())

    def is_eph_pub_used(self, license_id: str, pub_bytes: bytes) -> bool:
        """Check if ephemeral public key was used."""
        return pub_bytes in self.used_client_eph_pubs.get(license_id, {})
