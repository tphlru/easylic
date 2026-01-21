"""
Interfaces and protocols for dependency injection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from easylic.common.models import LicenseData, SessionData


class IDataPersistence(Protocol):
    """Protocol for data persistence operations."""

    @staticmethod
    def load_revoked_licenses(file_path: Path) -> dict[str, int]: ...

    @staticmethod
    def save_revoked_licenses(
        file_path: Path, revoked_licenses: dict[str, int]
    ) -> None: ...

    @staticmethod
    def load_sessions(file_path: Path) -> dict[str, SessionData]: ...

    @staticmethod
    def save_sessions(file_path: Path, sessions: dict[str, SessionData]) -> None: ...


class ISessionManager(Protocol):
    """Protocol for session management."""

    def clean_expired_sessions(self) -> None: ...

    def get_active_sessions_count(self, license_id: str) -> int: ...

    def add_session(self, session_id: str, session_data: SessionData) -> None: ...

    def get_session(self, session_id: str) -> SessionData | None: ...

    def remove_session(self, session_id: str) -> None: ...

    def revoke_sessions_for_license(self, license_id: str) -> None: ...

    def check_start_attempt_rate(self, license_id: str, max_attempts: int) -> bool: ...

    def record_used_eph_pub(self, license_id: str, pub_bytes: bytes) -> None: ...

    def is_eph_pub_used(self, license_id: str, pub_bytes: bytes) -> bool: ...


class ILicenseValidator(Protocol):
    """Protocol for license validation."""

    revoked_licenses: dict[str, int]
    revoked_licenses_file_path: Path

    def verify_license(self, lic: LicenseData) -> bool: ...

    def validate_policy(self, policy: dict) -> bool: ...


class ILicenseGenerator(Protocol):
    """Protocol for license generation."""

    def sign(self, obj: dict[str, str | int | dict]) -> str: ...

    def validate_policy(self, policy: dict[str, str | int | dict]) -> bool: ...

    def generate_license(
        self,
        license_id: str,
        product: str,
        valid_from: int,
        valid_until: int,
        policy: dict,
    ) -> LicenseData: ...
