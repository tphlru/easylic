"""Domain layer: Core business entities and rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from easylic.common.models import LicenseData


@dataclass
class SessionState:
    """Domain entity representing session state."""

    session_id: str | None = None
    counter: int = 0
    rekey_epoch: int = 0
    is_active: bool = False


@dataclass
class License:
    """Domain entity representing a license."""

    data: LicenseData
    file_path: Path

    @property
    def license_id(self) -> str:
        return self.data.payload.license_id


@dataclass
class ClientKeys:
    """Domain entity representing client cryptographic keys."""

    identity_private: Ed25519PrivateKey
    identity_public_hex: str
    ephemeral_private: X25519PrivateKey
    ephemeral_public_hex: str
