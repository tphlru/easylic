"""
License validation utilities.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cryptography.exceptions import InvalidSignature

from easylic.common.config import Config
from easylic.common.models import LicenseData, Policy


class LicenseValidator:
    """Handles license validation and policy checking."""

    def __init__(
        self,
        config: "Config",
        server_pub: Ed25519PublicKey,
        revoked_licenses: dict[str, int],
        revoked_licenses_file_path: Path,
    ):
        self.config = config
        self.server_pub = server_pub
        self.revoked_licenses = revoked_licenses
        self.revoked_licenses_file_path = revoked_licenses_file_path

    def verify_license(self, lic: LicenseData) -> bool:
        """Verify license signature and validity."""
        payload = lic.payload
        sig = bytes.fromhex(lic.signature)
        data = json.dumps(
            payload.model_dump(), sort_keys=True, separators=(",", ":")
        ).encode()
        try:
            self.server_pub.verify(sig, data)
        except InvalidSignature:
            return False
        now = int(time.time())

        # Check if license is revoked
        license_id = payload.license_id
        if license_id in self.revoked_licenses:
            return False  # Revoked licenses are permanently invalid

        return payload.valid_from <= now <= payload.valid_until

    def validate_policy(self, policy: dict) -> bool:
        """Server-side validation for policy."""
        try:
            Policy(**policy)
            return policy.get("version") == self.config.POLICY_VERSION
        except (ValueError, TypeError):
            return False
