"""
License validation utilities.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from easylic.common.config import Config
    from easylic.common.models import LicenseData, Policy  # noqa: TC004

from cryptography.exceptions import InvalidSignature


class LicenseValidator:
    """Handles license validation and policy checking."""

    def __init__(
        self,
        config: Config,
        server_pub: Ed25519PublicKey,
        revoked_licenses: dict[str, int],
        revoked_licenses_file_path: Path,
    ):
        self.config = config
        self.server_pub = server_pub
        self.revoked_licenses = revoked_licenses
        self.revoked_licenses_file_path = revoked_licenses_file_path
        self.logger = logging.getLogger(__name__)

    def verify_license(self, lic: LicenseData) -> bool:
        """Verify license signature and validity."""
        payload = lic.payload
        license_id = payload.license_id
        self.logger.debug("Verifying license %s", license_id)

        sig = bytes.fromhex(lic.signature)
        data = json.dumps(
            payload.model_dump(), sort_keys=True, separators=(",", ":")
        ).encode()
        try:
            self.server_pub.verify(sig, data)
            self.logger.debug("License %s signature valid", license_id)
        except InvalidSignature:
            self.logger.info("License %s signature invalid", license_id)
            return False

        now = int(time.time())
        self.logger.debug(
            "License %s times: valid_from=%s, valid_until=%s, now=%s",
            license_id,
            payload.valid_from,
            payload.valid_until,
            now,
        )

        # Check if license is revoked
        if license_id in self.revoked_licenses:
            self.logger.info("License %s revoked", license_id)
            return False  # Revoked licenses are permanently invalid

        if not (payload.valid_from <= now <= payload.valid_until):
            self.logger.info("License %s expired or not yet valid", license_id)
            return False

        self.logger.debug("License %s valid", license_id)
        return True

    def validate_policy(self, policy: dict) -> bool:
        """Server-side validation for policy."""
        try:
            Policy(**policy)
            return policy.get("version") == self.config.POLICY_VERSION
        except (ValueError, TypeError):
            return False
