"""
OOP-based license generator.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any, cast

from cryptography.hazmat.primitives import serialization

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from easylic.common.config import Config
from easylic.common.models import LicenseData, LicensePayload, Policy


class LicenseGenerator:
    """License generator for creating signed licenses."""

    def __init__(
        self,
        config: "Config | None" = None,
        server_priv: "Ed25519PrivateKey | None" = None,
        log_level: int | None = None,
    ):
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        self.log_level = log_level if log_level is not None else self.config.LOG_LEVEL
        self.logger.setLevel(self.log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(self.log_level)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.server_priv = server_priv or self._load_private_key()

    def _load_private_key(self) -> Ed25519PrivateKey:
        """Load server private key."""
        with self.config.SERVER_PRIVATE_KEY_PATH.open("rb") as f:
            return cast(
                "Ed25519PrivateKey", serialization.load_pem_private_key(f.read(), None)
            )

    def sign(self, obj: dict[str, Any]) -> str:
        """Sign a dictionary object."""
        data = json.dumps(obj, sort_keys=True).encode()
        return self.server_priv.sign(data).hex()

    def validate_policy(self, policy: dict[str, Any]) -> bool:
        """Validate policy structure."""
        try:
            Policy(**policy)
            return policy.get("version") == self.config.POLICY_VERSION
        except (ValueError, TypeError):
            return False

    def generate_license(
        self,
        license_id: str,
        product: str,
        valid_from: int,
        valid_until: int,
        policy: dict,
    ) -> LicenseData:
        """Generate a signed license."""
        if not self.validate_policy(policy):
            msg = "Invalid policy"
            raise ValueError(msg)
        payload = LicensePayload(
            license_id=license_id,
            product=product,
            valid_from=valid_from,
            valid_until=valid_until,
            policy=policy,
        )
        signature = self.sign(payload.model_dump())
        return LicenseData(payload=payload, signature=signature)

    def interactive_generate(self) -> LicenseData | None:
        """Interactive license generation."""
        self.logger.info("Interactive License Generator")
        license_id = input("License ID: ").strip()
        product = input("Product: ").strip()

        valid_from_str = input("Valid from (Unix timestamp or 'now'): ").strip()
        if valid_from_str.lower() == "now":
            valid_from = int(time.time())
        else:
            valid_from = int(valid_from_str)

        valid_until_str = input("Valid until (Unix timestamp or 'never'): ").strip()
        if valid_until_str.lower() == "never":
            valid_until = 2147483647  # Far future
        else:
            valid_until = int(valid_until_str)

        max_sessions = int(input("Max sessions: ").strip())
        features_str = input("Features (comma-separated, optional): ").strip()
        features = [f.strip() for f in features_str.split(",")] if features_str else []

        policy = {
            "max_sessions": max_sessions,
            "version": self.config.POLICY_VERSION,
            "features": features,
        }

        try:
            license_data = self.generate_license(
                license_id, product, valid_from, valid_until, policy
            )
        except ValueError:
            self.logger.exception("Error")
            return None
        else:
            self.logger.info("Generated License:")
            self.logger.info(json.dumps(license_data.model_dump(), indent=2))
            return license_data
