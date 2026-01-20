"""
OOP-based license generator.
"""

import json
import time
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing import cast
from cryptography.hazmat.primitives import serialization
from ..common.config import Config
from ..common.models import LicenseData, LicensePayload, Policy


class LicenseGenerator:
    """License generator for creating signed licenses."""

    def __init__(self, log_level: int = Config.LOG_LEVEL):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(log_level)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.server_priv: Ed25519PrivateKey = self._load_private_key()

    def _load_private_key(self) -> Ed25519PrivateKey:
        """Load server private key."""
        with open(Config.SERVER_PRIVATE_KEY_PATH, "rb") as f:
            return cast(Ed25519PrivateKey, serialization.load_pem_private_key(f.read(), None))

    def sign(self, obj: dict) -> str:
        """Sign a dictionary object."""
        data = json.dumps(obj, sort_keys=True).encode()
        return self.server_priv.sign(data).hex()

    def validate_policy(self, policy: dict) -> bool:
        """Validate policy structure."""
        try:
            Policy(**policy)
            return policy.get("version") == Config.POLICY_VERSION
        except Exception:
            return False

    def generate_license(self, license_id: str, product: str, valid_from: int, valid_until: int, policy: dict) -> LicenseData:
        """Generate a signed license."""
        if not self.validate_policy(policy):
            raise ValueError("Invalid policy")
        payload = LicensePayload(
            license_id=license_id,
            product=product,
            valid_from=valid_from,
            valid_until=valid_until,
            policy=policy
        )
        signature = self.sign(payload.model_dump())
        return LicenseData(payload=payload, signature=signature)

    def interactive_generate(self):
        """Interactive license generation."""
        self.logger.info("Interactive License Generator")
        license_id = input("License ID: ").strip()
        product = input("Product: ").strip()

        valid_from_str = input("Valid from (Unix timestamp or 'now'): ").strip()
        if valid_from_str.lower() == 'now':
            valid_from = int(time.time())
        else:
            valid_from = int(valid_from_str)

        valid_until_str = input("Valid until (Unix timestamp or 'never'): ").strip()
        if valid_until_str.lower() == 'never':
            valid_until = 2147483647  # Far future
        else:
            valid_until = int(valid_until_str)

        max_sessions = int(input("Max sessions: ").strip())
        features_str = input("Features (comma-separated, optional): ").strip()
        features = [f.strip() for f in features_str.split(',')] if features_str else []

        policy = {
            "max_sessions": max_sessions,
            "version": Config.POLICY_VERSION,
            "features": features
        }

        try:
            license_data = self.generate_license(license_id, product, valid_from, valid_until, policy)
            self.logger.info("Generated License:")
            self.logger.info(json.dumps(license_data.model_dump(), indent=2))
            return license_data
        except ValueError as e:
            self.logger.error(f"Error: {e}")
            return None


def main():
    # Example: set log level via argument or default
    generator = LicenseGenerator(log_level=logging.INFO)
    generator.interactive_generate()


if __name__ == "__main__":
    main()