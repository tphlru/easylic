"""
OOP-based key generator for server Ed25519 keys.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from easylic.common.config import Config

logger = logging.getLogger(__name__)


class KeyGenerator:
    """Key generator for creating server Ed25519 keys."""

    def __init__(self, keys_dir: Path | None = None):
        config = Config()
        self.keys_dir = keys_dir or config.SERVER_KEYS_DIR

    def generate_keys(self) -> None:
        """Generate and save server public/private keys."""
        logger.info("Generating Ed25519 server keys...")

        # Generate private key
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Ensure directory exists
        private_path = self.keys_dir / "server_private.key"
        public_path = self.keys_dir / "server_public.key"
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        # Save keys
        with private_path.open("wb") as f:
            f.write(private_pem)

        with public_path.open("wb") as f:
            f.write(public_pem)

        logger.info("Keys generated and saved:")
        logger.info("  Private: %s", private_path)
        logger.info("  Public: %s", public_path)
        logger.info("Keep the private key secure!")
