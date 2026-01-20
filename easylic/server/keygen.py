"""
OOP-based key generator for server Ed25519 keys.
"""

import os
from typing import Optional
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ..common.config import Config


class KeyGenerator:
    """Key generator for creating server Ed25519 keys."""

    def __init__(self, keys_dir: Optional[Path] = None):
        self.keys_dir = keys_dir or Config.SERVER_KEYS_DIR

    def generate_keys(self):
        """Generate and save server public/private keys."""
        print("Generating Ed25519 server keys...")

        # Generate private key
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Ensure directory exists
        private_path = self.keys_dir / "server_private.key"
        public_path = self.keys_dir / "server_public.key"
        os.makedirs(self.keys_dir, exist_ok=True)

        # Save keys
        with open(private_path, "wb") as f:
            f.write(private_pem)

        with open(public_path, "wb") as f:
            f.write(public_pem)

        print("Keys generated and saved:")
        print(f"  Private: {private_path}")
        print(f"  Public: {public_path}")
        print("Keep the private key secure!")


def main():
    """Generate and save server public/private keys."""
    keys_dir = os.getenv("EASYLIC_KEYS_DIR")
    keygen = KeyGenerator(keys_dir=Path(keys_dir) if keys_dir else None)
    keygen.generate_keys()


if __name__ == "__main__":
    main()