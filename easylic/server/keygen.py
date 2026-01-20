"""
OOP-based key generator for server Ed25519 keys.
"""

import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ..common.config import Config


class KeyGenerator:
    """Key generator for creating server Ed25519 keys."""

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
        os.makedirs(Config.SERVER_PUBLIC_KEY_PATH.parent, exist_ok=True)

        # Save keys
        with open(Config.SERVER_PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_pem)

        with open(Config.SERVER_PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_pem)

        print("Keys generated and saved:")
        print(f"  Private: {Config.SERVER_PRIVATE_KEY_PATH}")
        print(f"  Public: {Config.SERVER_PUBLIC_KEY_PATH}")
        print("Keep the private key secure!")


def main():
    """Generate and save server public/private keys."""
    KeyGenerator().generate_keys()


if __name__ == "__main__":
    main()