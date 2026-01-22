"""
Configuration settings for the license management system.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )


class Config:
    """Central configuration class for all system settings."""

    def __init__(self) -> None:
        # Session and security settings
        self.SESSION_TTL: int = 30  # Session time to live in seconds
        self.MAX_COUNTER: int = (
            2**40
        )  # Prevent nonce reuse: max 1e12 renewals per session
        self.MAX_START_ATTEMPTS_PER_MINUTE: int = (
            10  # Rate limit /start to prevent replay DoS
        )
        self.MAX_CIPHERTEXT_LEN: int = 10 * 1024  # 10KB, prevent DoS
        self.MAX_USED_EPH_PUBS_PER_LICENSE: int = (
            100  # Prevent memory exhaustion from flood attacks
        )

        # Renew and rekey settings (defaults, can be overridden in class constructors)
        self.RENEW_INTERVAL: int = 10  # Seconds between renew requests
        self.REKEY_AFTER_RENEWS: int = 10  # Number of renews before rekeying
        self.RENEW_RATE_LIMIT: float = 0.1  # Minimum seconds between renews

        # Required security features that clients must support
        self.REQUIRED_FEATURES: dict[str, bool] = {
            "secure_channel": True,  # ChaCha20Poly1305 AEAD
            "counter": True,  # Monotonic counter for nonces
            "pop": True,  # Proof of possession with Ed25519
            "transcript_binding": True,  # Channel binding to handshake transcript
            "rekey": True,  # Periodic key rotation
            "proofs": True,  # Client/server finished proofs
        }

        # Server settings
        self.ADMIN_PASSWORD: str | None = os.getenv("ADMIN_PASSWORD")
        self.SERVER_HOST: str = os.getenv("SERVER_HOST", "127.0.0.1")
        self.SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))
        self.SERVER_URL: str = f"http://{self.SERVER_HOST}:{self.SERVER_PORT}"

        # File paths
        self.BASE_DIR: Path = Path(__file__).parent.parent
        self.DATA_DIR: Path = self.BASE_DIR / "data"
        self.SERVER_KEYS_DIR: Path = Path(
            os.getenv("EASYLIC_KEYS_DIR", str(self.BASE_DIR / "server"))
        )
        self.SERVER_PUBLIC_KEY_PATH: Path = self.SERVER_KEYS_DIR / "server_public.key"
        self.SERVER_PRIVATE_KEY_PATH: Path = self.SERVER_KEYS_DIR / "server_private.key"
        self.LICENSE_FILE_PATH: Path = self.DATA_DIR / "license.json"
        self.REVOKED_LICENSES_FILE_PATH: Path = self.DATA_DIR / "revoked_licenses.json"

        # Protocol constants
        self.PROTOCOL_VERSION: int = 1
        self.CIPHER_SUITE: str = "v1:ChaCha20Poly1305"
        self.POLICY_VERSION: str = "1.0"

        # Logging
        self.LOG_LEVEL: int = logging.DEBUG

    def get_server_keys(self) -> tuple[Ed25519PublicKey, Ed25519PrivateKey]:
        """Load server keys from files."""
        try:
            with self.SERVER_PUBLIC_KEY_PATH.open("rb") as f:
                server_pub = cast(
                    "Ed25519PublicKey", serialization.load_pem_public_key(f.read())
                )
            with self.SERVER_PRIVATE_KEY_PATH.open("rb") as f:
                server_priv = cast(
                    "Ed25519PrivateKey",
                    serialization.load_pem_private_key(f.read(), None),
                )
        except FileNotFoundError as err:
            msg = (
                f"Server keys not found at {self.SERVER_PUBLIC_KEY_PATH} and {self.SERVER_PRIVATE_KEY_PATH}. "
                "Run 'easylic-keygen' to generate them."
            )
            raise ValueError(msg) from err

        return server_pub, server_priv
