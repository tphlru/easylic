"""
Configuration settings for the license management system.
"""

import os
import logging
from pathlib import Path
from typing import Dict


class Config:
    """Central configuration class for all system settings."""

    # Session and security settings
    SESSION_TTL: int = 30  # Session time to live in seconds
    MAX_COUNTER: int = 2**40  # Prevent nonce reuse: max 1e12 renewals per session
    MAX_START_ATTEMPTS_PER_MINUTE: int = 10  # Rate limit /start to prevent replay DoS
    MAX_CIPHERTEXT_LEN: int = 10 * 1024  # 10KB, prevent DoS
    MAX_USED_EPH_PUBS_PER_LICENSE: int = 100  # Prevent memory exhaustion from flood attacks

    # Renew and rekey settings (defaults, can be overridden in class constructors)
    RENEW_INTERVAL_DEFAULT: int = 10  # Seconds between renew requests
    REKEY_AFTER_RENEWS_DEFAULT: int = 10  # Number of renews before rekeying

    # Required security features that clients must support
    REQUIRED_FEATURES: Dict[str, bool] = {
        "secure_channel": True,  # ChaCha20Poly1305 AEAD
        "counter": True,         # Monotonic counter for nonces
        "pop": True,             # Proof of possession with Ed25519
        "transcript_binding": True,  # Channel binding to handshake transcript
        "rekey": True,           # Periodic key rotation
        "proofs": True,          # Client/server finished proofs
    }

    # Server settings
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin123")  # Change this to a secure password
    SERVER_HOST: str = os.getenv("SERVER_HOST", "127.0.0.1")
    SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))
    SERVER_URL: str = f"http://{SERVER_HOST}:{SERVER_PORT}"

    # File paths
    BASE_DIR: Path = Path(__file__).parent.parent
    SERVER_KEYS_DIR: Path = Path(os.getenv("EASYLIC_KEYS_DIR", str(BASE_DIR / "server")))
    SERVER_PUBLIC_KEY_PATH: Path = SERVER_KEYS_DIR / "server_public.key"
    SERVER_PRIVATE_KEY_PATH: Path = SERVER_KEYS_DIR / "server_private.key"
    LICENSE_FILE_PATH: Path = BASE_DIR / "server" / "license.json"
    REVOKED_LICENSES_FILE_PATH: Path = BASE_DIR / "server" / "revoked_licenses.json"

    # Protocol constants
    PROTOCOL_VERSION: int = 1
    CIPHER_SUITE: str = "v1:ChaCha20Poly1305"
    POLICY_VERSION: str = "1.0"

    # Logging
    LOG_LEVEL: int = logging.INFO

    @classmethod
    def get_server_keys(cls):
        """Load server keys from files."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
        from typing import cast

        try:
            with open(cls.SERVER_PUBLIC_KEY_PATH, "rb") as f:
                server_pub = cast(Ed25519PublicKey, serialization.load_pem_public_key(f.read()))
            with open(cls.SERVER_PRIVATE_KEY_PATH, "rb") as f:
                server_priv = cast(Ed25519PrivateKey, serialization.load_pem_private_key(f.read(), None))
        except FileNotFoundError:
            raise ValueError(
                f"Server keys not found at {cls.SERVER_PUBLIC_KEY_PATH} and {cls.SERVER_PRIVATE_KEY_PATH}. "
                "Run 'easylic-keygen' to generate them."
            )

        return server_pub, server_priv