"""Common cryptographic utilities.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoUtils:
    """Utility class for cryptographic operations."""

    @staticmethod
    def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
        """Calculate nonce prefix for a given epoch."""
        epoch_bytes = epoch.to_bytes(4, "big")
        return bytes(
            a ^ b for a, b in zip(initial_nonce_prefix, epoch_bytes, strict=False)
        )

    @staticmethod
    def derive_session_key(
        root_secret: bytes,
        license_id: str,
        session_id: str,
        rekey_epoch: int = 0,
        effective_nonce_prefix_hex: str = "",
    ) -> bytes:
        """Derive session key from root secret."""
        salt = (license_id + session_id + effective_nonce_prefix_hex).encode()
        info = f"epoch:{rekey_epoch}".encode()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(root_secret)
