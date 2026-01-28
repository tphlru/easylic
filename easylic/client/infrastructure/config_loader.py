"""Infrastructure layer: Configuration loading and file operations.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from easylic.common import Configurable, setup_logger
from easylic.common.config import Config
from easylic.common.models import ClientConfig, LicenseData


class ConfigLoader(Configurable):
    """Handles loading configuration, keys, and license data from files."""

    def __init__(self, client_config: ClientConfig):
        self.config: Config = Config()

        # Compute server_url if host and port provided
        if client_config.server_host and client_config.server_port:
            self.server_url = (
                f"http://{client_config.server_host}:{client_config.server_port}"
            )
        else:
            self.server_url = client_config.server_url or self.config.SERVER_URL

        # Configurable paths
        self.base_dir = client_config.base_dir or self.config.BASE_DIR
        self.server_keys_dir = (
            client_config.server_keys_dir or self.config.SERVER_KEYS_DIR
        )
        self.license_file_path = (
            client_config.license_file_path or self.config.LICENSE_FILE_PATH
        )
        self.revoked_licenses_file_path = (
            client_config.revoked_licenses_file_path
            or self.config.REVOKED_LICENSES_FILE_PATH
        )

        self.license_file = client_config.license_file or str(self.license_file_path)
        self.log_level: int = (
            client_config.log_level
            if client_config.log_level is not None
            else self.config.LOG_LEVEL
        )
        self.renew_interval: int = (
            client_config.renew_interval
            if client_config.renew_interval is not None
            else self.config.RENEW_INTERVAL
        )
        self.session_ttl = (
            client_config.session_ttl
            if client_config.session_ttl is not None
            else self.config.SESSION_TTL
        )
        self.max_counter = (
            client_config.max_counter
            if client_config.max_counter is not None
            else self.config.MAX_COUNTER
        )
        self.max_start_attempts_per_minute = (
            client_config.max_start_attempts_per_minute
            if client_config.max_start_attempts_per_minute is not None
            else self.config.MAX_START_ATTEMPTS_PER_MINUTE
        )
        self.max_ciphertext_len = (
            client_config.max_ciphertext_len
            if client_config.max_ciphertext_len is not None
            else self.config.MAX_CIPHERTEXT_LEN
        )
        self.max_used_eph_pubs_per_license = (
            client_config.max_used_eph_pubs_per_license
            if client_config.max_used_eph_pubs_per_license is not None
            else self.config.MAX_USED_EPH_PUBS_PER_LICENSE
        )

        # Setup logging
        self.logger = logging.getLogger(__name__)
        setup_logger(self.logger, self.log_level)

    def load_server_public_key(self) -> Ed25519PublicKey:
        """Load the server public key from file."""
        key_path = self.server_keys_dir / "server_public.key"
        if not key_path.exists():
            msg = f"Server public key file not found: {key_path}"
            raise FileNotFoundError(msg)
        with key_path.open("rb") as key_f:
            return cast(
                "Ed25519PublicKey", serialization.load_pem_public_key(key_f.read())
            )

    def load_license(self) -> LicenseData:
        """Load the license data from file."""
        license_path = Path(self.license_file)
        if not license_path.exists():
            msg = f"License file not found: {license_path}"
            raise FileNotFoundError(msg)
        if license_path.stat().st_size == 0:
            msg = f"License file is empty: {license_path}"
            raise ValueError(msg)
        with license_path.open() as lic_f:
            content = lic_f.read()
        try:
            return LicenseData.model_validate_json(content)
        except Exception as e:
            msg = f"Invalid license file format in {license_path}: {e}"
            raise ValueError(msg) from e

    def generate_client_keys(
        self,
    ) -> tuple[Ed25519PrivateKey, str, X25519PrivateKey, str]:
        """Generate client cryptographic keys."""
        # Generate identity key
        client_priv: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        client_pub_hex: str = (
            client_priv.public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            .hex()
        )

        # Generate ephemeral transport key
        client_eph_priv: X25519PrivateKey = X25519PrivateKey.generate()
        client_eph_pub_hex: str = (
            client_eph_priv.public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            .hex()
        )

        return client_priv, client_pub_hex, client_eph_priv, client_eph_pub_hex
