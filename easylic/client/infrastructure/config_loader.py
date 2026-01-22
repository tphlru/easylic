"""
Infrastructure layer: Configuration loading and file operations.
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
from easylic.common.models import LicenseData


class ConfigLoader(Configurable):
    """Handles loading configuration, keys, and license data from files."""

    def __init__(
        self,
        server_url: str | None = None,
        license_file: str | None = None,
        log_level: int | None = None,
        renew_interval: int | None = None,
        session_ttl: int | None = None,
        max_counter: int | None = None,
        max_start_attempts_per_minute: int | None = None,
        max_ciphertext_len: int | None = None,
        max_used_eph_pubs_per_license: int | None = None,
        server_host: str | None = None,
        server_port: int | None = None,
        base_dir: Path | None = None,
        server_keys_dir: Path | None = None,
        license_file_path: Path | None = None,
        revoked_licenses_file_path: Path | None = None,
    ):
        self.config: Config = Config()

        # Compute server_url if host and port provided
        if server_host and server_port:
            self.server_url = f"http://{server_host}:{server_port}"
        else:
            self.server_url = server_url or self.config.SERVER_URL

        # Configurable paths
        self.base_dir = base_dir or self.config.BASE_DIR
        self.server_keys_dir = (
            Path(server_keys_dir) if server_keys_dir else self.config.SERVER_KEYS_DIR
        )
        self.license_file_path = license_file_path or self.config.LICENSE_FILE_PATH
        self.revoked_licenses_file_path = (
            revoked_licenses_file_path or self.config.REVOKED_LICENSES_FILE_PATH
        )

        self.license_file = license_file or str(self.license_file_path)
        self.session_ttl = session_ttl
        self.max_counter = max_counter
        self.max_start_attempts_per_minute = max_start_attempts_per_minute
        self.max_ciphertext_len = max_ciphertext_len
        self.log_level: int = (
            log_level if log_level is not None else self.config.LOG_LEVEL
        )
        self.renew_interval: int = (
            renew_interval
            if renew_interval is not None
            else self.config.RENEW_INTERVAL_DEFAULT
        )
        self.session_ttl = (
            session_ttl if session_ttl is not None else self.config.SESSION_TTL
        )
        self.max_counter = (
            max_counter if max_counter is not None else self.config.MAX_COUNTER
        )
        self.max_start_attempts_per_minute = (
            max_start_attempts_per_minute
            if max_start_attempts_per_minute is not None
            else self.config.MAX_START_ATTEMPTS_PER_MINUTE
        )
        self.max_ciphertext_len = (
            max_ciphertext_len
            if max_ciphertext_len is not None
            else self.config.MAX_CIPHERTEXT_LEN
        )
        self.max_used_eph_pubs_per_license = (
            max_used_eph_pubs_per_license
            if max_used_eph_pubs_per_license is not None
            else self.config.MAX_USED_EPH_PUBS_PER_LICENSE
        )

        # Setup logging
        self.logger = logging.getLogger(__name__)
        setup_logger(self.logger, self.log_level)

    def load_server_public_key(self) -> Ed25519PublicKey:
        """Load the server public key from file."""
        with (self.server_keys_dir / "server_public.key").open("rb") as key_f:
            return cast(
                "Ed25519PublicKey", serialization.load_pem_public_key(key_f.read())
            )

    def load_license(self) -> LicenseData:
        """Load the license data from file."""
        with Path(self.license_file).open() as lic_f:
            return LicenseData.model_validate_json(lic_f.read())

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
