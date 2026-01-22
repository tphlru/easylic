"""
OOP-based license client.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from easylic.common import Configurable, setup_logger
from easylic.common.config import Config
from easylic.common.models import (
    LicenseData,
)

from .session_handler import SessionHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def error_handler(error: Exception) -> None:
    logger.info("License error occurred: %s", error)
    # Custom error handling logic here


class LicenseClient(Configurable):
    """License client for secure session management."""

    def __init__(
        self,
        server_url: str | None = None,
        license_file: str | None = None,
        log_level: int | None = None,
        on_error_callback: Callable[[Exception], None] | None = None,
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
        self.server_keys_dir = server_keys_dir or self.config.SERVER_KEYS_DIR
        self.license_file_path = license_file_path or self.config.LICENSE_FILE_PATH
        self.revoked_licenses_file_path = (
            revoked_licenses_file_path or self.config.REVOKED_LICENSES_FILE_PATH
        )

        self.license_file = license_file or self.license_file_path
        self.on_error_callback = on_error_callback
        self.session_ttl = session_ttl
        self.max_counter = max_counter
        self.max_start_attempts_per_minute = max_start_attempts_per_minute
        self.max_ciphertext_len = max_ciphertext_len
        self.log_level: int = (
            log_level if log_level is not None else self.config.LOG_LEVEL
        )
        self.on_error_callback = on_error_callback
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
        self._thread: threading.Thread | None = None

        # Setup logging
        self.logger = logging.getLogger(__name__)
        setup_logger(self.logger, self.log_level)

        # Load server public key
        with (self.server_keys_dir / "server_public.key").open("rb") as key_f:
            self.server_pub: Ed25519PublicKey = cast(
                "Ed25519PublicKey", serialization.load_pem_public_key(key_f.read())
            )

        # Load license
        with Path(self.license_file).open() as lic_f:
            self.license = LicenseData.model_validate_json(lic_f.read())

        # Generate client keys
        self.client_priv: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self.client_pub_hex: str = (
            self.client_priv.public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            .hex()
        )

        # ephemeral transport key
        self.client_eph_priv: X25519PrivateKey = X25519PrivateKey.generate()
        self.client_eph_pub_hex: str = (
            self.client_eph_priv.public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            .hex()
        )

        # Initialize session handler
        self.session_handler = SessionHandler(
            server_url=self.server_url,
            license_data=self.license,
            client_priv=self.client_priv,
            client_pub_hex=self.client_pub_hex,
            client_eph_priv=self.client_eph_priv,
            client_eph_pub_hex=self.client_eph_pub_hex,
            server_pub=self.server_pub,
            config=self.config,
        )

    @property
    def session_id(self) -> str | None:
        return self.session_handler.session_id

    @property
    def counter(self) -> int:
        return self.session_handler.counter

    @property
    def rekey_epoch(self) -> int:
        return self.session_handler.rekey_epoch

    @staticmethod
    def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
        """Calculate nonce prefix for a given epoch."""
        epoch_bytes = epoch.to_bytes(4, "big")
        return bytes(a ^ b for a, b in zip(initial_nonce_prefix, epoch_bytes))

    def start_session(self) -> str:
        """Start a secure session with the server."""
        return self.session_handler.start_session()

    def is_license_active(self) -> bool:
        """Check if the license is currently active (session is valid)."""
        return self.session_handler.is_license_active()

    def renew_session(self) -> bool:
        """Renew the current session."""
        return self.session_handler.renew_session()

    def run(self) -> None:
        """Run the client loop."""
        try:
            self.start_session()
            while True:
                time.sleep(self.renew_interval)
                if not self.renew_session():
                    if self.on_error_callback:
                        self.on_error_callback(Exception("Session renewal failed"))
                    break
        except Exception as e:
            self.logger.exception("Client error")
            if self.on_error_callback:
                self.on_error_callback(e)
            raise

    def start_in_thread(self) -> None:
        """Start the client in a separate thread."""
        if self._thread and self._thread.is_alive():
            self.logger.warning("Client is already running in a thread")
            return
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        self.logger.info("Client started in background thread")

    def stop_thread(self) -> None:
        """Stop the background thread (not implemented, use daemon thread)."""
        # Since it's daemon, it will stop when main thread exits
