"""
OOP-based license server using FastAPI.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from typing import TYPE_CHECKING

from fastapi import FastAPI

from easylic.common.config import Config

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

from .license_generator import LicenseGenerator
from .license_validator import LicenseValidator
from .persistence import DataPersistence
from .routes import LicenseRoutes
from .services import LicenseService
from .session_manager import SessionManager


class LicenseServer:
    """Main license server class handling all operations."""

    def __init__(self, config: "Config | None" = None, **overrides: Any) -> None:
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        self.log_level = overrides.get("log_level", self.config.LOG_LEVEL)
        self.logger.setLevel(self.log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(self.log_level)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.rekey_after_renews = overrides.get(
            "rekey_after_renews", self.config.REKEY_AFTER_RENEWS_DEFAULT
        )
        self.session_ttl = overrides.get("session_ttl", self.config.SESSION_TTL)
        self.max_counter = overrides.get("max_counter", self.config.MAX_COUNTER)
        self.max_start_attempts_per_minute = overrides.get(
            "max_start_attempts_per_minute", self.config.MAX_START_ATTEMPTS_PER_MINUTE
        )
        self.max_ciphertext_len = overrides.get(
            "max_ciphertext_len", self.config.MAX_CIPHERTEXT_LEN
        )
        self.max_used_eph_pubs_per_license = overrides.get(
            "max_used_eph_pubs_per_license", self.config.MAX_USED_EPH_PUBS_PER_LICENSE
        )
        self.admin_password = overrides.get(
            "admin_password", self.config.ADMIN_PASSWORD
        )
        self.server_host = overrides.get("server_host", self.config.SERVER_HOST)
        self.server_port = overrides.get("server_port", self.config.SERVER_PORT)
        self.base_dir = overrides.get("base_dir", self.config.BASE_DIR)
        self.server_keys_dir = overrides.get(
            "server_keys_dir", self.config.SERVER_KEYS_DIR
        )
        self.license_file_path = overrides.get(
            "license_file_path", self.config.LICENSE_FILE_PATH
        )
        self.revoked_licenses_file_path = overrides.get(
            "revoked_licenses_file_path", self.config.REVOKED_LICENSES_FILE_PATH
        )
        self.app = FastAPI()
        server_priv = overrides.get("server_priv")
        if server_priv is None:
            self.server_pub, self.server_priv = self._get_server_keys()
        else:
            self.server_priv = server_priv
            self.server_pub = self.server_priv.public_key()

        # Initialize components
        self.revoked_licenses: dict[str, int] = DataPersistence.load_revoked_licenses(
            self.revoked_licenses_file_path
        )
        self.session_manager = overrides.get("session_manager") or SessionManager(
            self.max_used_eph_pubs_per_license, self.config.DATA_DIR / "sessions.json"
        )
        self.license_validator = overrides.get("license_validator") or LicenseValidator(
            self.config,
            self.server_pub,
            self.revoked_licenses,
            self.revoked_licenses_file_path,
        )
        self.license_generator = overrides.get("license_generator") or LicenseGenerator(
            self.config, self.server_priv
        )
        self.data_persistence = DataPersistence()

        # Initialize service and routes
        self.service = LicenseService(
            config=self.config,
            session_manager=self.session_manager,
            license_validator=self.license_validator,
            license_generator=self.license_generator,
            rekey_after_renews=self.rekey_after_renews,
            session_ttl=self.session_ttl,
            max_counter=self.max_counter,
            max_start_attempts_per_minute=self.max_start_attempts_per_minute,
            max_ciphertext_len=self.max_ciphertext_len,
            logger=self.logger,
        )
        self.routes = LicenseRoutes(self.service, self.admin_password)
        self.routes.setup_routes(self.app)

        # Log required client configuration
        self.logger.info(
            "Server started on http://%s:%s", self.server_host, self.server_port
        )
        self.logger.info(
            "Client must set server_url='http://%s:%s' to connect",
            self.server_host,
            self.server_port,
        )

    def _get_server_keys(self) -> tuple[Ed25519PublicKey, Ed25519PrivateKey]:
        """Load server keys from files using configured paths."""
        return self.config.get_server_keys()
