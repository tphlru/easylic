"""
OOP-based license server using FastAPI.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Request

from easylic.common import Configurable, setup_logger
from easylic.common.config import Config
from easylic.common.exceptions import RateLimitError, ValidationError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

from easylic.server.license_generator import LicenseGenerator
from easylic.server.license_validator import LicenseValidator
from easylic.server.persistence import DataPersistence
from easylic.server.routes import LicenseRoutes
from easylic.server.services import LicenseService
from easylic.server.session_manager import SessionManager


class LicenseServer(Configurable):
    """Main license server class handling all operations."""

    # Configuration attributes (set via apply_overrides)
    rekey_after_renews: int
    session_ttl: int
    max_counter: int
    max_start_attempts_per_minute: int
    max_ciphertext_len: int
    max_used_eph_pubs_per_license: int
    admin_password: str | None
    server_host: str
    server_port: int
    base_dir: Path
    server_keys_dir: Path
    license_file_path: Path
    revoked_licenses_file_path: Path

    def __init__(
        self,
        config: Config | None = None,
        session_manager=None,
        license_validator=None,
        license_generator=None,
        data_persistence=None,
        service=None,
        routes=None,
        **overrides: Any,
    ) -> None:
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        self.log_level = overrides.get("log_level", self.config.LOG_LEVEL)
        setup_logger(self.logger, self.log_level)

        # Apply configuration overrides
        attr_list = [
            "rekey_after_renews",
            "session_ttl",
            "max_counter",
            "max_start_attempts_per_minute",
            "max_ciphertext_len",
            "max_used_eph_pubs_per_license",
            "admin_password",
            "server_host",
            "server_port",
            "base_dir",
            "server_keys_dir",
            "license_file_path",
            "revoked_licenses_file_path",
        ]
        self.apply_overrides(overrides, self.config, attr_list)
        self.app = FastAPI()

        # Add global exception handlers
        @self.app.exception_handler(ValidationError)
        async def validation_error_handler(
            _request: Request, exc: ValidationError
        ) -> None:
            raise HTTPException(status_code=exc.status_code, detail=str(exc))

        @self.app.exception_handler(RateLimitError)
        async def rate_limit_error_handler(
            _request: Request, exc: RateLimitError
        ) -> None:
            raise HTTPException(status_code=exc.status_code, detail=str(exc))

        server_priv = overrides.get("server_priv")
        if server_priv is None:
            self.server_pub, self.server_priv = self._get_server_keys()
        else:
            self.server_priv = server_priv
            self.server_pub = self.server_priv.public_key()

        # Initialize components with dependency injection
        self.revoked_licenses: dict[str, int] = DataPersistence.load_revoked_licenses(
            self.revoked_licenses_file_path
        )
        self.session_manager = (
            session_manager
            or overrides.get("session_manager")
            or SessionManager(
                self.max_used_eph_pubs_per_license,
                self.config.DATA_DIR / "sessions.json",
            )
        )
        self.license_validator = (
            license_validator
            or overrides.get("license_validator")
            or LicenseValidator(
                self.config,
                self.server_pub,
                self.revoked_licenses,
                self.revoked_licenses_file_path,
            )
        )
        self.license_generator = (
            license_generator
            or overrides.get("license_generator")
            or LicenseGenerator(self.config, self.server_priv)
        )
        self.data_persistence = data_persistence or DataPersistence()

        # Initialize service and routes
        self.service = service or LicenseService(
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
        self.routes = routes or LicenseRoutes(self.service, self.admin_password)
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
