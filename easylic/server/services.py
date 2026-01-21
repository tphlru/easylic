"""
Business logic services for the license server.
"""

import logging
import time
from typing import Any

from fastapi.responses import Response

from easylic.common.config import Config
from easylic.common.interfaces import (
    ILicenseGenerator,
    ILicenseValidator,
    ISessionManager,
)
from easylic.common.models import (
    GenerateLicenseRequest,
    LicenseData,
    RenewRequest,
    RenewResponse,
    RevokeRequest,
    StartRequest,
)
from .persistence import DataPersistence

from .domain.admin_handler import AdminHandler
from .domain.renew_handler import RenewHandler
from .domain.start_handler import StartHandler

from .domain.admin_handler import AdminHandler
from .domain.renew_handler import RenewHandler
from .domain.start_handler import StartHandler


class LicenseService:
    """Handles business logic for the license server."""

    def __init__(
        self,
        config: "Config",
        session_manager: ISessionManager,
        license_validator: ILicenseValidator,
        license_generator: ILicenseGenerator,
        rekey_after_renews: int,
        session_ttl: int,
        max_counter: int,
        max_start_attempts_per_minute: int,
        max_ciphertext_len: int,
        logger: logging.Logger,
    ):
        self.config = config
        self.session_manager = session_manager
        self.license_validator = license_validator
        self.license_generator = license_generator
        self.rekey_after_renews = rekey_after_renews
        self.session_ttl = session_ttl
        self.max_counter = max_counter
        self.max_start_attempts_per_minute = max_start_attempts_per_minute
        self.max_ciphertext_len = max_ciphertext_len
        self.logger = logger

        self.data_persistence = DataPersistence()

        # Initialize handlers
        self.start_handler = StartHandler(
            config=self.config,
            session_manager=self.session_manager,
            license_validator=self.license_validator,
            license_generator=self.license_generator,
            max_start_attempts_per_minute=self.max_start_attempts_per_minute,
            session_ttl=self.session_ttl,
        )
        self.renew_handler = RenewHandler(
            config=self.config,
            session_manager=self.session_manager,
            license_validator=self.license_validator,
            rekey_after_renews=self.rekey_after_renews,
            session_ttl=self.session_ttl,
            max_counter=self.max_counter,
            max_ciphertext_len=self.max_ciphertext_len,
            logger=self.logger,
        )
        self.admin_handler = AdminHandler(
            license_validator=self.license_validator,
            license_generator=self.license_generator,
            session_manager=self.session_manager,
            data_persistence=self.data_persistence,
        )

    def clean_expired_sessions(self) -> None:
        """Clean expired sessions and related data."""
        self.session_manager.clean_expired_sessions()

    def verify_license(self, lic: LicenseData) -> bool:
        """Verify license signature and validity."""
        return self.license_validator.verify_license(lic)

    def validate_policy(self, policy: dict) -> bool:
        """Server-side validation for policy."""
        return self.license_validator.validate_policy(policy)

    def health(self) -> dict[str, Any]:
        """Health check endpoint."""
        return {"status": "ok", "timestamp": int(time.time())}

    async def start(self, req: StartRequest) -> dict:
        """Handle /start endpoint business logic."""
        return self.start_handler.handle_start(req)

    async def renew(self, req: RenewRequest) -> RenewResponse:
        """Handle /renew endpoint business logic."""
        return self.renew_handler.handle_renew(req)

    async def revoke(self, req: RevokeRequest, admin_password: str | None) -> dict:
        """Handle /revoke endpoint business logic."""
        return await self.admin_handler.revoke(req, admin_password)

    async def generate_license_endpoint(
        self, req: GenerateLicenseRequest, admin_password: str | None
    ) -> Response:
        """Handle /generate_license endpoint business logic."""
        return await self.admin_handler.generate_license_endpoint(req, admin_password)
