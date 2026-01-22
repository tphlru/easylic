"""
Admin license_requestuest handler for license service.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

from fastapi.responses import Response

from easylic.common.exceptions import ValidationError
from easylic.server.persistence import DataPersistence

if TYPE_CHECKING:
    from easylic.common.interfaces import (
        IDataPersistence,
        ILicenseGenerator,
        ILicenseValidator,
        ISessionManager,
    )
    from easylic.common.models import GenerateLicenseRequest, RevokeRequest


class AdminHandler:
    """Handles admin license_requestuests like revoke and generate license."""

    def __init__(
        self,
        license_validator: ILicenseValidator,
        license_generator: ILicenseGenerator,
        session_manager: ISessionManager,
        data_persistence: IDataPersistence,
    ):
        self.license_validator = license_validator
        self.license_generator = license_generator
        self.session_manager = session_manager
        self.data_persistence = data_persistence

    async def revoke(
        self, license_request: RevokeRequest, admin_password: str | None
    ) -> dict:
        """Handle /revoke endpoint business logic."""
        payload = license_request.payload
        if admin_password is None or payload.get("password") != admin_password:
            msg = "Invalid admin password"
            raise ValidationError(msg)

        license_id = payload["license_id"]

        now = int(time.time())

        # Record revocation timestamp
        revoked_licenses = self.license_validator.revoked_licenses
        now = int(time.time())
        revoked_licenses[license_id] = now
        DataPersistence.save_revoked_licenses(
            self.license_validator.revoked_licenses_file_path,
            revoked_licenses,
        )

        # Force expire all sessions for this license
        self.session_manager.revoke_sessions_for_license(license_id)

        return {"revoked_at": now}

    async def generate_license_endpoint(
        self, license_request: GenerateLicenseRequest, admin_password: str | None
    ) -> Response:
        """Handle /generate_license endpoint business logic."""
        if admin_password is None or license_request.password != admin_password:
            msg = "Invalid admin password"
            raise ValidationError(msg)

        try:
            license_id = license_request.license_id
            product = license_request.product
            valid_from = license_request.valid_from
            valid_until = license_request.valid_until
            policy = license_request.policy
            license_data = self.license_generator.generate_license(
                license_id, product, valid_from, valid_until, policy
            )

            # Return as downloadable JSON file
            json_str = json.dumps(license_data.model_dump(), indent=2)
            return Response(
                content=json_str,
                media_type="application/json",
                headers={
                    "Content-Disposition": (
                        f"attachment; filename=license_{license_id}.json"
                    )
                },
            )
        except ValueError as e:
            msg = str(e)
            raise ValidationError(msg, 400) from e
        except KeyError as e:
            msg = "Missing license_requestuired fields"
            raise ValidationError(msg, 400) from e
