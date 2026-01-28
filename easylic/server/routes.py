"""Routes for the license server.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI  # noqa: TC002
from fastapi.responses import HTMLResponse

from easylic.common.models import (  # noqa: TC001
    GenerateLicenseRequest,
    RenewRequest,
    RevokeRequest,
    StartRequest,
)
from easylic.server.services import LicenseService  # noqa: TC001


class LicenseRoutes:
    """Handles FastAPI routes for the license server."""

    def __init__(self, service: LicenseService, admin_password: str | None):
        self.service = service
        self.admin_password = admin_password

    async def _revoke_handler(self, license_request: RevokeRequest) -> dict:
        return await self.revoke(license_request)

    async def _generate_license_handler(
        self, license_request: GenerateLicenseRequest
    ) -> Any:
        return await self.generate_license_endpoint(license_request)

    def setup_routes(self, app: FastAPI) -> None:
        """Setup API routes on the FastAPI app."""
        app.get("/health")(self.health)
        app.post("/start")(self.start)
        app.post("/renew")(self.renew)
        if self.admin_password:
            app.post("/revoke")(self._revoke_handler)
            app.post("/generate_license")(self._generate_license_handler)
        app.get("/admin")(self.admin_page)

    async def health(self) -> dict[str, Any]:
        """Handle /health endpoint."""
        return self.service.health()

    async def start(self, license_request: StartRequest) -> dict:
        """Handle /start endpoint."""
        return await self.service.start(license_request)

    async def renew(self, license_request: RenewRequest) -> Any:
        """Handle /renew endpoint."""
        return await self.service.renew(license_request)

    async def revoke(self, license_request: RevokeRequest) -> dict:
        """Handle /revoke endpoint."""
        return await self.service.revoke(license_request, self.admin_password)

    async def generate_license_endpoint(
        self, license_request: GenerateLicenseRequest
    ) -> Any:
        """Handle /generate_license endpoint."""
        return await self.service.generate_license_endpoint(
            license_request, self.admin_password
        )

    async def admin_page(self) -> HTMLResponse:
        """Handle /admin endpoint."""
        admin_html_path = Path(__file__).parent / "admin.html"
        with admin_html_path.open() as f:
            content = f.read()
        return HTMLResponse(content)
