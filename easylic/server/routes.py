"""
Routes for the license server.
"""

from functools import partial
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from easylic.common.models import (
    GenerateLicenseRequest,
    RenewRequest,
    RevokeRequest,
    StartRequest,
)


from .services import LicenseService


class LicenseRoutes:
    """Handles FastAPI routes for the license server."""

    def __init__(self, service: LicenseService, admin_password: str | None):
        self.service = service
        self.admin_password = admin_password

    def setup_routes(self, app: FastAPI) -> None:
        """Setup API routes on the FastAPI app."""

        app.get("/health")(self.health)
        app.post("/start")(self.start)
        app.post("/renew")(self.renew)
        if self.admin_password:
            app.post("/revoke")(
                partial(self.revoke, admin_password=self.admin_password)
            )
            app.post("/generate_license")(
                partial(
                    self.generate_license_endpoint, admin_password=self.admin_password
                )
            )
        app.get("/admin")(self.admin_page)

    async def health(self) -> dict[str, Any]:
        """Handle /health endpoint."""
        return self.service.health()

    async def start(self, req: StartRequest) -> dict:
        """Handle /start endpoint."""
        return await self.service.start(req)

    async def renew(self, req: RenewRequest) -> Any:
        """Handle /renew endpoint."""
        return await self.service.renew(req)

    async def revoke(self, req: RevokeRequest, admin_password: str | None) -> dict:
        """Handle /revoke endpoint."""
        return await self.service.revoke(req, admin_password)

    async def generate_license_endpoint(
        self, req: GenerateLicenseRequest, admin_password: str | None
    ) -> Any:
        """Handle /generate_license endpoint."""
        return await self.service.generate_license_endpoint(req, admin_password)

    async def admin_page(self) -> HTMLResponse:
        """Handle /admin endpoint."""
        admin_html_path = Path(__file__).parent / "admin.html"
        with admin_html_path.open() as f:
            content = f.read()
        return HTMLResponse(content)
