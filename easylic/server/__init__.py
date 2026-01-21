"""
Entry point for the license server.
"""

import uvicorn

from .core import LicenseServer


def main() -> None:
    server = LicenseServer()
    uvicorn.run(server.app, host=server.server_host, port=server.server_port)
