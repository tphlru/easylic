"""
Entry point for the license server.
"""

import uvicorn

from easylic.common.config import Config
from .core import LicenseServer


def main(config: Config | None = None) -> None:
    server = LicenseServer(config=config)
    uvicorn.run(server.app, host=server.server_host, port=server.server_port)
