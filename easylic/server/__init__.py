"""
Entry point for the license server.
"""

import logging
import uvicorn

from easylic.common.config import Config
from .core import LicenseServer


def start_server(config: Config | None = None) -> None:
    """Start the license server."""
    if config is None:
        config = Config()
    logging.basicConfig(level=config.LOG_LEVEL)
    server = LicenseServer(config=config)
    uvicorn.run(server.app, host=server.server_host, port=server.server_port)
