"""
Entry point for the license server.
"""

from .core import LicenseServer


def main():
    import uvicorn
    server = LicenseServer()
    server._setup_routes()  # Setup routes after initialization
    app = server.app
    uvicorn.run(app, host=server.server_host, port=server.server_port)