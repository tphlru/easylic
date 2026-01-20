"""
Entry point for the license server.
"""

from .core import LicenseServer


def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)


# Create server instance
server = LicenseServer()
server._setup_routes()  # Setup routes after initialization
app = server.app