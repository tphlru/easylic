"""
Command-line interface for THPL Easy Licensing.
"""

from __future__ import annotations

import importlib
import os

import click

import easylic.common.config

from .server import main as server_main
from .server.keygen import main as keygen_main
from .server.license_generator import main as generator_main


@click.group()
def cli() -> None:
    """THPL Easy Licensing CLI"""


@cli.command()
@click.option(
    "--keys-dir",
    default=None,
    help="Directory to save keys (default: ./easylic/server)",
)
def keygen(keys_dir: str | None) -> None:
    """Generate server Ed25519 keys"""
    if keys_dir:
        os.environ["EASYLIC_KEYS_DIR"] = keys_dir

    keygen_main()


@cli.command()
@click.option(
    "--keys-dir",
    default=None,
    help="Directory to load keys from (default: ./easylic/server)",
)
@click.option(
    "--host",
    default=None,
    help="Host to bind server to (default: from SERVER_HOST env or 127.0.0.1)",
)
@click.option(
    "--port",
    default=None,
    type=int,
    help="Port to bind server to (default: from SERVER_PORT env or 8000)",
)
def serve(keys_dir: str | None, host: str | None, port: int | None) -> None:
    """Start the license server"""
    # Set environment variables before importing server
    if keys_dir:
        os.environ["EASYLIC_KEYS_DIR"] = keys_dir
    if host:
        os.environ["SERVER_HOST"] = host
    if port:
        os.environ["SERVER_PORT"] = str(port)

    # Warn about default admin password
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    if admin_password == "admin123":
        click.echo(
            "WARNING: Using default admin password 'admin123'. "
            "Set ADMIN_PASSWORD environment variable to a secure password.",
            err=True,
        )

    # Force reload of config after env vars are set
    importlib.reload(easylic.common.config)

    server_main()


@cli.command()
@click.option(
    "--keys-dir",
    default=None,
    help="Directory to load keys from (default: ./easylic/server)",
)
def generator(keys_dir: str | None) -> None:
    """Interactive license generator"""
    if keys_dir:
        os.environ["EASYLIC_KEYS_DIR"] = keys_dir

    generator_main()


if __name__ == "__main__":
    cli()
