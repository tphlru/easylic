"""
Command-line interface for THPL Easy Licensing.
"""

from __future__ import annotations

import os

import click

from easylic.common.config import Config

from .server import start_server
from .server.keygen import KeyGenerator
from .server.license_generator import LicenseGenerator


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

    keygen = KeyGenerator()
    keygen.generate_keys()
    click.echo("Keys generated and saved")


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

    # Require ADMIN_PASSWORD
    admin_password = os.getenv("ADMIN_PASSWORD")
    if not admin_password:
        msg = "ERROR: ADMIN_PASSWORD environment variable must be set to a secure password."
        raise click.ClickException(msg)

    # Create config with updated env vars
    config = Config()

    start_server(config)


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

    generator = LicenseGenerator()
    generator.interactive_generate()


if __name__ == "__main__":
    cli()
