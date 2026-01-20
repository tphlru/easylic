"""
Command-line interface for THPL Easy Licensing.
"""

import click

@click.group()
def cli():
    """THPL Easy Licensing CLI"""
    pass

@cli.command()
@click.option('--keys-dir', default=None, help='Directory to save keys (default: ./easylic/server)')
def keygen(keys_dir):
    """Generate server Ed25519 keys"""
    if keys_dir:
        import os
        os.environ['EASYLIC_KEYS_DIR'] = keys_dir
    from .server.keygen import main
    main()

@cli.command()
@click.option('--keys-dir', default=None, help='Directory to load keys from (default: ./easylic/server)')
@click.option('--host', default=None, help='Host to bind server to (default: from SERVER_HOST env or 127.0.0.1)')
@click.option('--port', default=None, type=int, help='Port to bind server to (default: from SERVER_PORT env or 8000)')
def serve(keys_dir, host, port):
    """Start the license server"""
    if keys_dir:
        import os
        os.environ['EASYLIC_KEYS_DIR'] = keys_dir
    if host:
        import os
        os.environ['SERVER_HOST'] = host
    if port:
        import os
        os.environ['SERVER_PORT'] = str(port)
    # Warn about default admin password
    import os
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    if admin_password == "admin123":
        click.echo("WARNING: Using default admin password 'admin123'. Set ADMIN_PASSWORD environment variable to a secure password.", err=True)
    from .server import main
    main()

@cli.command()
@click.option('--keys-dir', default=None, help='Directory to load keys from (default: ./easylic/server)')
def generator(keys_dir):
    """Interactive license generator"""
    if keys_dir:
        import os
        os.environ['EASYLIC_KEYS_DIR'] = keys_dir
    from .server.license_generator import main
    main()

if __name__ == "__main__":
    cli()