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
def serve(keys_dir):
    """Start the license server"""
    if keys_dir:
        import os
        os.environ['EASYLIC_KEYS_DIR'] = keys_dir
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