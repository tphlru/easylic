# Integration tests
import pytest
import json
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from easylic.server.core import LicenseServer
from easylic.client.client import LicenseClient


@pytest.fixture
def temp_setup(tmp_path):
    """Create temporary setup for integration test."""
    base_dir = tmp_path / "easylic"
    keys_dir = base_dir / "server"
    keys_dir.mkdir(parents=True)

    # Generate server keys
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    (keys_dir / "server_private.key").write_bytes(private_pem)
    (keys_dir / "server_public.key").write_bytes(public_pem)

    # Create license file
    license_data = {
        "payload": {
            "license_id": "integration-test-license",
            "product": "IntegrationTest",
            "valid_from": int(time.time()),
            "valid_until": int(time.time()) + 3600,  # 1 hour
            "policy": {
                "version": "1.0",
                "max_sessions": 1
            }
        },
        "signature": "integration-test-signature"
    }

    license_file = base_dir / "license.json"
    license_file.write_text(json.dumps(license_data))

    return {
        "base_dir": base_dir,
        "keys_dir": keys_dir,
        "license_file": license_file,
        "server_host": "127.0.0.1",
        "server_port": 8888
    }


def test_full_integration_flow(temp_setup):
    """Test full client-server integration."""
    setup = temp_setup

    # Start server in background
    server = LicenseServer(
        server_keys_dir=setup["keys_dir"],
        license_file_path=setup["license_file"],
        server_host=setup["server_host"],
        server_port=setup["server_port"]
    )

    # Note: In real implementation, would start server with uvicorn in thread
    # For now, placeholder - would need to implement server startup

    # Create client
    client = LicenseClient(
        server_url=f"http://{setup['server_host']}:{setup['server_port']}",
        license_file=str(setup["license_file"]),
        server_keys_dir=setup["keys_dir"]
    )

    # Test that client can be created and initialized
    assert client.server_url == f"http://{setup['server_host']}:{setup['server_port']}"
    assert client.license.payload.license_id == "integration-test-license"

    # Note: Full integration would require running server and making real HTTP calls
    # This is a placeholder for the structure


def test_client_server_key_exchange(temp_setup):
    """Test that client and server can exchange keys."""
    # Placeholder - would test key loading and validation
    pass