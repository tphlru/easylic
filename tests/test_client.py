import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from easylic.client.client import LicenseClient


@pytest.fixture
def temp_license_file(tmp_path):
    """Create temporary license file."""
    license_data = {
        "payload": {
            "license_id": "test-license-123",
            "product": "TestProduct",
            "valid_from": 1000000000,
            "valid_until": 2000000000,
            "policy": {"version": "1.0", "max_sessions": 1},
        },
        "signature": "test-signature-hex",
    }

    license_file = tmp_path / "license.json"
    license_file.write_text(json.dumps(license_data))
    return license_file


@pytest.fixture
def temp_keys_dir(tmp_path):
    """Create temporary keys directory."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()

    # Generate test keys
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    _private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (keys_dir / "server_public.key").write_bytes(public_pem)
    return keys_dir


@pytest.fixture
def client(temp_license_file, temp_keys_dir):
    """Create LicenseClient instance."""
    return LicenseClient(
        server_url="http://localhost:8080",
        license_file=str(temp_license_file),
        server_keys_dir=temp_keys_dir,
    )


def test_client_initialization(client):
    """Test client initialization."""
    assert client.server_url == "http://localhost:8080"
    assert client.license.payload.license_id == "test-license-123"
    assert client.license.payload.product == "TestProduct"


def test_client_is_license_active_no_session(client):
    """Test license active check without active session."""
    assert not client.is_license_active()


def test_client_start_session_placeholder(client):
    """Placeholder for start_session test - full mocking is complex."""
    # Test that client has required attributes
    assert hasattr(client, "start_session")
    assert hasattr(client, "server_url")
    assert client.server_url == "http://localhost:8080"


def test_client_renew_session_placeholder(client):
    """Placeholder for renew_session test - requires complex session state setup."""
    # Test that client has required attributes
    assert hasattr(client, "renew_session")
    assert hasattr(client, "counter")
    assert client.counter == 0
