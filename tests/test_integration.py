# Integration tests
import json
import threading
import time
from unittest.mock import Mock

import pytest
import requests
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from easylic.client.client import LicenseClient
from easylic.server.core import LicenseServer


class MockResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json = json_data

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Client Error", response=self)


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
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
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
            "policy": {"version": "1.0", "max_sessions": 1},
        },
        "signature": "placeholder-signature",  # Will be signed properly below
    }

    # Sign the license properly
    payload_str = json.dumps(license_data["payload"], separators=(",", ":"))
    signature = private_key.sign(payload_str.encode())
    license_data["signature"] = signature.hex()

    license_file = base_dir / "license.json"
    license_file.write_text(json.dumps(license_data))

    import socket

    server_host = "127.0.0.1"
    # Find a free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server_host, 0))
        server_port = s.getsockname()[1]

    # Create server
    server = LicenseServer(
        server_keys_dir=keys_dir,
        license_file_path=license_file,
        server_host=server_host,
        server_port=server_port,
        admin_password="testpassword",
    )

    return {
        "base_dir": base_dir,
        "keys_dir": keys_dir,
        "license_file": license_file,
        "server_host": server_host,
        "server_port": server_port,
        "server": server,
    }


@pytest.fixture
def test_client(temp_setup):
    """Fixture to provide TestClient for server."""
    setup = temp_setup
    return TestClient(setup["server"].app)


def test_full_integration_flow(test_client, temp_setup, monkeypatch):
    """Test full client-server integration."""
    setup = temp_setup
    client_app = test_client

    # Mock requests.post to use TestClient
    def mock_post(url, **kwargs):
        # Remove base url
        path = url.replace(f"http://{setup['server_host']}:{setup['server_port']}", "")
        response = client_app.post(path, **kwargs)
        return MockResponse(response.status_code, response.json())

    monkeypatch.setattr("requests.post", mock_post)

    # Create client
    client = LicenseClient(
        server_url=f"http://{setup['server_host']}:{setup['server_port']}",
        license_file=str(setup["license_file"]),
        server_keys_dir=setup["keys_dir"],
    )

    # Test that client can be created and initialized
    assert client.server_url == f"http://{setup['server_host']}:{setup['server_port']}"
    assert client.license.payload.license_id == "integration-test-license"

    # Test starting a session
    session_id = client.start_session()
    assert session_id is not None
    assert len(session_id) > 0

    # Test that license is active
    assert client.is_license_active()


def test_client_server_key_exchange(test_client, temp_setup, monkeypatch):
    """Test that client and server can exchange keys."""
    setup = temp_setup
    client_app = test_client

    # Mock requests.get to use TestClient
    def mock_get(url, **kwargs):
        path = url.replace(f"http://{setup['server_host']}:{setup['server_port']}", "")
        response = client_app.get(path, **kwargs)
        return MockResponse(response.status_code, response.json())

    monkeypatch.setattr("requests.get", mock_get)

    # Create client
    client = LicenseClient(
        server_url=f"http://{setup['server_host']}:{setup['server_port']}",
        license_file=str(setup["license_file"]),
        server_keys_dir=setup["keys_dir"],
    )

    # Test health endpoint
    response = requests.get(
        f"http://{setup['server_host']}:{setup['server_port']}/health"
    )
    assert response.status_code == 200
    data = response.json()
    assert "timestamp" in data

    # Test that client loaded keys correctly
    assert client.license is not None
    assert client.license.payload.license_id == "integration-test-license"
