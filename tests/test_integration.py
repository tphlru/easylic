# Integration tests
import json
import socket
import time
from pathlib import Path
from typing import Any

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from easylic.client.client import LicenseClient
from easylic.server.core import LicenseServer


class MockResponse:
    def __init__(self, status_code: int, json_data: Any) -> None:
        self.status_code = status_code
        self._json = json_data

    def json(self) -> Any:
        return self._json

    @property
    def text(self) -> str:
        return str(self._json)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:  # noqa: PLR2004
            msg = f"{self.status_code} Client Error"
            raise requests.HTTPError(msg, response=self)  # type: ignore[arg-type]


@pytest.fixture
def temp_setup(tmp_path: Path, monkeypatch: Any) -> Any:
    """Create temporary setup for integration test."""
    # Use separate directory for test keys, not production
    test_keys_dir = tmp_path / "test_keys"
    test_keys_dir.mkdir(parents=True)

    license_file = tmp_path / "license.json"

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

    (test_keys_dir / "server_private.key").write_bytes(private_pem)
    (test_keys_dir / "server_public.key").write_bytes(public_pem)

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
    payload_str = json.dumps(
        license_data["payload"], sort_keys=True, separators=(",", ":")
    )
    signature = private_key.sign(payload_str.encode())
    license_data["signature"] = signature.hex()

    license_file = tmp_path / "license.json"

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

    (test_keys_dir / "server_private.key").write_bytes(private_pem)
    (test_keys_dir / "server_public.key").write_bytes(public_pem)

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
    payload_str = json.dumps(
        license_data["payload"], sort_keys=True, separators=(",", ":")
    )
    signature = private_key.sign(payload_str.encode())
    license_data["signature"] = signature.hex()

    license_file.write_text(json.dumps(license_data))

    server_host = "127.0.0.1"
    # Find a free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server_host, 0))
        server_port = s.getsockname()[1]

    # Create server
    server = LicenseServer(
        server_keys_dir=test_keys_dir,
        license_file_path=license_file,
        server_host=server_host,
        server_port=server_port,
        admin_password="testpassword",  # noqa: S106
    )

    client_app = TestClient(server.app)

    # Mock requests.post to use TestClient
    def mock_post(url: str, **kwargs: Any) -> MockResponse:
        # Remove base url
        path = url.replace(f"http://{server_host}:{server_port}", "")
        response = client_app.post(path, **kwargs)
        return MockResponse(response.status_code, response.json())

    monkeypatch.setattr("requests.post", mock_post)

    # Create client
    client = LicenseClient(
        server_url=f"http://{server_host}:{server_port}",
        license_file=str(license_file),
        server_keys_dir=test_keys_dir,
    )

    # Test that client can be created and initialized
    assert client.server_url == f"http://{server_host}:{server_port}"
    assert client.license.payload.license_id == "integration-test-license"

    # Test starting a session
    session_id = client.start_session()
    assert session_id is not None
    assert len(session_id) > 0

    # Test that license is active
    assert client.is_license_active()
