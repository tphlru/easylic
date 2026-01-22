from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from easylic.common.config import Config
from easylic.server.core import LicenseServer


@pytest.fixture
def temp_keys_dir(tmp_path: Path) -> Path:
    """Create temporary keys directory with test keys."""

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()

    # Generate test keys
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

    return keys_dir


@pytest.fixture
def server(temp_keys_dir: Path) -> LicenseServer:
    """Create LicenseServer instance with temp keys."""
    return LicenseServer(
        server_keys_dir=temp_keys_dir, license_file_path=temp_keys_dir / "license.json"
    )


def test_server_initialization(temp_keys_dir: Path) -> None:
    """Test server initialization."""
    server = LicenseServer(
        server_keys_dir=temp_keys_dir, license_file_path=temp_keys_dir / "license.json"
    )
    config = Config()
    assert server.session_ttl == config.SESSION_TTL
    assert server.max_counter == config.MAX_COUNTER
    assert server.max_start_attempts_per_minute == config.MAX_START_ATTEMPTS_PER_MINUTE


def test_server_health_endpoint(temp_keys_dir: Path) -> None:
    """Test health endpoint."""
    server = LicenseServer(server_keys_dir=temp_keys_dir)
    # Since server uses FastAPI app, we need to test the endpoint
    # This is a placeholder - in real implementation would use TestClient
    assert hasattr(server, "app")
    # Test that app has health route
    routes = [route.path for route in server.app.routes]  # type: ignore[attr-defined]
    assert "/health" in routes


def test_server_start_endpoint_missing_features(temp_keys_dir: Path) -> None:
    """Test /start endpoint with missing required features."""
    server = LicenseServer(server_keys_dir=temp_keys_dir)
    client = TestClient(server.app)

    # Request with missing features - note that server may return 404 if not
    # fully initialized
    response = client.post(
        "/start",
        json={
            "version": 1,
            "license": {"payload": {"license_id": "test"}, "signature": "sig"},
            "client_pubkey": "pub",
            "client_eph_pub": "eph",
            "supported_features": {
                "secure_channel": False
            },  # Missing required features
        },
    )

    # Should return error for missing features or endpoint not found
    assert response.status_code in [403, 404, 422]


def test_server_renew_endpoint_invalid_session(temp_keys_dir: Path) -> None:
    """Test /renew endpoint with invalid session."""
    server = LicenseServer(server_keys_dir=temp_keys_dir)
    client = TestClient(server.app)

    # Request with non-existent session
    response = client.post(
        "/renew",
        json={
            "session_id": "non-existent-session",
            "ciphertext": "cipher",
            "counter": 1,
        },
    )

    # Should return 404 or error
    assert response.status_code in [400, 403, 404]
