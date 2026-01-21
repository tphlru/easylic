from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from easylic.server.keygen import KeyGenerator


def test_key_generator_generate_keys(tmp_path):
    """Test key generation with temporary directory."""
    keygen = KeyGenerator()
    keygen.keys_dir = tmp_path

    keygen.generate_keys()

    # Check that files were created
    private_path = tmp_path / "server_private.key"
    public_path = tmp_path / "server_public.key"

    assert private_path.exists()
    assert public_path.exists()

    # Verify keys can be loaded
    with open(private_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(private_key, Ed25519PrivateKey)

    with open(public_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
        assert isinstance(public_key, Ed25519PublicKey)


def test_key_generator_directory_creation(tmp_path):
    """Test that directory is created if it doesn't exist."""
    keys_dir = tmp_path / "nested" / "keys"
    keygen = KeyGenerator()
    keygen.keys_dir = keys_dir

    keygen.generate_keys()

    assert keys_dir.exists()
    assert (keys_dir / "server_private.key").exists()
    assert (keys_dir / "server_public.key").exists()
