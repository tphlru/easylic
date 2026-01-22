import os
from pathlib import Path

from easylic.common.config import Config


def test_config_class_attributes():
    config = Config()
    assert config.SESSION_TTL == 30
    assert config.MAX_COUNTER == 2**40
    assert config.MAX_START_ATTEMPTS_PER_MINUTE == 10
    assert config.MAX_CIPHERTEXT_LEN == 10 * 1024
    assert config.MAX_USED_EPH_PUBS_PER_LICENSE == 100


def test_config_server_settings():
    # Test default values
    config = Config()
    assert os.getenv("ADMIN_PASSWORD") == config.ADMIN_PASSWORD
    assert os.getenv("SERVER_HOST", "127.0.0.1") == config.SERVER_HOST
    assert int(os.getenv("SERVER_PORT", "8000")) == config.SERVER_PORT


def test_config_paths(monkeypatch):
    """Test config paths with clean environment."""
    # Ensure clean environment for this test
    monkeypatch.delenv("EASYLIC_KEYS_DIR", raising=False)
    monkeypatch.delenv("SERVER_HOST", raising=False)
    monkeypatch.delenv("SERVER_PORT", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)

    # Import Config after env cleanup to get fresh values
    from importlib import reload

    import easylic.common.config

    reload(easylic.common.config)
    from easylic.common.config import Config

    base_dir = Path(__file__).parent.parent / "easylic"
    expected_keys_dir = base_dir / "server"
    config = Config()
    assert expected_keys_dir == config.SERVER_KEYS_DIR
    assert config.SERVER_PUBLIC_KEY_PATH == config.SERVER_KEYS_DIR / "server_public.key"
    assert (
        config.SERVER_PRIVATE_KEY_PATH == config.SERVER_KEYS_DIR / "server_private.key"
    )


def test_config_required_features():
    config = Config()
    features = config.REQUIRED_FEATURES
    assert features["secure_channel"] is True
    assert features["counter"] is True
    assert features["pop"] is True
    assert features["transcript_binding"] is True
    assert features["rekey"] is True
    assert features["proofs"] is True
