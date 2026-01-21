import pytest

from easylic.common.models import LicenseData, Policy, RenewRequest, StartRequest


def test_license_data_model():
    license_data = {
        "payload": {
            "license_id": "1",
            "product": "test",
            "valid_from": 1000,
            "valid_until": 2000,
            "policy": {"version": "1.0", "max_sessions": 1}
        },
        "signature": "test_signature"
    }
    license = LicenseData(**license_data)
    assert license.payload.license_id == "1"
    assert license.payload.product == "test"
    assert license.payload.valid_from == 1000
    assert license.payload.valid_until == 2000
    assert license.payload.policy["version"] == "1.0"
    assert license.payload.policy["max_sessions"] == 1
    assert license.signature == "test_signature"


def test_policy_model():
    policy = Policy(version="1.0", max_sessions=5, features=["feature1", "feature2"])
    assert policy.version == "1.0"
    assert policy.max_sessions == 5
    assert policy.features == ["feature1", "feature2"]


def test_policy_model_defaults():
    policy = Policy(version="1.0", max_sessions=1)
    assert policy.features == []


def test_policy_validation():
    with pytest.raises(ValueError):
        Policy(version="1.0", max_sessions=0)  # max_sessions must be > 0


def test_start_request_model():
    req = StartRequest(
        version=1,
        license={"payload": {"license_id": "1", "product": "test", "valid_from": 1000, "valid_until": 2000, "policy": {"version": "1.0", "max_sessions": 1}}, "signature": "sig"},
        client_pubkey="pubkey",
        client_eph_pub="ephpub",
        supported_features={"secure_channel": True, "counter": True, "pop": True, "transcript_binding": True, "rekey": True, "proofs": True}
    )
    assert req.version == 1
    assert req.license.payload.license_id == "1"
    assert req.client_pubkey == "pubkey"


def test_renew_request_model():
    req = RenewRequest(session_id="session123", ciphertext="cipher", counter=5)
    assert req.session_id == "session123"
    assert req.ciphertext == "cipher"
    assert req.counter == 5
