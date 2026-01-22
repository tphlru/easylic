import pytest
from pydantic import ValidationError

from easylic.common.models import (
    LicenseData,
    LicensePayload,
    Policy,
    RenewRequest,
    StartRequest,
)


def test_license_data_model() -> None:
    license_data = {
        "payload": {
            "license_id": "1",
            "product": "test",
            "valid_from": 1000,
            "valid_until": 2000,
            "policy": {"version": "1.0", "max_sessions": 1},
        },
        "signature": "test_signature",
    }
    payload = LicensePayload(**license_data["payload"])  # type: ignore[arg-type]
    lic = LicenseData(payload=payload, signature=license_data["signature"])  # type: ignore[arg-type]
    assert lic.payload.license_id == "1"
    assert lic.payload.product == "test"
    assert lic.payload.valid_from == 1000  # noqa: PLR2004
    assert lic.payload.valid_until == 2000  # noqa: PLR2004
    assert lic.payload.policy["version"] == "1.0"
    assert lic.payload.policy["max_sessions"] == 1
    assert lic.signature == "test_signature"


def test_policy_model() -> None:
    policy = Policy(version="1.0", max_sessions=5, features=["feature1", "feature2"])
    assert policy.version == "1.0"
    assert policy.max_sessions == 5  # noqa: PLR2004
    assert policy.features == ["feature1", "feature2"]


def test_policy_model_defaults() -> None:
    policy = Policy(version="1.0", max_sessions=1)
    assert policy.features == []


def test_policy_validation() -> None:
    with pytest.raises(ValidationError):
        Policy(version="1.0", max_sessions=0)  # max_sessions must be > 0


def test_start_request_model() -> None:
    license_data = {
        "payload": LicensePayload(
            license_id="1",
            product="test",
            valid_from=1000,
            valid_until=2000,
            policy={"version": "1.0", "max_sessions": 1},
        ),
        "signature": "sig",
    }
    lic = LicenseData(**license_data)  # type: ignore[arg-type]
    req = StartRequest(
        version=1,
        license=lic,
        client_pubkey="pubkey",
        client_eph_pub="ephpub",
        supported_features={"feat1": True},
    )
    assert req.version == 1
    assert req.license.payload.license_id == "1"
    assert req.client_pubkey == "pubkey"


def test_renew_request_model() -> None:
    req = RenewRequest(session_id="session123", ciphertext="cipher", counter=5)
    assert req.session_id == "session123"
    assert req.ciphertext == "cipher"
    assert req.counter == 5  # noqa: PLR2004
