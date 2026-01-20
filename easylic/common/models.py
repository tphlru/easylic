"""
Pydantic models for request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional


class LicensePayload(BaseModel):
    license_id: str
    product: str
    valid_from: int
    valid_until: int
    policy: Dict[str, Any]


class LicenseData(BaseModel):
    payload: LicensePayload
    signature: str


class StartRequest(BaseModel):
    version: int
    license: LicenseData
    client_pubkey: str
    client_eph_pub: str
    supported_features: Dict[str, bool]


class StartResponse(BaseModel):
    session_id: str
    expires_at: int
    protocol_version: int
    cipher_suite: str
    required_features: Dict[str, bool]
    server_eph_pub: str
    nonce_prefix: str
    signature: str


class RenewRequest(BaseModel):
    session_id: str
    ciphertext: str
    counter: int


class RenewResponse(BaseModel):
    ciphertext: str
    counter: int
    epoch_used: int


class RenewData(BaseModel):
    session_id: str
    counter: int
    client_sig: str
    version: int
    cipher_suite: str
    client_proof: Optional[str] = None


class RenewResponseData(BaseModel):
    expires_at: int
    next_counter: int
    epoch_used: int
    version: int
    cipher_suite: str
    server_proof: Optional[str] = None
    rekey_ack: Optional[bool] = None


class RevokeRequest(BaseModel):
    payload: Dict[str, Any]


class GenerateLicenseRequest(BaseModel):
    payload: Dict[str, Any]


class Policy(BaseModel):
    max_sessions: int = Field(gt=0)
    version: str
    features: List[str] = Field(default_factory=list)


class SessionData(BaseModel):
    license_id: str
    expires_at: int
    client_pub: str
    expected_counter: int
    session_key: bytes
    root_secret: bytes
    initial_nonce_prefix: bytes
    transcript_hash: str
    rekey_epoch: int
    last_renew_at: int
    last_cipher_hash: Optional[bytes] = None