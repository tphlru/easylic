"""
Pydantic models for request/response validation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field


class LicensePayload(BaseModel):
    license_id: str
    product: str
    valid_from: int
    valid_until: int
    policy: dict[str, Any]


class LicenseData(BaseModel):
    payload: LicensePayload
    signature: str


class StartRequest(BaseModel):
    version: int
    license: LicenseData
    client_pubkey: str
    client_eph_pub: str
    supported_features: dict[str, bool]


class StartResponse(BaseModel):
    session_id: str
    expires_at: int
    protocol_version: int
    cipher_suite: str
    required_features: dict[str, bool]
    server_eph_pub: str
    nonce_prefix: str
    signature: str
    transcript_hash: str
    transcript_hash_signature: str
    handshake_ciphertext: str
    handshake_nonce: str


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
    client_proof: str | None = None
    transcript_hash: str


class RenewResponseData(BaseModel):
    expires_at: int
    next_counter: int
    epoch_used: int
    version: int
    cipher_suite: str
    server_proof: str | None = None
    rekey_ack: bool | None = None


class RevokeRequest(BaseModel):
    payload: dict[str, Any]


class GenerateLicenseRequest(BaseModel):
    payload: dict[str, Any]


class Policy(BaseModel):
    max_sessions: int = Field(gt=0)
    version: str
    features: list[str] = Field(default_factory=list)


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
    last_cipher_hash: bytes | None = None


class ClientConfig(BaseModel):
    server_url: str | None = None
    license_file: str | None = None
    log_level: int | None = None
    on_error_callback: Callable[[Exception], None] | None = None
    renew_interval: int | None = None
    session_ttl: int | None = None
    max_counter: int | None = None
    max_start_attempts_per_minute: int | None = None
    max_ciphertext_len: int | None = None
    max_used_eph_pubs_per_license: int | None = None
    server_host: str | None = None
    server_port: int | None = None
    base_dir: Path | None = None
    server_keys_dir: Path | None = None
    license_file_path: Path | None = None
    revoked_licenses_file_path: Path | None = None
