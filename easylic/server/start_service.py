"""
Start service for license server.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from easylic.common.crypto import CryptoUtils
from easylic.common.exceptions import RateLimitError, ValidationError

if TYPE_CHECKING:
    from easylic.common.config import Config
    from easylic.common.models import (
        LicenseData,
        SessionData,  # noqa: TC004
        StartRequest,
    )
    from easylic.server.license_generator import LicenseGenerator
    from easylic.server.license_validator import LicenseValidator
    from easylic.server.session_manager import SessionManager


class StartService:
    """Handles start session logic."""

    def __init__(  # noqa: PLR0913
        self,
        config: Config,
        session_manager: SessionManager,
        license_validator: LicenseValidator,
        license_generator: LicenseGenerator,
        rekey_after_renews: int,
        session_ttl: int,
        max_counter: int,
        max_start_attempts_per_minute: int,
        max_ciphertext_len: int,
        logger: Any,
    ):
        self.config = config
        self.session_manager = session_manager
        self.license_validator = license_validator
        self.license_generator = license_generator
        self.rekey_after_renews = rekey_after_renews
        self.session_ttl = session_ttl
        self.max_counter = max_counter
        self.max_start_attempts_per_minute = max_start_attempts_per_minute
        self.max_ciphertext_len = max_ciphertext_len
        self.logger = logger

    async def start(self, license_request: StartRequest) -> dict:
        """Handle /start endpoint business logic."""
        self._validate_start_license_requestuest(license_request)
        self.session_manager.clean_expired_sessions()

        lic, client_pub_hex, client_eph_pub = self._extract_start_data(license_request)
        license_id = self._perform_anti_replay_and_verify(lic, client_eph_pub)
        policy = self._validate_license_and_policy(lic)
        self._enforce_session_limits(license_id, policy)

        session_data, resp_data = self._generate_keys_and_session(
            license_request, lic, client_pub_hex, client_eph_pub
        )
        self.session_manager.add_session(
            session_data["session_id"], session_data["session"]
        )

        return self._build_start_response(session_data, resp_data)

    def _validate_start_license_requestuest(
        self, license_request: StartRequest
    ) -> None:
        """Validate protocol version and license_requestuired features."""
        if license_request.version != self.config.PROTOCOL_VERSION:
            msg = "protocol version mismatch"
            raise ValidationError(msg)
        for feature, license_requestuired in self.config.REQUIRED_FEATURES.items():
            if license_request.supported_features.get(feature) != license_requestuired:
                msg = f"license_requestuired feature not supported: {feature}"
                raise ValidationError(msg)

    def _extract_start_data(
        self, license_request: StartRequest
    ) -> tuple[LicenseData, str, X25519PublicKey]:
        """Extract license, client pubkey, and ephemeral pubkey from request."""
        lic = license_request.license
        client_pub_hex = license_request.client_pubkey
        client_eph_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(license_request.client_eph_pub)
        )
        return lic, client_pub_hex, client_eph_pub

    def _perform_anti_replay_and_verify(
        self, lic: LicenseData, client_eph_pub: X25519PublicKey
    ) -> str:
        """Perform anti-replay check and verify license."""
        pub_bytes = client_eph_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        license_id = lic.payload.license_id
        if self.session_manager.is_eph_pub_used(license_id, pub_bytes):
            msg = "handshake replay detected"
            raise ValidationError(msg)
        self.session_manager.record_used_eph_pub(license_id, pub_bytes)

        if not self.license_validator.verify_license(lic):
            msg = "invalid license"
            raise ValidationError(msg)
        return license_id

    def _validate_license_and_policy(self, lic: LicenseData) -> dict:
        """Validate license policy and rate limit."""
        license_id = lic.payload.license_id
        if not self.session_manager.check_start_attempt_rate(
            license_id, self.max_start_attempts_per_minute
        ):
            msg = "too many start attempts"
            raise RateLimitError(msg)

        policy = lic.payload.policy
        if not self.license_validator.validate_policy(policy):
            msg = "invalid policy"
            raise ValidationError(msg)
        return policy

    def _enforce_session_limits(self, license_id: str, policy: dict) -> None:
        """Enforce max sessions limit."""
        max_sessions = policy["max_sessions"]
        active_sessions = self.session_manager.get_active_sessions_count(license_id)
        if active_sessions >= max_sessions:
            msg = "max_sessions exceeded"
            raise ValidationError(msg)

    def _generate_keys_and_session(
        self,
        license_request: StartRequest,
        lic: LicenseData,
        client_pub_hex: str,
        client_eph_pub: X25519PublicKey,
    ) -> tuple[dict, dict]:
        """Generate server keys, derive secrets, and create session data."""
        server_eph_priv = X25519PrivateKey.generate()
        server_eph_pub = server_eph_priv.public_key()
        shared = server_eph_priv.exchange(client_eph_pub)

        session_id = str(uuid.uuid4())
        nonce_prefix = os.urandom(4)

        root_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=(lic.payload.license_id + session_id).encode(),
            info=b"root",
        ).derive(shared)

        effective_prefix = CryptoUtils.get_nonce_prefix_for_epoch(nonce_prefix, 0)
        session_key = CryptoUtils.derive_session_key(
            root_secret, lic.payload.license_id, session_id, 0, effective_prefix.hex()
        )

        expires = int(time.time()) + self.session_ttl
        handshake_data = {
            "license_id": lic.payload.license_id,
            "client_pubkey": license_request.client_pubkey,
            "client_eph_pub": license_request.client_eph_pub,
            "server_eph_pub": server_eph_pub.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
            "nonce_prefix": nonce_prefix.hex(),
        }
        transcript_hash = hashlib.sha256(
            json.dumps(handshake_data, sort_keys=True).encode()
        ).hexdigest()

        transcript_hash_signature = self.license_generator.server_priv.sign(
            transcript_hash.encode()
        ).hex()

        # Encrypt handshake data
        aead = ChaCha20Poly1305(session_key)
        aad = b"handshake"
        plaintext = json.dumps(handshake_data, sort_keys=True).encode()
        nonce = os.urandom(12)
        ciphertext = aead.encrypt(nonce, plaintext, aad)
        handshake_data["ciphertext"] = ciphertext.hex()
        handshake_data["nonce"] = nonce.hex()

        session = SessionData(
            license_id=lic.payload.license_id,
            expires_at=expires,
            client_pub=client_pub_hex,
            expected_counter=0,
            session_key=session_key,
            root_secret=root_secret,
            initial_nonce_prefix=nonce_prefix,
            transcript_hash=transcript_hash,
            rekey_epoch=0,
            last_renew_at=0,
        )

        return {
            "session_id": session_id,
            "session": session,
            "server_eph_pub": server_eph_pub,
            "nonce_prefix": nonce_prefix,
            "expires": expires,
            "transcript_hash": transcript_hash,
            "transcript_hash_signature": transcript_hash_signature,
        }, handshake_data

    def _build_start_response(self, session_data: dict, resp_data: dict) -> dict:
        """Build the response dict for start endpoint."""
        server_eph_pub = session_data["server_eph_pub"]
        resp = {
            "session_id": session_data["session_id"],
            "expires_at": session_data["expires"],
            "protocol_version": self.config.PROTOCOL_VERSION,
            "cipher_suite": self.config.CIPHER_SUITE,
            "license_requestuired_features": self.config.REQUIRED_FEATURES,
            "server_eph_pub": server_eph_pub.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
            "nonce_prefix": session_data["nonce_prefix"].hex(),
            "transcript_hash": session_data["transcript_hash"],
            "transcript_hash_signature": session_data["transcript_hash_signature"],
            "handshake_ciphertext": resp_data["ciphertext"],
            "handshake_nonce": resp_data["nonce"],
        }
        resp["signature"] = self.license_generator.sign(resp)
        return resp
