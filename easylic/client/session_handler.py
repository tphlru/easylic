"""
Session handling for license client.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import TYPE_CHECKING

import requests
from cryptography.hazmat.primitives import hashes

HTTP_OK = 200

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from easylic.common.config import Config
from easylic.common.crypto import CryptoUtils
from easylic.common.models import (
    LicenseData,
    RenewData,
    RenewRequest,
    RenewResponse,
    RenewResponseData,
    StartRequest,
    StartResponse,
)

logger = logging.getLogger(__name__)


class SessionHandler:
    """Handles session start, renew, and management."""

    def __init__(
        self,
        server_url: str,
        license_data: LicenseData,
        client_priv: Ed25519PrivateKey,
        client_pub_hex: str,
        client_eph_priv: X25519PrivateKey,
        client_eph_pub_hex: str,
        server_pub: Ed25519PublicKey,
    ):
        self.server_url = server_url
        self.license_data = license_data
        self.client_priv = client_priv
        self.client_pub_hex = client_pub_hex
        self.client_eph_priv = client_eph_priv
        self.client_eph_pub_hex = client_eph_pub_hex
        self.server_pub = server_pub

        # Session state
        self.session_id: str | None = None
        self.initial_nonce_prefix: bytes | None = None
        self.session_key: bytes | None = None
        self.root_secret: bytes | None = None
        self.transcript_hash: str | None = None
        self.counter: int = 0
        self.rekey_epoch: int = 0
        self.aead: ChaCha20Poly1305 | None = None

    def start_session(self) -> str:
        """Start a secure session with the server."""
        logger.info("Starting session...")

        req = StartRequest(
            version=Config.PROTOCOL_VERSION,
            license=self.license_data,
            client_pubkey=self.client_pub_hex,
            client_eph_pub=self.client_eph_pub_hex,
            supported_features=Config.REQUIRED_FEATURES,
        )

        r = requests.post(f"{self.server_url}/start", json=req.model_dump(), timeout=10)
        r.raise_for_status()
        resp = StartResponse.model_validate(r.json())

        # Verify protocol version
        if resp.protocol_version != Config.PROTOCOL_VERSION:
            msg = "Protocol version mismatch"
            raise ValueError(msg)

        # Verify cipher suite
        if resp.cipher_suite != Config.CIPHER_SUITE:
            msg = "Cipher suite mismatch"
            raise ValueError(msg)

        # Verify required features
        if resp.required_features != Config.REQUIRED_FEATURES:
            msg = "Required features mismatch"
            raise ValueError(msg)

        # Verify signature
        signature = bytes.fromhex(resp.signature)
        resp_dict = resp.model_dump()
        resp_dict.pop("signature")
        self.server_pub.verify(
            signature, json.dumps(resp_dict, sort_keys=True).encode()
        )

        server_eph_pub = bytes.fromhex(resp.server_eph_pub)
        self.session_id = resp.session_id
        self.initial_nonce_prefix = bytes.fromhex(resp.nonce_prefix)

        shared = self.client_eph_priv.exchange(
            X25519PublicKey.from_public_bytes(server_eph_pub)
        )

        # Derive root secret from shared
        self.root_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=(self.license_data.payload.license_id + self.session_id).encode(),
            info=b"root",
        ).derive(shared)

        # Calculate handshake transcript hash for channel binding
        handshake_data = {
            "license_id": self.license_data.payload.license_id,
            "client_pubkey": self.client_pub_hex,
            "client_eph_pub": self.client_eph_pub_hex,
            "server_eph_pub": resp.server_eph_pub,
            "nonce_prefix": resp.nonce_prefix,
        }
        self.transcript_hash = hashlib.sha256(
            json.dumps(handshake_data, sort_keys=True).encode()
        ).hexdigest()

        effective_prefix = CryptoUtils.get_nonce_prefix_for_epoch(
            self.initial_nonce_prefix, 0
        )
        self.session_key = CryptoUtils.derive_session_key(
            self.root_secret,
            self.license_data.payload.license_id,
            self.session_id,
            0,
            effective_prefix.hex(),
        )
        self.aead = ChaCha20Poly1305(self.session_key)

        logger.info("Secure session started: %s", self.session_id)
        return self.session_id

    def is_license_active(self) -> bool:
        """Check if the license is currently active (session is valid)."""
        return self.session_id is not None and self.initial_nonce_prefix is not None

    def renew_session(self) -> bool:
        """Renew the current session."""
        if not self.session_id:
            logger.error("No active session")
            return False

        assert self.session_key is not None
        assert self.initial_nonce_prefix is not None
        assert self.root_secret is not None
        assert self.transcript_hash is not None
        assert self.aead is not None

        msg = f"renew:{self.session_id}:{self.counter}".encode()
        client_sig = self.client_priv.sign(msg).hex()

        renew_data = RenewData(
            session_id=self.session_id,
            counter=self.counter,
            client_sig=client_sig,
            version=Config.PROTOCOL_VERSION,
            cipher_suite=Config.CIPHER_SUITE,
        )
        if self.counter == 0:
            renew_data.client_proof = hmac.new(
                self.session_key,
                b"client-finished:" + self.transcript_hash.encode(),
                hashlib.sha256,
            ).hexdigest()

        plaintext = json.dumps(renew_data.model_dump()).encode()

        effective_prefix = CryptoUtils.get_nonce_prefix_for_epoch(
            self.initial_nonce_prefix, self.rekey_epoch
        )
        nonce = effective_prefix + self.counter.to_bytes(8, "big")
        aad_str = (
            f"renew:{Config.CIPHER_SUITE}:{self.session_id}:"
            f"{self.license_data.payload.license_id}:{self.client_pub_hex}:"
            f"{self.transcript_hash}:{self.rekey_epoch}"
        )
        aad = aad_str.encode()
        cipher = self.aead.encrypt(nonce, plaintext, aad)

        retry_count = 0
        max_retries = 3
        backoff = 1
        success = False
        while retry_count < max_retries:
            r = requests.post(
                f"{self.server_url}/renew",
                json=RenewRequest(
                    session_id=self.session_id,
                    ciphertext=cipher.hex(),
                    counter=self.counter,
                ).model_dump(),
                timeout=10,
            )
            if r.status_code == HTTP_OK:
                success = True
                break
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(backoff)
                backoff *= 2

        if not success:
            logger.error("Session lost after retries")
            return False

        assert r is not None
        data = RenewResponse.model_validate(r.json())
        resp_counter = data.counter
        epoch_used = data.epoch_used

        resp_effective_prefix = CryptoUtils.get_nonce_prefix_for_epoch(
            self.initial_nonce_prefix, epoch_used
        )
        resp_nonce = resp_effective_prefix + resp_counter.to_bytes(8, "big")

        resp_session_key = CryptoUtils.derive_session_key(
            self.root_secret,
            self.license_data.payload.license_id,
            self.session_id,
            epoch_used,
            resp_effective_prefix.hex(),
        )
        resp_aead = ChaCha20Poly1305(resp_session_key)

        resp_aad_str = (
            f"renew:{Config.CIPHER_SUITE}:{self.session_id}:"
            f"{self.license_data.payload.license_id}:{self.client_pub_hex}:"
            f"{self.transcript_hash}:{epoch_used}"
        )
        resp_aad = resp_aad_str.encode()
        resp_plain_dict = json.loads(
            resp_aead.decrypt(
                resp_nonce,
                bytes.fromhex(data.ciphertext),
                resp_aad,
            ).decode()
        )
        resp_plain = RenewResponseData.model_validate(resp_plain_dict)

        if resp_plain.version != Config.PROTOCOL_VERSION:
            logger.error("Protocol version mismatch")
            return False
        if resp_plain.cipher_suite != Config.CIPHER_SUITE:
            logger.error("Cipher suite mismatch")
            return False

        if resp_plain.next_counter == 1:
            expected_proof = hmac.new(
                self.session_key,
                b"server-finished:" + self.transcript_hash.encode(),
                hashlib.sha256,
            ).hexdigest()
            if resp_plain.server_proof != expected_proof:
                logger.error("Server proof mismatch")
                return False

        self.counter = resp_plain.next_counter
        old_epoch = self.rekey_epoch
        self.rekey_epoch = self.counter // 10
        if self.rekey_epoch > old_epoch:
            effective_prefix = CryptoUtils.get_nonce_prefix_for_epoch(
                self.initial_nonce_prefix, self.rekey_epoch
            )
            self.session_key = CryptoUtils.derive_session_key(
                self.root_secret,
                self.license_data.payload.license_id,
                self.session_id,
                self.rekey_epoch,
                effective_prefix.hex(),
            )
            self.aead = ChaCha20Poly1305(self.session_key)

        logger.info("Renew OK, counter = %s", self.counter)
        return True
