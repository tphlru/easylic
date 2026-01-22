"""
Renew request handler for license service.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from easylic.common.crypto import CryptoUtils
from easylic.common.exceptions import RateLimitError, ValidationError
from easylic.common.models import (
    RenewData,
    RenewRequest,
    RenewResponse,
    RenewResponseData,
    SessionData,
)

if TYPE_CHECKING:
    from easylic.common.config import Config
    from easylic.common.interfaces import ILicenseValidator, ISessionManager


class RenewHandler:
    """Handles renew request logic."""

    def __init__(  # noqa: PLR0913
        self,
        config: Config,
        session_manager: ISessionManager,
        license_validator: ILicenseValidator,
        rekey_after_renews: int,
        session_ttl: int,
        max_counter: int,
        max_ciphertext_len: int,
        logger: Any,
    ):
        self.config = config
        self.session_manager = session_manager
        self.license_validator = license_validator
        self.rekey_after_renews = rekey_after_renews
        self.session_ttl = session_ttl
        self.max_counter = max_counter
        self.max_ciphertext_len = max_ciphertext_len
        self.logger = logger

    def handle_renew(self, req: RenewRequest) -> RenewResponse:
        """Handle renew request."""
        sess = self._validate_renew_session(req)
        data, is_retry = self._decrypt_and_validate_data(req, sess)
        self._process_counter_and_rekey(sess, data, is_retry, req.ciphertext)
        return self._build_renew_response(sess, data, is_retry)

    def _validate_renew_session(self, req: RenewRequest) -> SessionData:
        """Validate session existence, expiration, rate limit, revocation, and counter overflow."""  # noqa: E501
        session_id = req.session_id
        sess = self.session_manager.get_session(session_id)
        now = int(time.time())

        if not sess or sess.expires_at < now:
            self.session_manager.remove_session(session_id)
            msg = "session expired"
            raise ValidationError(msg)

        if now - sess.last_renew_at < self.config.RENEW_RATE_LIMIT:
            msg = "too many renews"
            raise RateLimitError(msg)

        if sess.expected_counter >= self.max_counter:
            self.session_manager.remove_session(session_id)
            msg = "session counter overflow"
            raise ValidationError(msg)

        license_id = sess.license_id
        revoked_licenses = self.license_validator.revoked_licenses
        if license_id in revoked_licenses:
            self.session_manager.remove_session(session_id)
            msg = "license revoked"
            raise ValidationError(msg)

        return sess

    def _decrypt_and_validate_data(
        self, req: RenewRequest, sess: SessionData
    ) -> tuple[RenewData, bool]:
        """Decrypt ciphertext and validate the inner data."""
        ciphertext = bytes.fromhex(req.ciphertext)
        if len(ciphertext) > self.max_ciphertext_len:
            msg = "ciphertext too large"
            raise ValidationError(msg)
        counter = req.counter

        if counter > sess.expected_counter:
            msg = "counter too high"
            raise ValidationError(msg)

        nonce = CryptoUtils.get_nonce_prefix_for_epoch(
            sess.initial_nonce_prefix, sess.rekey_epoch
        ) + counter.to_bytes(8, "big")

        aead = ChaCha20Poly1305(sess.session_key)
        aad_str = (
            f"renew:{self.config.CIPHER_SUITE}:{req.session_id}:"
            f"{sess.license_id}:{sess.client_pub}:"
            f"{sess.transcript_hash}:{sess.rekey_epoch}"
        )
        aad = aad_str.encode()
        try:
            plaintext = aead.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            msg = "decrypt failed"
            raise ValidationError(msg) from e

        data = RenewData.model_validate_json(plaintext.decode())
        self._validate_decrypted_data(data, req, sess, counter)

        is_retry = self._determine_retry_status(data.counter, sess.expected_counter)
        if is_retry:
            self._check_retry_validity(ciphertext, sess)

        self._validate_proofs_and_signature(data, sess, req.session_id)
        return data, is_retry

    def _validate_decrypted_data(
        self, data: RenewData, req: RenewRequest, sess: SessionData, counter: int
    ) -> None:
        """Validate fields in decrypted renew data."""
        if data.session_id != req.session_id:
            msg = "session_id mismatch"
            raise ValidationError(msg)
        if data.version != self.config.PROTOCOL_VERSION:
            msg = "protocol version mismatch"
            raise ValidationError(msg)
        if data.cipher_suite != self.config.CIPHER_SUITE:
            msg = "cipher suite mismatch"
            raise ValidationError(msg)
        if data.counter != counter:
            msg = "counter mismatch"
            raise ValidationError(msg)
        if data.transcript_hash != sess.transcript_hash:
            msg = "transcript hash mismatch"
            raise ValidationError(msg)

    def _determine_retry_status(
        self, inner_counter: int, expected_counter: int
    ) -> bool:
        """Determine if this is a retry request."""
        if inner_counter == expected_counter:
            return False
        if inner_counter == expected_counter - 1:
            return True
        msg = "counter mismatch"
        raise ValidationError(msg)

    def _check_retry_validity(self, ciphertext: bytes, sess: SessionData) -> None:
        """Check if retry ciphertext matches previous."""
        if not hmac.compare_digest(
            hashlib.sha256(ciphertext).digest(), sess.last_cipher_hash or b""
        ):
            msg = "invalid retry"
            raise ValidationError(msg)

    def _validate_proofs_and_signature(
        self, data: RenewData, sess: SessionData, session_id: str
    ) -> None:
        """Validate client proofs and signature."""
        if data.counter == 0:
            expected_proof = hmac.new(
                sess.session_key,
                b"client-finished:" + sess.transcript_hash.encode(),
                hashlib.sha256,
            ).hexdigest()
            if data.client_proof != expected_proof:
                msg = "client proof mismatch"
                raise ValidationError(msg)

        message = f"renew:{session_id}:{data.counter}".encode()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sess.client_pub)).verify(
            bytes.fromhex(data.client_sig), message
        )

    def _process_counter_and_rekey(
        self,
        sess: SessionData,
        data: RenewData,
        is_retry: bool,  # noqa: FBT001
        ciphertext: str,
    ) -> None:
        """Process counter increment, rekeying, and session updates."""
        if not is_retry:
            sess.last_cipher_hash = hashlib.sha256(bytes.fromhex(ciphertext)).digest()
            sess.expected_counter += 1
            old_epoch = sess.rekey_epoch
            sess.rekey_epoch = sess.expected_counter // self.rekey_after_renews
            if sess.rekey_epoch > old_epoch:
                effective_prefix = CryptoUtils.get_nonce_prefix_for_epoch(
                    sess.initial_nonce_prefix, sess.rekey_epoch
                )
                sess.session_key = CryptoUtils.derive_session_key(
                    sess.root_secret,
                    sess.license_id,
                    data.session_id,
                    sess.rekey_epoch,
                    effective_prefix.hex(),
                )
            sess.expires_at = int(time.time()) + self.session_ttl
            sess.last_renew_at = int(time.time())

    def _build_renew_response(
        self,
        sess: SessionData,
        data: RenewData,
        is_retry: bool,  # noqa: FBT001
    ) -> RenewResponse:
        """Build the encrypted response for renew."""
        resp_plain = RenewResponseData(
            expires_at=sess.expires_at,
            next_counter=sess.expected_counter,
            epoch_used=sess.rekey_epoch,
            version=self.config.PROTOCOL_VERSION,
            cipher_suite=self.config.CIPHER_SUITE,
        )
        if sess.expected_counter == 1:
            resp_plain.server_proof = hmac.new(
                sess.session_key,
                b"server-finished:" + sess.transcript_hash.encode(),
                hashlib.sha256,
            ).hexdigest()

        if not is_retry and sess.expected_counter % self.rekey_after_renews == 0:
            resp_plain.rekey_ack = True

        effective_prefix = CryptoUtils.get_nonce_prefix_for_epoch(
            sess.initial_nonce_prefix, sess.rekey_epoch
        )
        resp_nonce = effective_prefix + sess.expected_counter.to_bytes(8, "big")
        aad_str = (
            f"renew:{self.config.CIPHER_SUITE}:{data.session_id}:"
            f"{sess.license_id}:{sess.client_pub}:"
            f"{sess.transcript_hash}:{sess.rekey_epoch}"
        )
        aad = aad_str.encode()
        aead = ChaCha20Poly1305(sess.session_key)
        resp_cipher = aead.encrypt(
            resp_nonce,
            json.dumps(resp_plain.model_dump()).encode(),
            aad,
        )

        return RenewResponse(
            ciphertext=resp_cipher.hex(),
            counter=sess.expected_counter,
            epoch_used=sess.rekey_epoch,
        )
