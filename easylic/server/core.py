"""
OOP-based license server using FastAPI.
"""

import json
import time
import uuid
import os
import hashlib
import hmac
import logging
from typing import Dict, List, Optional, cast
from pathlib import Path
from fastapi import FastAPI, HTTPException, APIRouter
from fastapi.responses import HTMLResponse, Response
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ..common.config import Config
from ..common.models import (
    StartRequest, RenewRequest, RenewResponse,
    RenewData, RenewResponseData, RevokeRequest, GenerateLicenseRequest,
    LicenseData, LicensePayload, Policy, SessionData
)




class LicenseServer:
    """Main license server class handling all operations."""

    def __init__(
        self,
        log_level: int = Config.LOG_LEVEL,
        rekey_after_renews: int = Config.REKEY_AFTER_RENEWS_DEFAULT,
        session_ttl: int = Config.SESSION_TTL,
        max_counter: int = Config.MAX_COUNTER,
        max_start_attempts_per_minute: int = Config.MAX_START_ATTEMPTS_PER_MINUTE,
        max_ciphertext_len: int = Config.MAX_CIPHERTEXT_LEN,
        max_used_eph_pubs_per_license: int = Config.MAX_USED_EPH_PUBS_PER_LICENSE,
        admin_password: str = Config.ADMIN_PASSWORD,
        server_host: str = Config.SERVER_HOST,
        server_port: int = Config.SERVER_PORT,
        base_dir: Optional[Path] = None,
        server_keys_dir: Optional[Path] = None,
        license_file_path: Optional[Path] = None,
        revoked_licenses_file_path: Optional[Path] = None,
    ):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(log_level)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.rekey_after_renews = rekey_after_renews
        self.session_ttl = session_ttl
        self.max_counter = max_counter
        self.max_start_attempts_per_minute = max_start_attempts_per_minute
        self.max_ciphertext_len = max_ciphertext_len
        self.max_used_eph_pubs_per_license = max_used_eph_pubs_per_license
        self.admin_password = admin_password
        self.server_host = server_host
        self.server_port = server_port
        self.base_dir = base_dir or Config.BASE_DIR
        self.server_keys_dir = server_keys_dir or Config.SERVER_KEYS_DIR
        self.license_file_path = license_file_path or Config.LICENSE_FILE_PATH
        self.revoked_licenses_file_path = revoked_licenses_file_path or Config.REVOKED_LICENSES_FILE_PATH
        self.app = FastAPI()
        self.server_pub, self.server_priv = self._get_server_keys()

        # State management
        self.sessions: Dict[str, SessionData] = {}
        self.revoked_licenses: Dict[str, int] = self._load_revoked_licenses()
        self.start_attempts: Dict[str, List[int]] = {}
        self.used_client_eph_pubs: Dict[str, Dict[bytes, int]] = {}

        # Log required client configuration
        self.logger.info(f"Server started on http://{self.server_host}:{self.server_port}")
        self.logger.info(f"Client must set server_url='http://{self.server_host}:{self.server_port}' to connect")

    def _get_server_keys(self):
        """Load server keys from files using configured paths."""
        try:
            with open(self.server_keys_dir / "server_public.key", "rb") as f:
                server_pub = cast(Ed25519PublicKey, serialization.load_pem_public_key(f.read()))
            with open(self.server_keys_dir / "server_private.key", "rb") as f:
                server_priv = cast(Ed25519PrivateKey, serialization.load_pem_private_key(f.read(), None))
        except FileNotFoundError:
            raise ValueError(
                f"Server keys not found at {self.server_keys_dir / 'server_public.key'} and {self.server_keys_dir / 'server_private.key'}. "
                "Run 'easylic-keygen' to generate them."
            )

        return server_pub, server_priv

        # Setup routes
        self._setup_routes()

    def _setup_routes(self):
        """Setup API routes."""
        @self.app.get("/health")
        def health():
            return {"status": "ok", "timestamp": int(time.time())}

    def _health_endpoint(self):
        """Health check endpoint."""
        return {"status": "ok", "timestamp": int(time.time())}

    def _load_revoked_licenses(self) -> Dict[str, int]:
        """Load revoked licenses from file."""
        try:
            with open(self.revoked_licenses_file_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_revoked_licenses(self):
        """Save revoked licenses to file."""
        with open(self.revoked_licenses_file_path, "w") as f:
            json.dump(self.revoked_licenses, f)

    def clean_expired_sessions(self):
        """Clean expired sessions and related data."""
        now = int(time.time())
        expired = [sid for sid, sess in self.sessions.items() if sess.expires_at < now]
        for sid in expired:
            self.sessions.pop(sid, None)

        # Clean expired start attempts (TTL 60s)
        for lid in list(self.start_attempts.keys()):
            self.start_attempts[lid] = [t for t in self.start_attempts[lid] if now - t < 60]
            if not self.start_attempts[lid]:
                del self.start_attempts[lid]

        # Clean expired used client eph pubs (TTL 60s)
        for lid in list(self.used_client_eph_pubs.keys()):
            for pub in list(self.used_client_eph_pubs[lid].keys()):
                if now - self.used_client_eph_pubs[lid][pub] > 60:
                    del self.used_client_eph_pubs[lid][pub]
            # Enforce upper bound to prevent memory exhaustion
            if len(self.used_client_eph_pubs[lid]) > self.max_used_eph_pubs_per_license:
                sorted_items = sorted(self.used_client_eph_pubs[lid].items(), key=lambda x: x[1])
                self.used_client_eph_pubs[lid] = dict(sorted_items[:self.max_used_eph_pubs_per_license])
            if not self.used_client_eph_pubs[lid]:
                del self.used_client_eph_pubs[lid]

    def verify_license(self, lic: LicenseData) -> bool:
        """Verify license signature and validity."""
        payload = lic.payload
        sig = bytes.fromhex(lic.signature)
        data = json.dumps(payload.model_dump(), sort_keys=True).encode()
        try:
            self.server_pub.verify(sig, data)  # type: ignore
        except Exception:
            return False
        now = int(time.time())

        # Check if license is revoked
        license_id = payload.license_id
        if license_id in self.revoked_licenses:
            return False  # Revoked licenses are permanently invalid

        return payload.valid_from <= now <= payload.valid_until

    def sign(self, obj: dict) -> str:
        """Sign a dictionary object."""
        data = json.dumps(obj, sort_keys=True).encode()
        return self.server_priv.sign(data).hex()  # type: ignore

    def generate_license(self, license_id: str, product: str, valid_from: int, valid_until: int, policy: dict) -> LicenseData:
        """Generate a signed license."""
        if not self.validate_policy(policy):
            raise ValueError("Invalid policy")
        payload = LicensePayload(
            license_id=license_id,
            product=product,
            valid_from=valid_from,
            valid_until=valid_until,
            policy=policy
        )
        signature = self.sign(payload.model_dump())
        return LicenseData(payload=payload, signature=signature)

    @staticmethod
    def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
        """Calculate nonce prefix for a given epoch."""
        epoch_bytes = epoch.to_bytes(4, 'big')
        return bytes(a ^ b for a, b in zip(initial_nonce_prefix, epoch_bytes))

    @staticmethod
    def derive_session_key(root_secret: bytes, license_id: str, session_id: str, rekey_epoch: int = 0, effective_nonce_prefix_hex: str = "") -> bytes:
        """Derive session key from root secret."""
        salt = (license_id + session_id + effective_nonce_prefix_hex).encode()
        info = f"epoch:{rekey_epoch}".encode()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(root_secret)

    async def start(self, req: StartRequest):
        """Handle /start endpoint."""
        # Check protocol version
        if req.version != Config.PROTOCOL_VERSION:
            raise HTTPException(403, "protocol version mismatch")

        # Validate required security features
        for feature, required in Config.REQUIRED_FEATURES.items():
            if req.supported_features.get(feature) != required:
                raise HTTPException(403, f"required feature not supported: {feature}")

        self.clean_expired_sessions()
        lic = req.license
        client_pub_hex = req.client_pubkey
        client_eph_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(req.client_eph_pub)
        )

        # Anti-replay: check if client ephemeral pub was used recently
        pub_bytes = client_eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        license_id = lic.payload.license_id
        if license_id not in self.used_client_eph_pubs:
            self.used_client_eph_pubs[license_id] = {}
        if pub_bytes in self.used_client_eph_pubs[license_id]:
            raise HTTPException(403, "handshake replay detected")
        self.used_client_eph_pubs[license_id][pub_bytes] = int(time.time())

        if not self.verify_license(lic):
            raise HTTPException(403, "invalid license")

        license_id = lic.payload.license_id
        now = int(time.time())

        # Rate limit start attempts to prevent replay DoS
        if license_id not in self.start_attempts:
            self.start_attempts[license_id] = []
        self.start_attempts[license_id] = [t for t in self.start_attempts[license_id] if now - t < 60]
        if len(self.start_attempts[license_id]) >= self.max_start_attempts_per_minute:
            raise HTTPException(429, "too many start attempts")

        # Validate policy
        policy = lic.payload.policy
        if not self.validate_policy(policy):
            raise HTTPException(403, "invalid policy")

        # Enforce max_sessions
        max_sessions = policy["max_sessions"]
        active_sessions = len([s for s in self.sessions.values() if s.license_id == license_id])
        if active_sessions >= max_sessions:
            raise HTTPException(403, "max_sessions exceeded")

        # server ephemeral key
        server_eph_priv = X25519PrivateKey.generate()
        server_eph_pub = server_eph_priv.public_key()

        shared = server_eph_priv.exchange(client_eph_pub)

        session_id = str(uuid.uuid4())
        nonce_prefix = os.urandom(4)

        # Derive root secret from shared
        root_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=(lic.payload.license_id + session_id).encode(),
            info=b"root",
        ).derive(shared)

        effective_prefix = self.get_nonce_prefix_for_epoch(nonce_prefix, 0)
        session_key = self.derive_session_key(
            root_secret, lic.payload.license_id, session_id, 0, effective_prefix.hex()
        )

        expires = int(time.time()) + self.session_ttl
        # Calculate handshake transcript hash for channel binding
        handshake_data = {
            "license_id": lic.payload.license_id,
            "client_pubkey": req.client_pubkey,
            "client_eph_pub": req.client_eph_pub,
            "server_eph_pub": server_eph_pub.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
            "nonce_prefix": nonce_prefix.hex(),
        }
        transcript_hash = hashlib.sha256(json.dumps(handshake_data, sort_keys=True).encode()).hexdigest()

        self.sessions[session_id] = SessionData(
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

        resp = {
            "session_id": session_id,
            "expires_at": expires,
            "protocol_version": Config.PROTOCOL_VERSION,
            "cipher_suite": Config.CIPHER_SUITE,
            "required_features": Config.REQUIRED_FEATURES,
            "server_eph_pub": server_eph_pub.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
            "nonce_prefix": self.sessions[session_id].initial_nonce_prefix.hex(),
        }
        resp["signature"] = self.sign(resp)
        return resp

    async def renew(self, req: RenewRequest):
        """Handle /renew endpoint."""
        session_id = req.session_id
        sess = self.sessions.get(session_id)
        now = int(time.time())

        if not sess or sess.expires_at < now:
            self.sessions.pop(session_id, None)
            raise HTTPException(403, "session expired")

        # Rate limit renew attempts to prevent DoS
        if now - sess.last_renew_at < 0.1:
            raise HTTPException(429, "too many renews")

        if sess.expected_counter >= self.max_counter:
            self.sessions.pop(session_id, None)
            raise HTTPException(403, "session counter overflow")

        # Check if license is revoked (mandatory invariant: revoke ⇒ no renew)
        if sess.license_id in self.revoked_licenses:
            self.sessions.pop(session_id, None)
            raise HTTPException(403, "license revoked")

        ciphertext = bytes.fromhex(req.ciphertext)
        if len(ciphertext) > self.max_ciphertext_len:
            raise HTTPException(403, "ciphertext too large")
        counter = req.counter
        nonce = self.get_nonce_prefix_for_epoch(sess.initial_nonce_prefix, sess.rekey_epoch) + counter.to_bytes(8, "big")

        # Check counter before decrypt to prevent CPU-DoS
        if counter > sess.expected_counter:
            raise HTTPException(403, "counter too high")

        aead = ChaCha20Poly1305(sess.session_key)
        # Invariant: AAD binds ciphertext to protocol version, cipher suite, session, license, client, and handshake transcript
        aad = f"renew:{Config.CIPHER_SUITE}:{session_id}:{sess.license_id}:{sess.client_pub}:{sess.transcript_hash}:{sess.rekey_epoch}".encode()
        try:
            plaintext = aead.decrypt(nonce, ciphertext, aad)
        except Exception:
            raise HTTPException(403, "decrypt failed")

        data = RenewData.model_validate_json(plaintext.decode())
        if data.session_id != session_id:
            raise HTTPException(403, "session_id mismatch")
        if data.version != Config.PROTOCOL_VERSION:
            raise HTTPException(403, "protocol version mismatch")
        if data.cipher_suite != Config.CIPHER_SUITE:
            raise HTTPException(403, "cipher suite mismatch")
        inner_counter = data.counter
        if inner_counter != counter:
            raise HTTPException(403, "counter mismatch")
        sig = bytes.fromhex(data.client_sig)

        # Invariant: Allow idempotent retries with same counter
        if inner_counter == sess.expected_counter:
            # Normal renew
            is_retry = False
        elif inner_counter == sess.expected_counter - 1:
            # Retry of previous renew
            is_retry = True
        else:
            raise HTTPException(403, "counter mismatch")

        # Check for invalid replay in retry window
        if is_retry:
            if not hmac.compare_digest(
                hashlib.sha256(ciphertext).digest(),
                sess.last_cipher_hash or b""
            ):
                raise HTTPException(403, "invalid retry")

        if inner_counter == 0:
            expected_proof = hmac.new(sess.session_key, b"client-finished:" + sess.transcript_hash.encode(), hashlib.sha256).hexdigest()
            if data.client_proof != expected_proof:
                raise HTTPException(403, "client proof mismatch")

        # Proof-of-possession
        msg = f"renew:{session_id}:{inner_counter}".encode()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sess.client_pub)).verify(sig, msg)

        if not is_retry:
            sess.last_cipher_hash = hashlib.sha256(ciphertext).digest()
            sess.expected_counter += 1
            old_epoch = sess.rekey_epoch
            sess.rekey_epoch = sess.expected_counter // 10
            if sess.rekey_epoch > old_epoch:
                effective_prefix = self.get_nonce_prefix_for_epoch(sess.initial_nonce_prefix, sess.rekey_epoch)
                sess.session_key = self.derive_session_key(
                    sess.root_secret, sess.license_id, session_id, sess.rekey_epoch, effective_prefix.hex()
                )
                aead = ChaCha20Poly1305(sess.session_key)
            sess.expires_at = now + self.session_ttl
            sess.last_renew_at = now

        resp_plain = RenewResponseData(
            expires_at=sess.expires_at,
            next_counter=sess.expected_counter,
            epoch_used=sess.rekey_epoch,
            version=Config.PROTOCOL_VERSION,
            cipher_suite=Config.CIPHER_SUITE,
        )
        if sess.expected_counter == 1:
            resp_plain.server_proof = hmac.new(sess.session_key, b"server-finished:" + sess.transcript_hash.encode(), hashlib.sha256).hexdigest()

        # Rekey every N renews, only on normal renew
        if not is_retry and sess.expected_counter % self.rekey_after_renews == 0:
            resp_plain.rekey_ack = True

        effective_prefix = self.get_nonce_prefix_for_epoch(sess.initial_nonce_prefix, sess.rekey_epoch)
        resp_nonce = effective_prefix + sess.expected_counter.to_bytes(8, "big")
        # Invariant: AAD binds ciphertext to protocol version, cipher suite, session, license, client, and handshake transcript
        aad = f"renew:{Config.CIPHER_SUITE}:{session_id}:{sess.license_id}:{sess.client_pub}:{sess.transcript_hash}:{sess.rekey_epoch}".encode()
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

    async def revoke(self, req: RevokeRequest):
        """Handle /revoke endpoint."""
        payload = req.payload
        if payload.get("password") != self.admin_password:
            raise HTTPException(403, "Invalid admin password")

        license_id = payload["license_id"]
        now = int(time.time())

        # Record revocation timestamp
        self.revoked_licenses[license_id] = now
        self._save_revoked_licenses()

        # Force expire all sessions for this license
        expired_sessions = [
            sid for sid, sess in self.sessions.items()
            if sess.license_id == license_id
        ]
        for sid in expired_sessions:
            self.sessions.pop(sid, None)

        # Clean start attempts for revoked license
        self.start_attempts.pop(license_id, None)
        # Clean used client eph pubs for revoked license
        self.used_client_eph_pubs.pop(license_id, None)

        return {"revoked_at": now}

    async def generate_license_endpoint(self, req: GenerateLicenseRequest):
        """Handle /generate_license endpoint."""
        payload = req.payload
        if payload.get("password") != self.admin_password:
            raise HTTPException(403, "Invalid admin password")

        try:
            license_id = payload["license_id"]
            product = payload["product"]
            valid_from = payload["valid_from"]
            valid_until = payload["valid_until"]
            policy = payload["policy"]
            license_data = self.generate_license(license_id, product, valid_from, valid_until, policy)

            # Return as downloadable JSON file
            json_str = json.dumps(license_data.model_dump(), indent=2)
            return Response(
                content=json_str,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=license_{license_id}.json"}
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        except KeyError:
            raise HTTPException(400, "Missing required fields")

    def validate_policy(self, policy: dict) -> bool:
        """Server-side validation for policy."""
        try:
            Policy(**policy)
            return policy.get("version") == Config.POLICY_VERSION
        except Exception:
            return False

    def health(self):
        """Health check endpoint."""
        return {"status": "ok", "timestamp": int(time.time())}

    async def admin_page(self):
        """Handle /admin endpoint."""
        with open("admin.html", "r") as f:
            return HTMLResponse(f.read())