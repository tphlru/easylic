"""
OOP-based license client.
"""

import json
import time
import hashlib
import hmac
import requests
import logging
import threading
from typing import Optional, Callable
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from typing import cast
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ..common.config import Config
from ..common.models import LicenseData, StartRequest, StartResponse, RenewRequest, RenewResponse, RenewData, RenewResponseData

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def error_handler(error: Exception):
    print(f"License error occurred: {error}")
    # Custom error handling logic here


class LicenseClient:
    """License client for secure session management."""

    def __init__(
        self,
        server_url: Optional[str] = None,
        license_file: Optional[str] = None,
        log_level: int = Config.LOG_LEVEL,
        on_error_callback: Optional[Callable[[Exception], None]] = None,
        renew_interval: int = Config.RENEW_INTERVAL_DEFAULT,
        session_ttl: int = Config.SESSION_TTL,
        max_counter: int = Config.MAX_COUNTER,
        max_start_attempts_per_minute: int = Config.MAX_START_ATTEMPTS_PER_MINUTE,
        max_ciphertext_len: int = Config.MAX_CIPHERTEXT_LEN,
        max_used_eph_pubs_per_license: int = Config.MAX_USED_EPH_PUBS_PER_LICENSE,
        server_host: Optional[str] = None,
        server_port: Optional[int] = None,
        base_dir: Optional[Path] = None,
        server_keys_dir: Optional[Path] = None,
        license_file_path: Optional[Path] = None,
        revoked_licenses_file_path: Optional[Path] = None,
    ):
        # Compute server_url if host and port provided
        if server_host and server_port:
            self.server_url = f"http://{server_host}:{server_port}"
        else:
            self.server_url = server_url or Config.SERVER_URL

        # Configurable paths
        self.base_dir = base_dir or Config.BASE_DIR
        self.server_keys_dir = server_keys_dir or Config.SERVER_KEYS_DIR
        self.license_file_path = license_file_path or Config.LICENSE_FILE_PATH
        self.revoked_licenses_file_path = revoked_licenses_file_path or Config.REVOKED_LICENSES_FILE_PATH

        self.license_file = license_file or self.license_file_path
        self.on_error_callback = on_error_callback
        self.renew_interval = renew_interval
        self.session_ttl = session_ttl
        self.max_counter = max_counter
        self.max_start_attempts_per_minute = max_start_attempts_per_minute
        self.max_ciphertext_len = max_ciphertext_len
        self.max_used_eph_pubs_per_license = max_used_eph_pubs_per_license
        self._thread: Optional[threading.Thread] = None

        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(log_level)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # Load server public key
        with open(self.server_keys_dir / "server_public.key", "rb") as key_f:
            self.server_pub: Ed25519PublicKey = cast(Ed25519PublicKey, serialization.load_pem_public_key(key_f.read()))

        # Load license
        with open(self.license_file) as lic_f:
            self.license = LicenseData.model_validate_json(lic_f.read())

        # Generate client keys
        self.client_priv: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self.client_pub_hex: str = self.client_priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()

        # ephemeral transport key
        self.client_eph_priv: X25519PrivateKey = X25519PrivateKey.generate()
        self.client_eph_pub_hex: str = self.client_eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()

        # Session state
        self.session_id: Optional[str] = None
        self.initial_nonce_prefix: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.root_secret: Optional[bytes] = None
        self.transcript_hash: Optional[str] = None
        self.counter: int = 0
        self.rekey_epoch: int = 0
        self.aead: Optional[ChaCha20Poly1305] = None

    @staticmethod
    def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
        """Calculate nonce prefix for a given epoch."""
        epoch_bytes = epoch.to_bytes(4, 'big')
        return bytes(a ^ b for a, b in zip(initial_nonce_prefix, epoch_bytes))

    @staticmethod
    def derive_session_key(root_secret: bytes, license_id: str, session_id: str, rekey_epoch: int = 0, nonce_prefix_hex: str = "") -> bytes:
        """Derive session key from root secret."""
        salt = (license_id + session_id + nonce_prefix_hex).encode()
        info = f"epoch:{rekey_epoch}".encode()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(root_secret)

    def start_session(self) -> str:
        """Start a secure session with the server."""
        logger.info("Starting session...")

        req = StartRequest(
            version=Config.PROTOCOL_VERSION,
            license=self.license,
            client_pubkey=self.client_pub_hex,
            client_eph_pub=self.client_eph_pub_hex,
            supported_features=Config.REQUIRED_FEATURES
        )

        r = requests.post(f"{self.server_url}/start", json=req.model_dump())
        r.raise_for_status()
        resp = StartResponse.model_validate(r.json())

        # Verify protocol version
        if resp.protocol_version != Config.PROTOCOL_VERSION:
            raise ValueError("Protocol version mismatch")

        # Verify cipher suite
        if resp.cipher_suite != Config.CIPHER_SUITE:
            raise ValueError("Cipher suite mismatch")

        # Verify required features
        if resp.required_features != Config.REQUIRED_FEATURES:
            raise ValueError("Required features mismatch")

        # Verify signature
        signature = bytes.fromhex(resp.signature)
        resp_dict = resp.model_dump()
        resp_dict.pop("signature")
        self.server_pub.verify(
            signature,
            json.dumps(resp_dict, sort_keys=True).encode()
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
            salt=(self.license.payload.license_id + self.session_id).encode(),
            info=b"root",
        ).derive(shared)

        # Calculate handshake transcript hash for channel binding
        handshake_data = {
            "license_id": self.license.payload.license_id,
            "client_pubkey": self.client_pub_hex,
            "client_eph_pub": self.client_eph_pub_hex,
            "server_eph_pub": resp.server_eph_pub,
            "nonce_prefix": resp.nonce_prefix,
        }
        self.transcript_hash = hashlib.sha256(json.dumps(handshake_data, sort_keys=True).encode()).hexdigest()

        effective_prefix = self.get_nonce_prefix_for_epoch(self.initial_nonce_prefix, 0)
        self.session_key = self.derive_session_key(
            self.root_secret, self.license.payload.license_id, self.session_id, 0, effective_prefix.hex()
        )
        self.aead = ChaCha20Poly1305(self.session_key)

        self.logger.info(f"Secure session started: {self.session_id}")
        return self.session_id

    def is_license_active(self) -> bool:
        """Check if the license is currently active (session is valid)."""
        if not self.session_id or not self.initial_nonce_prefix:
            return False
        # Simple check: if session_id exists and no error occurred
        # In a real implementation, you might check expiry time if available
        return True

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
            renew_data.client_proof = hmac.new(self.session_key, b"client-finished:" + self.transcript_hash.encode(), hashlib.sha256).hexdigest()

        plaintext = json.dumps(renew_data.model_dump()).encode()

        effective_prefix = self.get_nonce_prefix_for_epoch(self.initial_nonce_prefix, self.rekey_epoch)
        nonce = effective_prefix + self.counter.to_bytes(8, "big")
        aad = f"renew:{Config.CIPHER_SUITE}:{self.session_id}:{self.license.payload.license_id}:{self.client_pub_hex}:{self.transcript_hash}:{self.rekey_epoch}".encode()
        cipher = self.aead.encrypt(nonce, plaintext, aad)

        retry_count = 0
        max_retries = 3
        backoff = 1
        success = False
        while retry_count < max_retries:
            r = requests.post(f"{self.server_url}/renew", json=RenewRequest(
                session_id=self.session_id,
                ciphertext=cipher.hex(),
                counter=self.counter,
            ).model_dump())
            if r.status_code == 200:
                success = True
                break
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(backoff)
                backoff *= 2

        if not success:
            logger.error("Session lost after retries")
            return False

        data = RenewResponse.model_validate(r.json())
        resp_counter = data.counter
        epoch_used = data.epoch_used

        resp_effective_prefix = self.get_nonce_prefix_for_epoch(self.initial_nonce_prefix, epoch_used)
        resp_nonce = resp_effective_prefix + resp_counter.to_bytes(8, "big")

        resp_session_key = self.derive_session_key(
            self.root_secret, self.license.payload.license_id, self.session_id, epoch_used, resp_effective_prefix.hex()
        )
        resp_aead = ChaCha20Poly1305(resp_session_key)

        resp_aad = f"renew:{Config.CIPHER_SUITE}:{self.session_id}:{self.license.payload.license_id}:{self.client_pub_hex}:{self.transcript_hash}:{epoch_used}".encode()
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
            expected_proof = hmac.new(self.session_key, b"server-finished:" + self.transcript_hash.encode(), hashlib.sha256).hexdigest()
            if resp_plain.server_proof != expected_proof:
                logger.error("Server proof mismatch")
                return False

        self.counter = resp_plain.next_counter
        old_epoch = self.rekey_epoch
        self.rekey_epoch = self.counter // 10
        if self.rekey_epoch > old_epoch:
            effective_prefix = self.get_nonce_prefix_for_epoch(self.initial_nonce_prefix, self.rekey_epoch)
            self.session_key = self.derive_session_key(
                self.root_secret, self.license.payload.license_id, self.session_id, self.rekey_epoch, effective_prefix.hex()
            )
            self.aead = ChaCha20Poly1305(self.session_key)

        logger.info(f"Renew OK, counter = {self.counter}")
        return True

    def run(self):
        """Run the client loop."""
        try:
            self.start_session()
            while True:
                time.sleep(self.renew_interval)
                if not self.renew_session():
                    if self.on_error_callback:
                        self.on_error_callback(Exception("Session renewal failed"))
                    break
        except Exception as e:
            self.logger.error(f"Client error: {e}")
            if self.on_error_callback:
                self.on_error_callback(e)
            raise

    def start_in_thread(self):
        """Start the client in a separate thread."""
        if self._thread and self._thread.is_alive():
            self.logger.warning("Client is already running in a thread")
            return
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        self.logger.info("Client started in background thread")

    def stop_thread(self):
        """Stop the background thread (not implemented, use daemon thread)."""
        # Since it's daemon, it will stop when main thread exits
        pass


def main():
    # Example: run in thread with callback
    client = LicenseClient(
        log_level=logging.INFO,
        on_error_callback=error_handler
    )
    client.start_in_thread()

    # Main thread can do other work
    while True:
        print(f"License active: {client.is_license_active()}")
        time.sleep(5)


if __name__ == "__main__":
    main()