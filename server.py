# server.py
import json, time, uuid, os, hashlib, hmac
from typing import cast, Dict, List, Any
from fastapi import FastAPI, HTTPException
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

SESSION_TTL = 30
MAX_COUNTER = 2**40  # Prevent nonce reuse: max 1e12 renewals per session
MAX_START_ATTEMPTS_PER_MINUTE = 10  # Rate limit /start to prevent replay DoS
MAX_CIPHERTEXT_LEN = 10 * 1024  # 10KB, prevent DoS
MAX_USED_EPH_PUBS_PER_LICENSE = 100  # Prevent memory exhaustion from flood attacks

# Required security features that clients must support
REQUIRED_FEATURES = {
    "secure_channel": True,  # ChaCha20Poly1305 AEAD
    "counter": True,         # Monotonic counter for nonces
    "pop": True,             # Proof of possession with Ed25519
    "transcript_binding": True,  # Channel binding to handshake transcript
    "rekey": True,           # Periodic key rotation
    "proofs": True,          # Client/server finished proofs
}

app = FastAPI()

# session_id → state
sessions: Dict[str, Dict[str, Any]] = {}  # license_id, expires_at, client_pub, expected_counter, session_key
# license_id → revoke_timestamp
revoked_licenses: Dict[str, int] = {}
# license_id → [start attempt timestamps]
start_attempts: Dict[str, List[int]] = {}
# license_id → client_eph_pub_bytes → timestamp (for anti-replay, TTL 60s)
used_client_eph_pubs: Dict[str, Dict[bytes, int]] = {}


def load_revoked_licenses() -> Dict[str, int]:
    try:
        with open("revoked_licenses.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_revoked_licenses():
    with open("revoked_licenses.json", "w") as f:
        json.dump(revoked_licenses, f)


revoked_licenses = load_revoked_licenses()


def clean_expired_sessions():
    now = int(time.time())
    expired = [sid for sid, sess in sessions.items() if sess["expires_at"] < now]
    for sid in expired:
        sessions.pop(sid, None)
    # Clean expired start attempts (TTL 60s)
    for lid in list(start_attempts.keys()):
        start_attempts[lid] = [t for t in start_attempts[lid] if now - t < 60]
        if not start_attempts[lid]:
            del start_attempts[lid]
    # Clean expired used client eph pubs (TTL 60s)
    for lid in list(used_client_eph_pubs.keys()):
        for pub in list(used_client_eph_pubs[lid].keys()):
            if now - used_client_eph_pubs[lid][pub] > 60:
                del used_client_eph_pubs[lid][pub]
        # Enforce upper bound to prevent memory exhaustion
        if len(used_client_eph_pubs[lid]) > MAX_USED_EPH_PUBS_PER_LICENSE:
            # Keep only the most recent entries
            sorted_items = sorted(used_client_eph_pubs[lid].items(), key=lambda x: x[1], reverse=True)
            used_client_eph_pubs[lid] = dict(sorted_items[:MAX_USED_EPH_PUBS_PER_LICENSE])
        if not used_client_eph_pubs[lid]:
            del used_client_eph_pubs[lid]

with open("server_public.key", "rb") as f:
    SERVER_PUB = cast(Ed25519PublicKey, serialization.load_pem_public_key(f.read()))
with open("server_private.key", "rb") as f:
    SERVER_PRIV = cast(Ed25519PrivateKey, serialization.load_pem_private_key(f.read(), None))
ADMIN_PASSWORD = "admin123"  # Change this to a secure password


def verify_license(lic: dict) -> bool:
    payload = lic["payload"]
    sig = bytes.fromhex(lic["signature"])
    data = json.dumps(payload, sort_keys=True).encode()
    try:
        SERVER_PUB.verify(sig, data)  # type: ignore
    except Exception:
        return False
    now = int(time.time())
    
    # Check if license is revoked
    license_id = payload["license_id"]
    if license_id in revoked_licenses:
        return False  # Revoked licenses are permanently invalid
    
    return payload["valid_from"] <= now <= payload["valid_until"]


def sign(obj: dict) -> str:
    data = json.dumps(obj, sort_keys=True).encode()
    return SERVER_PRIV.sign(data).hex()  # type: ignore


def verify_admin_request(req: dict) -> bool:
    payload = req.get("payload")
    if not payload:
        return False
    sig = bytes.fromhex(req.get("signature", ""))
    data = json.dumps(payload, sort_keys=True).encode()
    try:
        ADMIN_PUB.verify(sig, data)  # type: ignore
    except Exception:
        return False
    return True


def generate_license(license_id: str, product: str, valid_from: int, valid_until: int, policy: dict) -> dict:
    if not validate_policy(policy):
        raise ValueError("Invalid policy")
    payload = {
        "license_id": license_id,
        "product": product,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "policy": policy
    }
    signature = sign(payload)
    return {"payload": payload, "signature": signature}


def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
    epoch_bytes = epoch.to_bytes(4, 'big')
    return bytes(a ^ b for a, b in zip(initial_nonce_prefix, epoch_bytes))


def derive_session_key(root_secret: bytes, license_id: str, session_id: str, rekey_epoch: int = 0, effective_nonce_prefix_hex: str = "") -> bytes:
    salt = (license_id + session_id + effective_nonce_prefix_hex).encode()
    info = f"epoch:{rekey_epoch}".encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(root_secret)


@app.post("/start")
def start(req: dict):
    # Check protocol version
    if req.get("version") != 1:
        raise HTTPException(403, "protocol version mismatch")

    # Validate required security features
    supported_features = req.get("supported_features", {})
    for feature, required in REQUIRED_FEATURES.items():
        if supported_features.get(feature) != required:
            raise HTTPException(403, f"required feature not supported: {feature}")

    clean_expired_sessions()
    lic = req["license"]
    client_pub_hex = req["client_pubkey"]
    client_pub = bytes.fromhex(client_pub_hex)
    client_eph_pub = X25519PublicKey.from_public_bytes(
        bytes.fromhex(req["client_eph_pub"])
    )

    # Anti-replay: check if client ephemeral pub was used recently
    pub_bytes = client_eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    license_id = lic["payload"]["license_id"]
    if license_id not in used_client_eph_pubs:
        used_client_eph_pubs[license_id] = {}
    if pub_bytes in used_client_eph_pubs[license_id]:
        raise HTTPException(403, "handshake replay detected")
    used_client_eph_pubs[license_id][pub_bytes] = int(time.time())

    if not verify_license(lic):
        raise HTTPException(403, "invalid license")
    
    license_id = lic["payload"]["license_id"]
    now = int(time.time())
    
    # Rate limit start attempts to prevent replay DoS
    if license_id not in start_attempts:
        start_attempts[license_id] = []
    start_attempts[license_id] = [t for t in start_attempts[license_id] if now - t < 60]
    if len(start_attempts[license_id]) >= MAX_START_ATTEMPTS_PER_MINUTE:
        raise HTTPException(429, "too many start attempts")
    
    # Validate policy
    policy = lic["payload"].get("policy", {})
    if not validate_policy(policy):
        raise HTTPException(403, "invalid policy")
    
    # Enforce max_sessions
    license_id = lic["payload"]["license_id"]
    max_sessions = policy["max_sessions"]
    active_sessions = len([s for s in sessions.values() if s["license_id"] == license_id])
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
        salt=(lic["payload"]["license_id"] + session_id).encode(),
        info=b"root",
    ).derive(shared)

    effective_prefix = get_nonce_prefix_for_epoch(nonce_prefix, 0)
    session_key = derive_session_key(
        root_secret, lic["payload"]["license_id"], session_id, 0, effective_prefix.hex()
    )

    expires = int(time.time()) + SESSION_TTL
    # Calculate handshake transcript hash for channel binding
    # Invariant: canonical JSON encoding MUST be identical on client and server
    handshake_data = {
        "license_id": lic["payload"]["license_id"],
        "client_pubkey": req["client_pubkey"],
        "client_eph_pub": req["client_eph_pub"],
        "server_eph_pub": server_eph_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex(),
        "nonce_prefix": nonce_prefix.hex(),
    }
    transcript_hash = hashlib.sha256(json.dumps(handshake_data, sort_keys=True).encode()).hexdigest()

    sessions[session_id] = {
        "license_id": lic["payload"]["license_id"],
        "expires_at": expires,
        "client_pub": client_pub_hex,
        "expected_counter": 0,
        "session_key": session_key,
        "root_secret": root_secret,
        "initial_nonce_prefix": nonce_prefix,
        "transcript_hash": transcript_hash,
        "rekey_epoch": 0,
        "last_renew_at": 0,
    }

    resp = {
        "session_id": session_id,
        "expires_at": expires,
        "protocol_version": 1,
        "cipher_suite": "v1:ChaCha20Poly1305",
        "required_features": REQUIRED_FEATURES,
        "server_eph_pub": server_eph_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex(),
        "nonce_prefix": sessions[session_id]["initial_nonce_prefix"].hex(),
    }
    resp["signature"] = sign(resp)
    return resp


@app.post("/renew")
def renew(req: dict):
    session_id = req["session_id"]
    sess = sessions.get(session_id)
    now = int(time.time())

    if not sess or sess["expires_at"] < now:
        sessions.pop(session_id, None)
        raise HTTPException(403, "session expired")

    # Rate limit renew attempts to prevent DoS
    if now - sess["last_renew_at"] < 0.1:
        raise HTTPException(429, "too many renews")
    
    if sess["expected_counter"] >= MAX_COUNTER:
        sessions.pop(session_id, None)
        raise HTTPException(403, "session counter overflow")
    
    # Check if license is revoked (mandatory invariant: revoke ⇒ no renew)
    if sess["license_id"] in revoked_licenses:
        sessions.pop(session_id, None)
        raise HTTPException(403, "license revoked")

    ciphertext = bytes.fromhex(req["ciphertext"])
    if len(ciphertext) > MAX_CIPHERTEXT_LEN:
        raise HTTPException(403, "ciphertext too large")
    counter = int(req["counter"])
    nonce = get_nonce_prefix_for_epoch(sess["initial_nonce_prefix"], sess["rekey_epoch"]) + counter.to_bytes(8, "big")

    # Check counter before decrypt to prevent CPU-DoS
    if counter > sess["expected_counter"]:
        raise HTTPException(403, "counter too high")

    aead = ChaCha20Poly1305(sess["session_key"])
    # Invariant: AAD binds ciphertext to protocol version, cipher suite, session, license, client, and handshake transcript
    aad = f"renew:v1:ChaCha20Poly1305:{session_id}:{sess['license_id']}:{sess['client_pub']}:{sess['transcript_hash']}:{sess['rekey_epoch']}".encode()
    try:
        plaintext = aead.decrypt(nonce, ciphertext, aad)
    except Exception:
        raise HTTPException(403, "decrypt failed")

    data = json.loads(plaintext.decode())
    if data.get("session_id") != session_id:
        raise HTTPException(403, "session_id mismatch")
    if data.get("version") != 1:
        raise HTTPException(403, "protocol version mismatch")
    if data.get("cipher_suite") != "v1:ChaCha20Poly1305":
        raise HTTPException(403, "cipher suite mismatch")
    inner_counter = data["counter"]
    if inner_counter != counter:
        raise HTTPException(403, "counter mismatch")
    sig = bytes.fromhex(data["client_sig"])

    # Invariant: Allow idempotent retries with same counter
    if inner_counter == sess["expected_counter"]:
        # Normal renew
        is_retry = False
    elif inner_counter == sess["expected_counter"] - 1:
        # Retry of previous renew
        is_retry = True
    else:
        raise HTTPException(403, "counter mismatch")

    # Check for invalid replay in retry window
    if is_retry:
        if not hmac.compare_digest(
            hashlib.sha256(ciphertext).digest(),
            sess.get("last_cipher_hash", b"")
        ):
            raise HTTPException(403, "invalid retry")

    if inner_counter == 0:
        expected_proof = hmac.new(sess["session_key"], b"client-finished:" + sess["transcript_hash"].encode(), hashlib.sha256).hexdigest()
        if data.get("client_proof") != expected_proof:
            raise HTTPException(403, "client proof mismatch")

    # Proof-of-possession
    msg = f"renew:{session_id}:{inner_counter}".encode()
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(sess["client_pub"])).verify(sig, msg)

    if not is_retry:
        sess["last_cipher_hash"] = hashlib.sha256(ciphertext).digest()
        sess["expected_counter"] += 1
        old_epoch = sess["rekey_epoch"]
        sess["rekey_epoch"] = sess["expected_counter"] // 10
        if sess["rekey_epoch"] > old_epoch:
            effective_prefix = get_nonce_prefix_for_epoch(sess["initial_nonce_prefix"], sess["rekey_epoch"])
            sess["session_key"] = derive_session_key(
                sess["root_secret"], sess["license_id"], session_id, sess["rekey_epoch"], effective_prefix.hex()
            )
            aead = ChaCha20Poly1305(sess["session_key"])
        sess["expires_at"] = now + SESSION_TTL
        sess["last_renew_at"] = now

    resp_plain = {
        "expires_at": sess["expires_at"],
        "next_counter": sess["expected_counter"],
        "epoch_used": sess["rekey_epoch"],
        "version": 1,
        "cipher_suite": "v1:ChaCha20Poly1305",
    }
    if sess["expected_counter"] == 1:
        resp_plain["server_proof"] = hmac.new(sess["session_key"], b"server-finished:" + sess["transcript_hash"].encode(), hashlib.sha256).hexdigest()

    # Rekey every 10 renews, only on normal renew
    if not is_retry and sess["expected_counter"] % 10 == 0:
        resp_plain["rekey_ack"] = True



    effective_prefix = get_nonce_prefix_for_epoch(sess["initial_nonce_prefix"], sess["rekey_epoch"])
    resp_nonce = effective_prefix + sess["expected_counter"].to_bytes(8, "big")
    # Invariant: AAD binds ciphertext to protocol version, cipher suite, session, license, client, and handshake transcript
    aad = f"renew:v1:ChaCha20Poly1305:{session_id}:{sess['license_id']}:{sess['client_pub']}:{sess['transcript_hash']}:{sess['rekey_epoch']}".encode()
    resp_cipher = aead.encrypt(
        resp_nonce,
        json.dumps(resp_plain).encode(),
        aad,
    )

    return {
        "ciphertext": resp_cipher.hex(),
        "counter": sess["expected_counter"],
        "epoch_used": sess["rekey_epoch"],
    }


@app.post("/revoke")
def revoke(req: dict):
    payload = req["payload"]
    if payload.get("password") != ADMIN_PASSWORD:
        raise HTTPException(403, "Invalid admin password")
    
    license_id = payload["license_id"]
    now = int(time.time())

    # Record revocation timestamp
    revoked_licenses[license_id] = now
    save_revoked_licenses()

    # Force expire all sessions for this license
    expired_sessions = [
        sid for sid, sess in sessions.items()
        if sess["license_id"] == license_id
    ]
    for sid in expired_sessions:
        sessions.pop(sid, None)

    # Clean start attempts for revoked license
    start_attempts.pop(license_id, None)
    # Clean used client eph pubs for revoked license
    used_client_eph_pubs.pop(license_id, None)

    return {"revoked_at": now}


@app.post("/generate_license")
def generate_license_endpoint(req: dict):
    payload = req["payload"]
    if payload.get("password") != ADMIN_PASSWORD:
        raise HTTPException(403, "Invalid admin password")
    
    try:
        license_id = payload["license_id"]
        product = payload["product"]
        valid_from = payload["valid_from"]
        valid_until = payload["valid_until"]
        policy = payload["policy"]
        license_data = generate_license(license_id, product, valid_from, valid_until, policy)
        
        # Return as downloadable JSON file
        json_str = json.dumps(license_data, indent=2)
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=license_{license_id}.json"}
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except KeyError:
        raise HTTPException(400, "Missing required fields")


def validate_policy(policy: dict) -> bool:
    """Server-side validation for policy"""
    if not isinstance(policy, dict):
        return False
    
    # Define known policy fields and their types
    known_fields = {
        "max_sessions": int,
        "version": str,
        "features": list,
    }
    
    # Check for unknown fields (deny by default)
    for field, value in policy.items():
        if field not in known_fields:
            return False
        if not isinstance(value, known_fields[field]):
            return False
    
    # Check for required fields
    if "max_sessions" not in policy or "version" not in policy:
        return False
    
    # Enforce known policy version
    if policy["version"] != "1.0":
        return False
    
    # Validate field values
    if policy["max_sessions"] <= 0:
        return False

    return True


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    with open("admin.html", "r") as f:
        return f.read()
