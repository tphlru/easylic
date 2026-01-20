# client.py
import json, time, hashlib, hmac, requests
from typing import cast
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

SERVER = "http://127.0.0.1:8000"

def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
    epoch_bytes = epoch.to_bytes(4, 'big')
    return bytes(a ^ b for a, b in zip(initial_nonce_prefix, epoch_bytes))

with open("server_public.key", "rb") as key_f:
    SERVER_PUB = cast(Ed25519PublicKey, serialization.load_pem_public_key(key_f.read()))

with open("license.json") as lic_f:
    LICENSE = json.load(lic_f)


def derive_session_key(root_secret: bytes, license_id: str, session_id: str, rekey_epoch: int = 0, nonce_prefix_hex: str = "") -> bytes:
    salt = (license_id + session_id + nonce_prefix_hex).encode()
    info = f"epoch:{rekey_epoch}".encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(root_secret)


# PoP key
client_priv = Ed25519PrivateKey.generate()
client_pub = client_priv.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
).hex()

# ephemeral transport key
client_eph_priv = X25519PrivateKey.generate()
client_eph_pub = client_eph_priv.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
).hex()

# start
r = requests.post(f"{SERVER}/start", json={
    "version": 1,
    "license": LICENSE,
    "client_pubkey": client_pub,
    "client_eph_pub": client_eph_pub,
    "supported_features": {
        "secure_channel": True,
        "counter": True,
        "pop": True,
        "transcript_binding": True,
        "rekey": True,
        "proofs": True,
    },
})
r.raise_for_status()
resp = r.json()

# Verify protocol version
if resp.get("protocol_version") != 1:
    print("Protocol version mismatch")
    exit(1)

# Verify cipher suite
if resp.get("cipher_suite") != "v1:ChaCha20Poly1305":
    print("Cipher suite mismatch")
    exit(1)

# Verify required features
expected_features = {
    "secure_channel": True,
    "counter": True,
    "pop": True,
    "transcript_binding": True,
    "rekey": True,
    "proofs": True,
}
if resp.get("required_features") != expected_features:
    print("Required features mismatch")
    exit(1)

signature = bytes.fromhex(resp.pop("signature"))
SERVER_PUB.verify(  # type: ignore
    signature,
    json.dumps(resp, sort_keys=True).encode()
)

server_eph_pub = bytes.fromhex(resp["server_eph_pub"])
session_id = resp["session_id"]
initial_nonce_prefix = bytes.fromhex(resp["nonce_prefix"])

shared = client_eph_priv.exchange(
    X25519PublicKey.from_public_bytes(server_eph_pub)
)

# Derive root secret from shared
root_secret = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=(LICENSE["payload"]["license_id"] + session_id).encode(),
    info=b"root",
).derive(shared)

# Calculate handshake transcript hash for channel binding
handshake_data = {
    "license_id": LICENSE["payload"]["license_id"],
    "client_pubkey": client_pub,
    "client_eph_pub": client_eph_pub,
    "server_eph_pub": resp["server_eph_pub"],
    "nonce_prefix": resp["nonce_prefix"],
}
transcript_hash = hashlib.sha256(json.dumps(handshake_data, sort_keys=True).encode()).hexdigest()

effective_prefix = get_nonce_prefix_for_epoch(initial_nonce_prefix, 0)
session_key = derive_session_key(
    root_secret, LICENSE["payload"]["license_id"], session_id, 0, effective_prefix.hex()
)
aead = ChaCha20Poly1305(session_key)

counter = 0
rekey_epoch = 0
print("Secure session:", session_id)

while True:
    time.sleep(10)

    msg = f"renew:{session_id}:{counter}".encode()
    client_sig = client_priv.sign(msg).hex()

    renew_data = {
        "session_id": session_id,
        "counter": counter,
        "client_sig": client_sig,
        "version": 1,
        "cipher_suite": "v1:ChaCha20Poly1305",
    }
    if counter == 0:
        renew_data["client_proof"] = hmac.new(session_key, b"client-finished:" + transcript_hash.encode(), hashlib.sha256).hexdigest()
    plaintext = json.dumps(renew_data).encode()

    effective_prefix = get_nonce_prefix_for_epoch(initial_nonce_prefix, rekey_epoch)
    nonce = effective_prefix + counter.to_bytes(8, "big")
    # Invariant: AAD binds ciphertext to protocol version, cipher suite, session, license, client, and handshake transcript
    aad = f"renew:v1:ChaCha20Poly1305:{session_id}:{LICENSE['payload']['license_id']}:{client_pub}:{transcript_hash}:{rekey_epoch}".encode()
    cipher = aead.encrypt(nonce, plaintext, aad)

    retry_count = 0
    max_retries = 3
    backoff = 1
    success = False
    while retry_count < max_retries:
        r = requests.post(f"{SERVER}/renew", json={
            "session_id": session_id,
            "ciphertext": cipher.hex(),
            "counter": counter,
        })
        if r.status_code == 200:
            success = True
            break
        retry_count += 1
        if retry_count < max_retries:
            time.sleep(backoff)
            backoff *= 2

    if not success:
        print("Session lost after retries")
        break



    data = r.json()
    resp_counter = data["counter"]
    epoch_used = data["epoch_used"]

    resp_effective_prefix = get_nonce_prefix_for_epoch(initial_nonce_prefix, epoch_used)
    resp_nonce = resp_effective_prefix + resp_counter.to_bytes(8, "big")

    # Derive session key for the epoch used in the response
    resp_session_key = derive_session_key(
        root_secret, LICENSE["payload"]["license_id"], session_id, epoch_used, resp_effective_prefix.hex()
    )
    resp_aead = ChaCha20Poly1305(resp_session_key)

    # Use same AAD for response decryption
    resp_aad = f"renew:v1:ChaCha20Poly1305:{session_id}:{LICENSE['payload']['license_id']}:{client_pub}:{transcript_hash}:{epoch_used}".encode()
    resp_plain = json.loads(
        resp_aead.decrypt(
            resp_nonce,
            bytes.fromhex(data["ciphertext"]),
            resp_aad,
        ).decode()
    )

    if resp_plain.get("version") != 1:
        print("Protocol version mismatch")
        break
    if resp_plain.get("cipher_suite") != "v1:ChaCha20Poly1305":
        print("Cipher suite mismatch")
        break

    if resp_plain.get("next_counter") == 1:
        expected_proof = hmac.new(session_key, b"server-finished:" + transcript_hash.encode(), hashlib.sha256).hexdigest()
        if resp_plain.get("server_proof") != expected_proof:
            print("Server proof mismatch")
            break



    counter = resp_plain["next_counter"]
    old_epoch = rekey_epoch
    rekey_epoch = counter // 10
    if rekey_epoch > old_epoch:
        effective_prefix = get_nonce_prefix_for_epoch(initial_nonce_prefix, rekey_epoch)
        session_key = derive_session_key(
            root_secret, LICENSE["payload"]["license_id"], session_id, rekey_epoch, effective_prefix.hex()
        )
        aead = ChaCha20Poly1305(session_key)
    print("Renew OK, counter =", counter)
