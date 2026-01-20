# license_generator.py
import json, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def load_keys():
    with open("server_public.key", "rb") as f:
        SERVER_PUB = serialization.load_pem_public_key(f.read())
    with open("server_private.key", "rb") as f:
        SERVER_PRIV = serialization.load_pem_private_key(f.read(), None)
    return SERVER_PRIV


def sign(obj: dict, priv_key) -> str:
    data = json.dumps(obj, sort_keys=True).encode()
    return priv_key.sign(data).hex()


def validate_policy(policy: dict) -> bool:
    if not isinstance(policy, dict):
        return False

    known_fields = {
        "max_sessions": int,
        "version": str,
        "features": list,
    }

    for field, value in policy.items():
        if field not in known_fields:
            return False
        if not isinstance(value, known_fields[field]):
            return False

    if "max_sessions" not in policy or "version" not in policy:
        return False

    if policy["version"] != "1.0":
        return False

    if policy["max_sessions"] <= 0:
        return False

    return True


def generate_license(license_id: str, product: str, valid_from: int, valid_until: int, policy: dict, priv_key):
    if not validate_policy(policy):
        raise ValueError("Invalid policy")
    payload = {
        "license_id": license_id,
        "product": product,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "policy": policy
    }
    signature = sign(payload, priv_key)
    return {"payload": payload, "signature": signature}


def main():
    priv_key = load_keys()

    print("Interactive License Generator")
    license_id = input("License ID: ").strip()
    product = input("Product: ").strip()

    valid_from_str = input("Valid from (Unix timestamp or 'now'): ").strip()
    if valid_from_str.lower() == 'now':
        valid_from = int(time.time())
    else:
        valid_from = int(valid_from_str)

    valid_until_str = input("Valid until (Unix timestamp or 'never'): ").strip()
    if valid_until_str.lower() == 'never':
        valid_until = 2147483647  # Far future
    else:
        valid_until = int(valid_until_str)

    max_sessions = int(input("Max sessions: ").strip())
    features_str = input("Features (comma-separated, optional): ").strip()
    features = [f.strip() for f in features_str.split(',')] if features_str else []

    policy = {
        "max_sessions": max_sessions,
        "version": "1.0",
        "features": features
    }

    try:
        license_data = generate_license(license_id, product, valid_from, valid_until, policy, priv_key)
        print("\nGenerated License:")
        print(json.dumps(license_data, indent=2))
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()