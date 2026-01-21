# EasyLic: THPL Easy Licensing

EasyLic is a secure, cryptographic license server built with FastAPI and cryptography libraries. It provides a robust licensing solution with features like session management, revocation, and protection against various attacks.

## Features

- **Secure Sessions**: Uses ChaCha20Poly1305 AEAD encryption
- **Proof of Possession**: Ed25519 digital signatures for client authentication
- **Session Management**: Automatic rekeying every 10 renewals
- **License Revocation**: Immediate termination of all sessions for revoked licenses
- **Rate Limiting**: Protection against abuse and DoS attacks
- **Admin Interface**: Web-based admin panel for managing licenses
- **Docker Support**: Easy deployment with Docker

## Installation

### Prerequisites

- Python 3.8+
- pip

### Install from Source

```bash
git clone <repository-url>
cd easylic
pip install -e .
```

### Generate Server Keys

Before running the server, generate Ed25519 key pair:

```bash
easylic keygen
```

This creates `easylic/server/server_public.key` and `easylic/server/server_private.key`.

## Configuration

EasyLic uses environment variables for configuration. Set them before running:

- `SERVER_HOST`: Server host (default: 127.0.0.1)
- `SERVER_PORT`: Server port (default: 8000)
- `ADMIN_PASSWORD`: Password for admin operations (default: admin)
- `LOG_LEVEL`: Logging level (default: INFO)

Example:

```bash
export SERVER_HOST=0.0.0.0
export SERVER_PORT=8000
export ADMIN_PASSWORD=mysupersecretpassword
```

## Running the Server

### Local Development

Start the server:

```bash
easylic server
```

The server will start on the configured host and port (default: http://127.0.0.1:8000).

### Docker

#### Build the Image

```bash
docker build -t easylic .
```

#### Run the Container

To persist keys between container restarts, use a volume:

```bash
docker run -v $(pwd)/easylic/server:/home/app/easylic/server -p 8000:8000 easylic
```

- The first run will generate keys inside the container (and save them to the host via volume).
- Subsequent runs will reuse existing keys.
- Access the server at http://localhost:8000.

For one-time runs (keys are lost on container stop):

```bash
docker run -p 8000:8000 easylic
```

## Usage

### Admin Interface

Visit http://localhost:8000/admin to access the admin panel. Use the admin password to revoke licenses or generate new ones.

### API Endpoints

- `GET /health` - Health check
- `POST /start` - Start a new session
- `POST /renew` - Renew an existing session
- `POST /revoke` - Revoke a license (requires admin password)
- `POST /generate_license` - Generate a new license (requires admin password)
- `GET /admin` - Admin interface

### Client Usage

See `examples/client/` for usage examples:

- `basic_usage.py` - Simple client usage
- `threaded_usage.py` - Multi-threaded client
- `status_check.py` - Check license status

## API Documentation

## Revoke Propagation Semantics

### Behavior

- When a license is revoked via `/revoke`, all active sessions for that license are immediately terminated
- Revoked licenses are permanently invalid and cannot be used for new sessions
- The revocation timestamp is recorded and checked during license verification
- Subsequent renew attempts will fail with "license revoked" error
- This is **documented behavior**, not a bug

### API

```http
POST /revoke
Content-Type: application/json

{
  "payload": {
    "license_id": "1"
  },
  "signature": "hex-encoded Ed25519 signature of the payload"
}
```

Response:
```json
{
  "revoked_at": 1703123456
}
```

### /start Endpoint

Initiates a secure session with feature negotiation and validation.

```http
POST /start
Content-Type: application/json

{
  "version": 1,
  "license": {...},
  "client_pubkey": "hex_string",
  "client_eph_pub": "hex_string",
  "supported_features": {
    "secure_channel": true,
    "counter": true,
    "pop": true,
    "transcript_binding": true,
    "rekey": true,
    "proofs": true
  }
}
```

Response (signed):
```json
{
  "session_id": "uuid",
  "expires_at": 1703123456,
  "protocol_version": 1,
  "cipher_suite": "v1:ChaCha20Poly1305",
  "required_features": {
    "secure_channel": true,
    "counter": true,
    "pop": true,
    "transcript_binding": true,
    "rekey": true,
    "proofs": true
  },
  "server_eph_pub": "hex_string",
  "nonce_prefix": "hex_string",
  "signature": "hex_string"
}
```

## Required Security Features

To prevent protocol downgrade attacks, the server enforces that clients support all mandatory security features. A patched client cannot silently disable security checks.

### Required Features

The following features are mandatory and must be declared as supported in the `/start` request:

| Feature | Description |
|---------|-------------|
| `secure_channel` | ChaCha20Poly1305 AEAD encryption for confidentiality and integrity |
| `counter` | Monotonic counter for nonce uniqueness and replay prevention |
| `pop` | Proof of possession using Ed25519 digital signatures |
| `transcript_binding` | Channel binding to the handshake transcript hash |
| `rekey` | Periodic key rotation every 10 renewals |
| `proofs` | Client and server finished message proofs |

### Validation

The `/start` request must include a `supported_features` object where all required features are set to `true`:

```json
{
  "version": 1,
  "license": {...},
  "client_pubkey": "...",
  "client_eph_pub": "...",
  "supported_features": {
    "secure_channel": true,
    "counter": true,
    "pop": true,
    "transcript_binding": true,
    "rekey": true,
    "proofs": true
  }
}
```

If any required feature is missing or set to `false`, the server rejects the request with HTTP 403.

## Retry Semantics

To handle network interruptions and temporary failures, the protocol supports idempotent retries for renew requests.

### Retry Rules

- **Normal renew**: Request counter must equal the server's expected counter
- **Retry allowed**: Request counter may equal expected_counter - 1 to allow retry of the previous renew
- **Invalid counter**: Any other counter value results in rejection

### Behavior

- Retries must use the exact same ciphertext (including nonce) as the original request
- Server validates the ciphertext hash matches the previous request
- Successful retry returns the same response as the original renew
- Failed retry (invalid hash) is rejected

This ensures clients can safely retry failed renew requests without causing protocol errors.

## Policy Lifecycle

### Policy Versioning

All policies must include a `version` field:

```json
{
  "policy": {
    "version": "1.0",
    "max_sessions": 1
  }
}
```

### Server-Side Validation

The server enforces strict policy validation:

1. **Unknown policy fields → deny**: Any field not in the allowlist causes rejection
2. **Missing required fields → deny**: Required fields must be present
3. **Invalid field types → deny**: Fields must match expected types

### Allowlisted Policy Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Policy version (e.g., "1.0") |
| `max_sessions` | integer | Yes | Maximum concurrent sessions |
| `features` | array | No | List of allowed features |

### Validation Rules

- `max_sessions` must be > 0
- `version` must be "1.0" (current policy format)
- `features` must be an array of strings

This ensures policies remain "hard" rather than "soft" - invalid policies are rejected rather than ignored.

## Session Counter Limits

To prevent AEAD nonce reuse, sessions have a maximum counter limit:

- `MAX_COUNTER = 2^40` (approximately 1 trillion renewals)
- When reached, the session is forcibly terminated with "session counter overflow"
- **This is a hard session kill; the client must perform a new `/start` to establish a session. This is intentional behavior to prevent cryptographic vulnerabilities, not a bug.**
- For typical usage (renew every 10 seconds), this allows ~348,000 years of continuous operation

## Rate Limiting

To prevent replay attacks and DoS on session establishment:

- `/start` requests are rate-limited to `MAX_START_ATTEMPTS_PER_MINUTE = 10` per license per minute
- Exceeding this limit returns HTTP 429 "too many start attempts"
- This mitigates MITM replay attacks that could exhaust `max_sessions`

## Nonce Prefix Immutability

The `nonce_prefix` is generated randomly during `/start` and remains immutable for the entire session lifetime. It is never modified, even during rekey operations, to ensure AEAD nonce uniqueness and prevent accidental nonce reuse that could compromise security.

## Development

### Testing

Run tests:

```bash
pytest
```

### Linting

Check code quality:

```bash
ruff check .
```

## License

THPL Easy Licensing - All rights reserved.