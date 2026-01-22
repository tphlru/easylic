# EasyLic // TPHL Easy Licensing

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-TPHL-orange.svg)](LICENSE)

A secure, cryptographic license server built with FastAPI and modern cryptography libraries. EasyLic provides robust software licensing with session management, revocation, and comprehensive security features to protect against various attacks.

Welcome! EasyLic helps developers secure their software with online license validation. It prevents piracy through real-time checks and is easy to integrate. If you're new, start with the Quick Start below.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Troubleshooting](#troubleshooting)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Client Usage](#client-usage)
- [Deployment](#deployment)
- [Security Overview](#security-overview)
- [Architecture](#architecture)
- [License States](#license-states)
- [License Lifecycle](#license-lifecycle)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Online Licensing**: Real-time license validation with instant revocation capabilities, centralized management, and usage monitoring - advantages over offline licensing include preventing piracy spread and enabling dynamic license policies
- **Concurrent Session Control**: License policies enforce `max_sessions` limits, preventing single license keys from being used simultaneously across multiple devices or installations
- **Cryptographic Security**: Ed25519 signatures (secure digital signatures for authenticity), ChaCha20Poly1305 AEAD encryption (confidentiality and integrity)
- **Proof of Possession**: Client authentication using digital signatures (proves ownership without revealing secrets)
- **Session Management**: Automatic rekeying every 10 renewals for forward secrecy
- **License Revocation**: Immediate termination of all sessions for revoked licenses
- **Rate Limiting**: Protection against abuse and DoS attacks (10 start attempts/minute per license)
- **Admin Interface**: Web-based admin panel for license management
- **Docker Support**: Easy deployment with Docker containers
- **Client Library**: Python client with automatic session renewal
- **Threaded Operation**: Background session management for applications

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

## Quick Start

### Server Setup

1. **Set Environment Variables**:
```bash
export EASYLIC_ADMIN_PASSWORD=your_secure_password_here
export EASYLIC_SERVER_HOST=0.0.0.0
export EASYLIC_SERVER_PORT=8000
```

2. **Generate Keys**:
```bash
easylic keygen
```

3. **Start Server**:
```bash
easylic serve
```

 The server starts on http://localhost:8000 with admin panel at http://localhost:8000/admin.

**Note:** If commands fail (e.g., "Permission denied" for keygen), ensure directories are writable or run as admin.

### Client Usage Example

```python
from easylic.client.client import LicenseClient

# Create client (loads license from default location)
client = LicenseClient()

# Start secure session
session_id = client.start_session()
print(f"Session started: {session_id}")

# Check license status
if client.is_license_active():
    print("License is active")

# Manual renewal
success = client.renew_session()
print(f"Renewal: {'success' if success else 'failed'}")

# Or run in background thread with auto-renewal
client.start_in_thread()

# Your application logic here
while client.is_license_active():
    # Application runs while license is valid
    pass
```

### Generate License (Admin)

Use the interactive generator:

```bash
easylic generator
```

Or via API (requires admin password to be set via `EASYLIC_ADMIN_PASSWORD` environment variable):

```bash
curl -X POST http://localhost:8000/generate_license \
  -H "Content-Type: application/json" \
  -d '{
    "password": "your_admin_password",
    "license_id": "lic-001",
    "product": "MyApp",
    "valid_from": 1704067200,
    "valid_until": 1735689600,
    "policy": {
      "version": "1.0",
      "max_sessions": 1,
      "features": ["feature1", "feature2"]
    }
  }'
```

**Note:** The `/generate_license` endpoint is only available when `EASYLIC_ADMIN_PASSWORD` environment variable is set on the server. Make sure to send a POST request with JSON body - accessing via GET (e.g., in browser) will result in validation errors.

## CLI Usage

EasyLic includes command-line tools for key management and server operations:

- **`easylic keygen`**: Generate cryptographic keys for the server. Run this first to create `server.key` and `server.pub` in `EASYLIC_KEYS_DIR`.
- **`easylic serve`**: Start the license server with configured host/port. Requires keys from keygen.
- **`easylic generator`**: Interactive tool to create licenses. Prompts for details like license ID, validity, and features.

Run `easylic --help` for full options. All commands respect environment variables like `EASYLIC_KEYS_DIR`.

## Troubleshooting

Common issues and solutions:

- **"Key not found" or "Permission denied" on keygen**: Ensure `EASYLIC_KEYS_DIR` (default `./easylic/server`) exists and is writable. Create it with `mkdir -p ./easylic/server`.
- **Server won't start**: Check if port 8000 is free (`lsof -i :8000`). Set `EASYLIC_SERVER_PORT` to a different value if needed.
- **Client connection fails**: Verify `server_url` in client config points to running server (e.g., `http://localhost:8000`).
- **License invalid**: Check license file format and dates. Use admin panel to generate test licenses.
- **Rate limited**: Wait a minute; the server limits start attempts to 10/minute per license.

## Configuration

EasyLic uses environment variables for configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `EASYLIC_SERVER_HOST` | `127.0.0.1` | Server bind address |
| `EASYLIC_SERVER_PORT` | `8000` | Server port |
| `EASYLIC_ADMIN_PASSWORD` | `admin` | Password for admin operations |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `EASYLIC_KEYS_DIR` | `./easylic/server` | Directory for server keys |

### Client Configuration

The client can be configured via `ClientConfig` object or environment variables:

```python
from easylic.client.client import LicenseClient
from easylic.common.models import ClientConfig

config = ClientConfig(
    server_url="http://localhost:8000",
    license_file="/path/to/license.json",
    renew_interval=30,  # seconds
    log_level=20,  # logging.INFO
)

client = LicenseClient(config)
```

## API Reference

### Endpoints

#### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1703123456
}
```

#### `POST /start`
Initiate a secure session.

**Request:**
```json
{
  "version": 1,
  "license": {
    "payload": {
      "license_id": "lic-001",
      "product": "MyApp",
      "valid_from": 1704067200,
      "valid_until": 1735689600,
      "policy": {
        "version": "1.0",
        "max_sessions": 1
      }
    },
    "signature": "hex-encoded-signature"
  },
  "client_pubkey": "hex-string",
  "client_eph_pub": "hex-string",
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

**Response:**
```json
{
  "session_id": "uuid",
  "expires_at": 1703123456,
  "protocol_version": 1,
  "cipher_suite": "v1:ChaCha20Poly1305",
  "required_features": {...},
  "server_eph_pub": "hex-string",
  "nonce_prefix": "hex-string",
  "signature": "hex-string",
  "transcript_hash": "hex-string",
  "handshake_ciphertext": "hex-string",
  "handshake_nonce": "hex-string"
}
```

#### `POST /renew`
Renew an existing session.

**Request:**
```json
{
  "session_id": "uuid",
  "ciphertext": "encrypted-renew-data",
  "counter": 1
}
```

**Response:**
```json
{
  "ciphertext": "encrypted-response",
  "counter": 2,
  "epoch_used": 0
}
```

#### `POST /revoke`
Revoke a license (admin only).

**Request:**
```json
{
  "payload": {
    "license_id": "lic-001"
  },
  "signature": "admin-signature"
}
```

#### `POST /generate_license`
Generate a new license (admin only).

## Deployment

### Docker Deployment

#### Build Image
```bash
docker build -t easylic .
```

#### Run Container
```bash
# Persistent keys
docker run -v $(pwd)/easylic/server:/home/app/easylic/server \
           -e EASYLIC_ADMIN_PASSWORD=secure_password \
           -p 8000:8000 easylic

# One-time (keys lost on stop)
docker run -p 8000:8000 easylic
```

### Production Considerations

- Use strong `EASYLIC_ADMIN_PASSWORD`
- Store keys securely (volume mount or secret management)
- Configure reverse proxy (nginx) for SSL termination
- Set appropriate rate limits based on your needs
- Monitor server logs and health endpoints
- Backup license database regularly

## Security Overview

EasyLic implements multiple layers of security to prevent licensing bypass and enforce license policies:

- **Online Validation**: Unlike offline licensing, EasyLic requires real-time server communication, enabling instant revocation and preventing license sharing across multiple concurrent sessions
- **Session Concurrency Limits**: The `max_sessions` policy prevents a single license from being used simultaneously on multiple devices, blocking common piracy techniques
- **Mandatory Security Features**: All clients must support secure_channel, counter, pop, transcript_binding, rekey, and proofs
- **AEAD Encryption**: ChaCha20Poly1305 for confidentiality and integrity
- **Monotonic Counters**: Prevent replay attacks and ensure message ordering
- **Transcript Binding**: Channel binding to handshake transcript hash
- **Periodic Rekeying**: Automatic key rotation every 10 renewals
- **Proof-of-Possession**: Ed25519 signatures for client authentication
- **Rate Limiting**: Prevents DoS and replay attacks on session establishment
- **Session Limits**: Hard limits on counter values to prevent nonce reuse

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client App    │────│   License Server │────│   Admin Panel   │
│                 │    │   (FastAPI)      │    │   (Web UI)      │
│ - LicenseClient │    │                  │    │                 │
│ - Session Mgmt  │    │ - Session Store  │    │ - Generate Lic  │
│ - Auto-renewal  │    │ - Key Management │    │ - Revoke Lic    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────────────┐
                    │  Cryptographic     │
                    │  Core (Ed25519,    │
                    │  ChaCha20Poly1305) │
                    └────────────────────┘
```

## License States

Licenses follow a strict state machine:

```
INIT → ACTIVE → REKEY → ACTIVE → EXPIRED → REVOKED
```

- **INIT**: Newly issued license, not yet activated
- **ACTIVE**: Valid license with active sessions
- **REKEY**: Temporary state during key rotation (every 10 renewals)
- **EXPIRED**: License validity period has ended
- **REVOKED**: License has been administratively revoked

## License Lifecycle

### Session Establishment (`/start`)
1. Client sends license data, public keys, and supported features
2. Server validates license signature and policy
3. Server checks rate limits (10 attempts/minute per license)
4. Server generates session keys and nonce prefix
5. Server responds with encrypted session parameters

### Session Renewal (`/renew`)
1. Client encrypts renewal request with session key
2. Server decrypts and validates request
3. Server checks counter monotonicity and replay protection
4. Server extends session TTL and increments counter
5. Every 10 renewals: automatic rekeying occurs
6. Server responds with encrypted renewal confirmation

### License Revocation (`/revoke`)
1. Admin sends revocation request with signature
2. Server validates admin credentials
3. Server marks license as revoked with timestamp
4. All active sessions for the license are immediately terminated
5. Future session starts and renewals are rejected

## Development

### Testing

Run the test suite:

```bash
pytest
```

### Linting

Check code quality:

```bash
ruff check .
```

### Development Server

For development with auto-reload:

```bash
uvicorn easylic.server.core:app --reload
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation for API changes
- Ensure all tests pass before submitting PR

## License

TPHL Easy Licensing - All rights reserved.

This software is proprietary and may only be used in accordance with the terms of the license agreement.