# EasyLic // Online Software Licensing by TPHL

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-TPHL-orange.svg)](LICENSE)

[Русская версия](readme_ru.md)

EasyLic solves the problem of software piracy by requiring real-time license checks, unlike offline systems that can be easily cracked or shared. It provides a secure, cryptographic license server built with FastAPI, offering session management, revocation, and comprehensive security features. If you're new, start with the Quick Start below.

**Important Security Notes:** Of course, the code should be compiled into a binary/obfuscated, and license checks should be placed not in one place, but throughout the code. We also recommend adding self-checks for code integrity via file hash to prevent tampering.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Troubleshooting](#troubleshooting)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Concepts and Security Overview](#concepts-and-security-overview)
- [Architecture](#architecture)
- [FAQ](#faq)
- [Development](#development)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

## Features

EasyLic provides everything you need for secure software licensing:

- **Real-Time Validation**: Licenses require online checks, allowing instant revocation and preventing piracy.
- **Multi-Device Control**: Set limits on concurrent usage to prevent license sharing.
- **Admin Dashboard**: Web interface for creating, managing, and revoking licenses.
- **Easy Integration**: Python client library with auto-renewal for seamless app integration.
- **Decorator-Based Protection**: Simple decorators to protect functions and methods (`@requires_active_license`, `@license_protected`, `@license_retry_on_fail`).
- **Docker Ready**: Simple containerized deployment.
- **Cryptographic Protection**: Advanced security with digital signatures and encryption (see [Concepts and Security Overview](#concepts-and-security-overview) for details).

## Quick Start

### Prerequisites

Before starting, ensure you have Python 3.8+ installed. 
### Server Setup

1. **Install EasyLic**:
   ```bash
   pip install easylic
   ```

2. **Set Environment Variables**:
   ```bash
   export EASYLIC_ADMIN_PASSWORD=your_secure_password_here  # Choose a strong password for admin access
   export EASYLIC_SERVER_HOST=0.0.0.0  # Bind to all interfaces (or 127.0.0.1 for local only)
   export EASYLIC_SERVER_PORT=8000  # Default port
   ```

3. **Generate Keys** (required):
   ```bash
   easylic keygen
   ```
   This creates cryptographic keys in `./easylic/server`. If you see "Permission denied", ensure the directory exists and is writable: `mkdir -p ./easylic/server`. Or set an alternative directory via `--keys-dir`.

4. **Start Server**:
   ```bash
   easylic serve
   ```
   The server starts at http://localhost:8000. Visit http://localhost:8000/admin for the admin panel (login with your admin password).

### Client Example

Integrate licensing into your Python app:

```python
from easylic.client.client import LicenseClient

# Load license and connect to server
client = LicenseClient()

# Start a secure session
session_id = client.start_session()
print(f"Session started: {session_id}")

# Check if license is active
if client.is_license_active():
    print("License is valid - your app can run")
else:
    print("License invalid - exit app")

# Run with auto-renewal in background
client.start_in_thread()

# Your app logic here
while client.is_license_active():
    # App runs while license is active
    pass
```

### Using Decorators (Simplest Way)

The easiest way to protect your functions is using decorators:

```python
from easylic import LicenseClient, requires_active_license

client = LicenseClient()

# Protect a function - raises ValidationError if license is inactive
@requires_active_license(client, "Premium feature requires active license")
def premium_feature():
    return "Premium feature executed!"

# Graceful handling - returns None if license is inactive
@requires_active_license(client, "Optional feature unavailable", raise_exception=False)
def optional_feature():
    return "Optional feature executed!"

# Class method protection
class MyService:
    def __init__(self):
        self.client = LicenseClient()
    
    @requires_active_license("client", "Service requires license")
    def protected_method(self):
        return "Protected method executed"

# Retry logic for critical operations
from easylic import license_retry_on_fail

@license_retry_on_fail(client, max_retries=3)
def critical_operation():
    return "Critical operation completed"
```

See [docs/decorators.md](docs/decorators.md) for full documentation.

### Generate a License (Admin)

Use the web admin panel at http://localhost:8000/admin to create licenses interactively.

Or via CLI:
```bash
easylic generator
```

Or via API: See [API Reference](#api-reference) for the POST /generate_license endpoint.

**Note:** The generated license is a JSON file that should be distributed to clients apps.

## Installation

### Prerequisites

- Python 3.8+

### Install from PyPI

EasyLic is published on PyPI and can be installed directly:

```bash
pip install easylic
```

### Install from Source

```bash
git clone https://github.com/tphlru/easylic
cd easylic
pip install -e .
```



## CLI Usage

EasyLic includes command-line tools for key management and server operations:

- **`easylic keygen`**: Generate cryptographic keys for the server. Run this first to create `server.key` and `server.pub` in `EASYLIC_KEYS_DIR`.
- **`easylic serve`**: Start the license server with configured host/port. Requires keys from keygen.
- **`easylic generator`**: Interactive tool to create licenses. Prompts for details like license ID, validity, and features.

Run `easylic --help` for full options. All commands respect environment variables like `EASYLIC_KEYS_DIR`.

## Troubleshooting

Common issues and solutions:

- **"Key not found" or "Permission denied" on keygen**: Ensure `EASYLIC_KEYS_DIR` (default `./easylic/server`) exists and is writable.
- **Server won't start**: Check if port is free (`lsof -i :8000`). Set `EASYLIC_SERVER_PORT` to a different value if needed.
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

**Request:**
```json
{
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
}
```

**Response:**
```json
{
  "license_id": "lic-001",
  "product": "MyApp",
  "valid_from": 1704067200,
  "valid_until": 1735689600,
  "policy": {
    "version": "1.0",
    "max_sessions": 1,
    "features": ["feature1", "feature2"]
  },
  "signature": "hex-encoded-signature"
}
```

**Example cURL:**
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
- Store keys securely (volume mount or secret management) and create a backup
- Configure reverse proxy (nginx) for SSL termination

## Concepts and Security Overview

### Key Concepts

To get started, here are some core terms explained simply:

- **Online Licensing**: Requires internet connection for real-time validation, preventing piracy by allowing instant revocation and usage monitoring (unlike offline licenses that can be copied).
- **Session**: A temporary, secure connection between your app and the license server for validation. Sessions auto-renew and expire if the license is invalid.
- **Cryptographic Security**: Uses Ed25519 digital signatures (for proving authenticity) and ChaCha20Poly1305 encryption (for secure data transmission) to protect against tampering and eavesdropping.
- **Proof of Possession**: Clients prove they own the license without revealing secrets, using digital signatures.
- **Revocation**: Admins can instantly disable licenses, terminating all active sessions.
- **Concurrent Sessions**: Limits how many devices can use the same license simultaneously, preventing sharing.

### Security Overview

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

EasyLic consists of three main components:

- **Client App**: Integrates the `LicenseClient` library for session management and auto-renewal. Communicates securely with the server.
- **License Server** (FastAPI): Handles validation, session storage, key management, and cryptographic operations. Core security logic resides here.
- **Admin Panel** (Web UI): Allows admins to generate licenses, revoke them, and monitor usage.

All components rely on shared cryptographic primitives (Ed25519 signatures and ChaCha20Poly1305 encryption) for secure communication.

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

## FAQ

**Q: Why use online licensing instead of offline?**  
A: Offline licenses can be easily copied and shared. Online licensing requires real-time server validation, enabling instant revocation, usage monitoring, and preventing piracy spread.

**Q: How does it prevent concurrent usage?**  
A: Each license has a `max_sessions` limit. If a license is used on more devices than allowed, new sessions are rejected.

**Q: What if the server is down?**  
A: Clients cache license validity briefly (less than 1 minute usually), but long outages require server availability. Plan for high availability in production.

**Q: Can I use it with non-Python apps?**  
A: The client is Python-only, but you can integrate via API calls to the server endpoints.

**Q: Common errors: "Connection failed"**  
A: Ensure server is running and `server_url` in client config points to the correct address (default: http://localhost:8000).

**Q: "License invalid"**  
A: Check license file format, dates, and ensure it's not revoked via admin panel. Also the keys files on the server must be the same as those used when creating the license. If you reissue them, the server will not be able to validate previously issued licenses, so keep your backups safe!

**Q: Permission denied on keygen**  
A: Try setting `EASYLIC_KEYS_DIR` to a writable path.


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
mypy .

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

## Changelog

- **v0.0.0**: Initial release with core licensing features. See git log for detailed changes.
- **v0.1.0**: Published on pip!

## License

TPHL - All rights reserved.

This software may only be used in accordance with the terms of the license agreement.
