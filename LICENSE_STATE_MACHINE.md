# License State Machine Documentation

## Overview

This document defines the formal state machine for the license lifecycle in the license server system. The state machine ensures that the system remains correct, maintainable, and resistant to regressions by new developers or forgotten invariants.

## States

The license follows the following state transitions:

```
INIT → ACTIVE → REKEY → ACTIVE → EXPIRED → REVOKED
```

- **INIT**: Initial state when a license is first issued but not yet used.
- **ACTIVE**: License is valid and sessions can be started and renewed.
- **REKEY**: Periodic key rotation for security (happens every 10 renewals).
- **EXPIRED**: License has passed its `valid_until` timestamp.
- **REVOKED**: License has been explicitly revoked via the `/revoke` endpoint.

## Invariants

The following invariants must be maintained at all times:

- **counter monotonic**: The session counter must increase monotonically with each renewal. No counter regression is allowed.
- **nonce uniqueness**: All nonces used in AEAD encryption must be unique to prevent cryptographic attacks.
- **revoke ⇒ no renew**: Once a license is revoked, no further renewals are permitted for any associated sessions.
- **downgrade forbidden**: License privileges (e.g., max_sessions, features) cannot be downgraded after issuance.

## Implementation Notes

- State transitions are enforced through server-side validation in `verify_license()` and session management.
- REKEY occurs automatically every 10 renewals to maintain forward secrecy.
- Revocation immediately terminates all active sessions and prevents future session establishment.
- EXPIRED licenses cannot start new sessions but existing sessions continue until TTL expires.