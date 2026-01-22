"""
Application layer: Session management use cases.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from easylic.client.domain.entities import ClientKeys, License, SessionState

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from easylic.client.infrastructure.session_handler import SessionHandlerInfra


class SessionManager:
    """Application service for managing license sessions."""

    def __init__(
        self,
        session_handler: SessionHandlerInfra,
        license_entity: License,
        client_keys: ClientKeys,
        server_pub: Ed25519PublicKey,
    ):
        self.session_handler = session_handler
        self.license = license_entity
        self.client_keys = client_keys
        self.server_pub = server_pub
        self._session_state = SessionState()

    def start_session(self) -> str:
        """Start a new session."""
        session_id = self.session_handler.start_session()
        self._session_state.session_id = session_id
        self._session_state.is_active = True
        self._session_state.counter = 0
        self._session_state.rekey_epoch = 0
        return session_id

    def renew_session(self) -> bool:
        """Renew the current session."""
        if not self._session_state.is_active:
            return False

        success = self.session_handler.renew_session()
        if success:
            # Update state from handler
            self._session_state.counter = self.session_handler.counter
            self._session_state.rekey_epoch = self.session_handler.rekey_epoch
        else:
            self._session_state.is_active = False
        return success

    def is_license_active(self) -> bool:
        """Check if the license session is active."""
        self._session_state.is_active = self.session_handler.is_license_active()
        return self._session_state.is_active

    @property
    def session_state(self) -> SessionState:
        """Get current session state."""
        # Ensure state is synchronized
        self._session_state.counter = self.session_handler.counter
        self._session_state.rekey_epoch = self.session_handler.rekey_epoch
        return self._session_state

    @staticmethod
    def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
        """Calculate nonce prefix for a given epoch."""
        epoch_bytes = epoch.to_bytes(4, "big")
        return bytes(a ^ b for a, b in zip(initial_nonce_prefix, epoch_bytes))
