"""
OOP-based license client - Presentation layer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from easylic.client.application.runner import Runner
from easylic.client.application.session_manager import SessionManager
from easylic.client.domain.entities import ClientKeys, License
from easylic.client.infrastructure.config_loader import ConfigLoader
from easylic.client.infrastructure.session_handler import SessionHandlerInfra
from easylic.common.models import ClientConfig, LicenseData


class LicenseClient:
    """License client for secure session management - Presentation layer."""

    def __init__(self, config: ClientConfig | None = None, **overrides: Any) -> None:
        if config is None:
            config = ClientConfig(**overrides)
        # Infrastructure layer: Configuration and file loading
        self.config_loader = ConfigLoader(config)

        # Load infrastructure components
        server_pub = self.config_loader.load_server_public_key()
        license_data = self.config_loader.load_license()
        client_priv, client_pub_hex, client_eph_priv, client_eph_pub_hex = (
            self.config_loader.generate_client_keys()
        )

        # Domain layer: Business entities
        license_entity = License(
            data=license_data, file_path=Path(self.config_loader.license_file)
        )
        client_keys = ClientKeys(
            identity_private=client_priv,
            identity_public_hex=client_pub_hex,
            ephemeral_private=client_eph_priv,
            ephemeral_public_hex=client_eph_pub_hex,
        )

        # Infrastructure layer: Session handling
        session_handler_infra = SessionHandlerInfra(
            server_url=self.config_loader.server_url,
            license_data=license_data,
            client_priv=client_priv,
            client_pub_hex=client_pub_hex,
            client_eph_priv=client_eph_priv,
            client_eph_pub_hex=client_eph_pub_hex,
            server_pub=server_pub,
            config=self.config_loader.config,
        )

        # Application layer: Session management
        self.session_manager = SessionManager(
            session_handler=session_handler_infra,
            license_entity=license_entity,
            client_keys=client_keys,
            server_pub=server_pub,
        )

        # Application layer: Runner
        self.runner = Runner(
            session_manager=self.session_manager,
            renew_interval=self.config_loader.renew_interval,
            on_error_callback=config.on_error_callback,
        )

    @property
    def session_id(self) -> str | None:
        return self.session_manager.session_state.session_id

    @property
    def counter(self) -> int:
        return self.session_manager.session_state.counter

    @property
    def rekey_epoch(self) -> int:
        return self.session_manager.session_state.rekey_epoch

    @property
    def server_url(self) -> str:
        """Get server URL from config."""
        return self.config_loader.server_url

    @property
    def license_file(self) -> str:
        """Get license file path from config."""
        return self.config_loader.license_file

    @property
    def license(self) -> LicenseData:
        """Get license data from domain entity."""
        return self.session_manager.license.data

    @staticmethod
    def get_nonce_prefix_for_epoch(initial_nonce_prefix: bytes, epoch: int) -> bytes:
        """Calculate nonce prefix for a given epoch."""
        return SessionManager.get_nonce_prefix_for_epoch(initial_nonce_prefix, epoch)

    def start_session(self) -> str:
        """Start a secure session with the server."""
        return self.session_manager.start_session()

    def is_license_active(self) -> bool:
        """Check if the license is currently active (session is valid)."""
        return self.session_manager.is_license_active()

    def renew_session(self) -> bool:
        """Renew the current session."""
        return self.session_manager.renew_session()

    def run(self) -> None:
        """Run the client loop."""
        self.runner.run()

    def start_in_thread(self) -> None:
        """Start the client in a separate thread."""
        self.runner.start_in_thread()

    def stop_thread(self) -> None:
        """Stop the background thread."""
        self.runner.stop_thread()
