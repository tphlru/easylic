"""
Application layer: Client runner for managing the license client lifecycle.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from easylic.client.application.session_manager import SessionManager


class Runner:
    """Application service for running the license client loop."""

    def __init__(
        self,
        session_manager: SessionManager,
        renew_interval: int,
        on_error_callback: Callable[[Exception], None] | None = None,
    ):
        self.session_manager = session_manager
        self.renew_interval = renew_interval
        self.on_error_callback = on_error_callback
        self.logger = logging.getLogger(__name__)
        self._thread: threading.Thread | None = None
        self._running = False

    def run(self) -> None:
        """Run the client loop."""
        try:
            self.session_manager.start_session()
            self._running = True
            while self._running:
                time.sleep(self.renew_interval)
                if not self.session_manager.renew_session():
                    error = Exception("Session renewal failed")
                    if self.on_error_callback:
                        self.on_error_callback(error)
                    break
        except Exception as e:
            self.logger.exception("Client error")
            if self.on_error_callback:
                self.on_error_callback(e)
            raise

    def start_in_thread(self) -> None:
        """Start the client in a separate thread."""
        if self._thread and self._thread.is_alive():
            self.logger.warning("Client is already running in a thread")
            return
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        self.logger.info("Client started in background thread")

    def stop_thread(self) -> None:
        """Stop the background thread."""
        self._running = False
        if self._thread:
            # Since it's daemon, it will stop when main thread exits
            self._thread = None
        self.logger.info("Client thread stopped")
