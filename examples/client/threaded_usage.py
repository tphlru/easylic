"""
Threaded usage example of LicenseClient.

This example shows how to run the LicenseClient in a background thread
while the main thread performs other operations.
"""

import logging
import sys
import time
from pathlib import Path

# Add the project root to the path to import easylic
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from easylic.client.client import LicenseClient


def error_callback(error: Exception) -> None:
    """Custom error handler for license client errors."""
    logger = logging.getLogger(__name__)
    logger.error("License client error: %s", error)


def main() -> None:
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    try:
        # Create a LicenseClient instance with custom settings
        client = LicenseClient(
            log_level=logging.INFO,
            on_error_callback=error_callback,
            renew_interval=10,  # Renew every 10 seconds
        )

        # Start the client in a background thread
        client.start_in_thread()
        logger.info("License client started in background thread")

        # Main thread can perform other work
        for i in range(6):  # Run for about 1 minute
            logger.info("Main thread working... Iteration %d", i + 1)
            logger.info("License active: %s", client.is_license_active())

            # Simulate some work
            time.sleep(10)

        logger.info("Threaded usage example completed")

        # Note: The daemon thread will stop when the main thread exits
    except Exception:
        logger.exception("Error")
        sys.exit(1)


if __name__ == "__main__":
    main()
