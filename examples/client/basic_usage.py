"""
Basic usage example of LicenseClient.

This example demonstrates how to create a LicenseClient instance,
start a secure session with the license server, and check the license status.
"""

import logging
import sys
import time
from pathlib import Path

# Add the project root to the path to import easylic
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from easylic.client.client import LicenseClient


def main() -> None:
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    try:
        # Create a LicenseClient instance with default settings
        client = LicenseClient(log_level=logging.INFO)

        # Start a secure session
        session_id = client.start_session()
        logger.info("Session started successfully: %s", session_id)

        # Check if license is active
        is_active = client.is_license_active()
        logger.info("License active: %s", is_active)

        # Keep the session alive by renewing periodically
        for _i in range(3):
            time.sleep(5)  # Wait a bit
            success = client.renew_session()
            if success:
                logger.info("Session renewed successfully, counter: %s", client.counter)
            else:
                logger.info("Failed to renew session")
                break

        logger.info("Basic usage example completed")
    except Exception:
        logger.exception("Error")
        sys.exit(1)


if __name__ == "__main__":
    main()
