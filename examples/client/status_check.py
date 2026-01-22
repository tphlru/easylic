"""
License status check example.

This example demonstrates how to check the current status of a license
and monitor session state using the LicenseClient.
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
        # Create a LicenseClient instance
        client = LicenseClient(log_level=logging.INFO)

        # Start a session first
        session_id = client.start_session()
        logger.info("Session started: %s", session_id)

        # Now check the license status multiple times
        for i in range(50):
            is_active = client.is_license_active()
            logger.info("License status check %d: Active = %s", i + 1, is_active)

            if is_active:
                logger.info("  Session ID: %s", client.session_id)
                logger.info("  Counter: %s", client.counter)
                logger.info("  Rekey Epoch: %s", client.rekey_epoch)

            # Wait a bit and renew once
            time.sleep(2)
            if i == 2:  # Renew in the middle  # noqa: PLR2004
                success = client.renew_session()
                logger.info("Session renewal: %s", "Success" if success else "Failed")

        logger.info("Status check example completed")

    except Exception:
        logger.exception("Error")
        sys.exit(1)


if __name__ == "__main__":
    main()
