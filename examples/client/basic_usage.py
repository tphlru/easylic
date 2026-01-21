#!/usr/bin/env python3
"""
Basic usage example of LicenseClient.

This example demonstrates how to create a LicenseClient instance,
start a secure session with the license server, and check the license status.
"""

import logging
import os
import sys

# Add the project root to the path to import easylic
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from easylic.client.client import LicenseClient


def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO)

    try:
        # Create a LicenseClient instance with default settings
        client = LicenseClient(
            log_level=logging.INFO
        )

        # Start a secure session
        session_id = client.start_session()
        print(f"Session started successfully: {session_id}")

        # Check if license is active
        is_active = client.is_license_active()
        print(f"License active: {is_active}")

        # Keep the session alive by renewing periodically
        import time
        for i in range(3):
            time.sleep(5)  # Wait a bit
            success = client.renew_session()
            if success:
                print(f"Session renewed successfully, counter: {client.counter}")
            else:
                print("Failed to renew session")
                break

        print("Basic usage example completed")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
