#!/usr/bin/env python3
"""
License status check example.

This example demonstrates how to check the current status of a license
and monitor session state using the LicenseClient.
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
        # Create a LicenseClient instance
        client = LicenseClient(log_level=logging.INFO)

        # Start a session first
        session_id = client.start_session()
        print(f"Session started: {session_id}")

        # Now check the license status multiple times
        for i in range(50):
            is_active = client.is_license_active()
            print(f"License status check {i + 1}: Active = {is_active}")

            if is_active:
                print(f"  Session ID: {client.session_id}")
                print(f"  Counter: {client.counter}")
                print(f"  Rekey Epoch: {client.rekey_epoch}")

            # Wait a bit and renew once
            import time

            time.sleep(2)
            if i == 2:  # Renew in the middle
                success = client.renew_session()
                print(f"Session renewal: {'Success' if success else 'Failed'}")

        print("Status check example completed")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
