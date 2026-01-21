#!/usr/bin/env python3
"""
Threaded usage example of LicenseClient.

This example shows how to run the LicenseClient in a background thread
while the main thread performs other operations.
"""

import logging
import os
import sys
import time

# Add the project root to the path to import easylic
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from easylic.client.client import LicenseClient


def error_callback(error: Exception):
    """Custom error handler for license client errors."""
    print(f"License client error: {error}")

def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO)

    try:
        # Create a LicenseClient instance with custom settings
        client = LicenseClient(
            log_level=logging.INFO,
            on_error_callback=error_callback,
            renew_interval=10  # Renew every 10 seconds
        )

        # Start the client in a background thread
        client.start_in_thread()
        print("License client started in background thread")

        # Main thread can perform other work
        for i in range(6):  # Run for about 1 minute
            print(f"Main thread working... Iteration {i+1}")
            print(f"License active: {client.is_license_active()}")

            # Simulate some work
            time.sleep(10)

        print("Threaded usage example completed")

        # Note: The daemon thread will stop when the main thread exits

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
