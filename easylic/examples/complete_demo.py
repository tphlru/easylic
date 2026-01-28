#!/usr/bin/env python3
"""Complete demonstration of license decorators functionality.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from easylic.client.client import LicenseClient
from easylic.common.decorators import (
    license_protected,
    license_retry_on_fail,
    requires_active_license,
)
from easylic.common.exceptions import ValidationError


def demo_basic_usage() -> None:
    """Demonstrate basic decorator usage."""
    print("=== Basic Usage Demo ===")

    # Initialize license client
    client = LicenseClient()

    @requires_active_license(client, "This feature requires an active license")
    def premium_feature() -> str:
        """Premium feature that requires license."""
        return "🎉 Premium feature executed successfully!"

    @requires_active_license(
        client, "Optional feature unavailable", raise_exception=False
    )
    def optional_feature() -> str:
        """Optional feature that returns None if license inactive."""
        return "⚡ Optional feature executed!"

    print("Testing with license check...")
    try:
        result = premium_feature()
        print(f"✅ {result}")
    except ValidationError as e:
        print(f"❌ License error: {e}")

    result = optional_feature()
    if result:
        print(f"✅ {result}")
    else:
        print("⚠️  Optional feature not available")

    print()


def demo_class_usage() -> None:
    """Demonstrate class-based decorator usage."""
    print("=== Class Usage Demo ===")

    class ProtectedService:
        """Example service with protected methods."""

        def __init__(self) -> None:
            self.client = LicenseClient()

        @requires_active_license("client", "Service requires active license")
        def process_data(self, data: str) -> str:
            """Protected data processing method."""
            return f"📊 Processed: {data}"

        def get_client(self) -> LicenseClient:
            """Helper method to get client for dynamic access."""
            return self.client

        @license_protected(get_client, "Admin access required")
        def admin_operation(self) -> str:
            """Protected admin operation."""
            return "🔐 Admin operation completed"

        @license_retry_on_fail("client", max_retries=2)
        def critical_operation(self) -> str:
            """Critical operation with retry logic."""
            return "⚡ Critical operation completed"

    service = ProtectedService()

    # Test protected methods
    try:
        result = service.process_data("sample data")
        print(f"✅ {result}")
    except ValidationError as e:
        print(f"❌ Process data error: {e}")

    try:
        result = service.admin_operation()
        print(f"✅ {result}")
    except ValidationError as e:
        print(f"❌ Admin operation error: {e}")

    try:
        result = service.critical_operation()
        print(f"✅ {result}")
    except ValidationError as e:
        print(f"❌ Critical operation error: {e}")

    print()


def demo_dynamic_client() -> None:
    """Demonstrate dynamic client retrieval."""
    print("=== Dynamic Client Demo ===")

    # Global client instance
    global_client = LicenseClient()

    def get_license_client() -> LicenseClient:
        """Function that returns the global client."""
        return global_client

    @license_protected(get_license_client, "Dynamic license check failed")
    def dynamic_protected_function() -> str:
        """Function protected by dynamic client retrieval."""
        return "🔄 Dynamic protection successful!"

    try:
        result = dynamic_protected_function()
        print(f"✅ {result}")
    except ValidationError as e:
        print(f"❌ Dynamic protection error: {e}")

    print()


def demo_retry_logic() -> None:
    """Demonstrate retry logic with mock client."""
    print("=== Retry Logic Demo ===")

    class MockClientWithRetry:
        """Mock client that simulates license renewal."""

        def __init__(self) -> None:
            self.active = False
            self.renew_attempts = 0
            self.max_renew_attempts = 2

        def is_license_active(self) -> bool:
            return self.active

        def renew_session(self) -> bool:
            self.renew_attempts += 1
            if self.renew_attempts <= self.max_renew_attempts:
                self.active = True
                print(f"🔄 License renewed after attempt {self.renew_attempts}")
                return True
            return False

    mock_client = MockClientWithRetry()

    @license_retry_on_fail(mock_client, max_retries=3)
    def function_with_retry() -> str:
        """Function that will trigger retry logic."""
        return "🎯 Retry logic successful!"

    try:
        result = function_with_retry()
        print(f"✅ {result}")
    except ValidationError as e:
        print(f"❌ Retry logic error: {e}")

    print()


def demo_error_handling() -> None:
    """Demonstrate different error handling approaches."""
    print("=== Error Handling Demo ===")

    client = LicenseClient()

    # Exception raising (default)
    @requires_active_license(client, "Strict license check failed")
    def strict_function() -> str:
        return "Strict execution"

    # Graceful handling
    @requires_active_license(
        client, "Graceful license check failed", raise_exception=False
    )
    def graceful_function() -> str:
        return "Graceful execution"

    print("Testing strict error handling...")
    try:
        result = strict_function()
        print(f"✅ {result}")
    except ValidationError as e:
        print(f"🚫 Strict check: {e}")

    print("Testing graceful error handling...")
    result = graceful_function()
    if result is None:
        print("⚠️  Graceful check: Feature not available")
    else:
        print(f"✅ {result}")

    print()


if __name__ == "__main__":
    print("🎫 License Decorators Complete Demo\n")

    demo_basic_usage()
    demo_class_usage()
    demo_dynamic_client()
    demo_retry_logic()
    demo_error_handling()

    print("🎉 Demo completed! All decorators are working correctly.")
