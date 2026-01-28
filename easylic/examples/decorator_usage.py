"""Example usage of license decorators.
"""

from __future__ import annotations

from easylic.client.client import LicenseClient
from easylic.common.decorators import (
    license_protected,
    license_retry_on_fail,
    requires_active_license,
)


# Example 1: Using decorator with direct client instance
def example_with_direct_client() -> None:
    """Example using requires_active_license decorator."""
    # Initialize license client
    client = LicenseClient()

    @requires_active_license(client, "This feature requires an active license")
    def premium_function() -> str:
        """Function that only works with active license."""
        return "Premium feature executed successfully!"

    @requires_active_license(client, raise_exception=False)
    def optional_feature() -> str:
        """Function that returns None if license is not active."""
        return "Optional feature executed!"

    # These will only work if license is active
    try:
        result = premium_function()
        print(result)
    except Exception as e:
        print(f"Error: {e}")

    # This will handle inactive license gracefully
    result = optional_feature()
    if result is None:
        print("Optional feature not available without license")
    else:
        print(result)


# Example 2: Using decorator with dynamic client retrieval
def example_with_dynamic_client() -> None:
    """Example using license_protected decorator."""
    # Global client instance
    global_client = LicenseClient()

    def get_client() -> LicenseClient:
        return global_client

    @license_protected(get_client, "Access denied: License required")
    def protected_api_call() -> str:
        """API call protected by license."""
        return "API call successful!"

    try:
        result = protected_api_call()
        print(result)
    except Exception as e:
        print(f"Protected call failed: {e}")


# Example 3: Using retry decorator
def example_with_retry() -> None:
    """Example using license_retry_on_fail decorator."""
    client = LicenseClient()

    @license_retry_on_fail(client, max_retries=2)
    def critical_function() -> str:
        """Function that will retry license activation."""
        return "Critical operation completed!"

    try:
        result = critical_function()
        print(result)
    except Exception as e:
        print(f"Critical function failed: {e}")


# Example 4: Class-based protection
class ProtectedService:
    """Example class with protected methods."""

    def __init__(self, client: LicenseClient) -> None:
        self.client = client

    @requires_active_license(lambda self: self.client, "Service requires license")
    def process_data(self, data: str) -> str:
        """Protected method that processes data."""
        return f"Processed: {data}"

    def get_client(self) -> LicenseClient:
        return self.client

    @license_protected(get_client, "Admin access required")
    def admin_function(self) -> str:
        """Protected admin function."""
        return "Admin operation completed"


if __name__ == "__main__":
    # Run examples
    print("=== License Decorator Examples ===")

    example_with_direct_client()
    print()

    example_with_dynamic_client()
    print()

    example_with_retry()
    print()

    # Class example
    client = LicenseClient()
    service = ProtectedService(client)

    try:
        result = service.process_data("test data")
        print(f"Service result: {result}")
    except Exception as e:
        print(f"Service error: {e}")
