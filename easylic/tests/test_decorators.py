"""Test script for license decorators functionality.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from easylic.common.decorators import (
    license_protected,
    license_retry_on_fail,
    requires_active_license,
)
from easylic.common.exceptions import ValidationError


class MockLicenseClient:
    """Mock license client for testing."""

    def __init__(self, active: bool = True):
        self._active = active
        self._renew_success = True

    def is_license_active(self) -> bool:
        return self._active

    def renew_session(self) -> bool:
        return self._renew_success

    def set_active(self, active: bool) -> None:
        self._active = active

    def set_renew_success(self, success: bool) -> None:
        self._renew_success = success


def test_requires_active_license() -> None:
    """Test basic requires_active_license decorator."""
    print("Testing requires_active_license decorator...")

    client = MockLicenseClient(active=True)

    @requires_active_license(client, "License required")
    def test_function() -> str:
        return "Function executed"

    # Test with active license
    try:
        result = test_function()
        assert result == "Function executed"
        print("✓ Active license: Function executed successfully")
    except Exception as e:
        print(f"✗ Active license failed: {e}")

    # Test with inactive license
    client.set_active(False)
    try:
        result = test_function()
        print(f"✗ Inactive license should have raised exception but got: {result}")
    except ValidationError as e:
        print(f"✓ Inactive license: Correctly raised exception: {e}")
    except Exception as e:
        print(f"✗ Inactive license: Wrong exception type: {e}")

    # Test with raise_exception=False
    @requires_active_license(client, "License required", raise_exception=False)
    def test_function_no_exception() -> str:
        return "Function executed"

    result = test_function_no_exception()
    if result is None:
        print("✓ Inactive license with raise_exception=False: Returned None")
    else:
        print(f"✗ Expected None but got: {result}")


def test_license_protected() -> None:
    """Test license_protected decorator with dynamic client retrieval."""
    print("\nTesting license_protected decorator...")

    global_client = MockLicenseClient(active=True)

    def get_client() -> MockLicenseClient:
        return global_client

    @license_protected(get_client, "License required")
    def test_function() -> str:
        return "Function executed"

    # Test with active license
    try:
        result = test_function()
        assert result == "Function executed"
        print("✓ Active license: Function executed successfully")
    except Exception as e:
        print(f"✗ Active license failed: {e}")

    # Test with inactive license
    global_client.set_active(False)
    try:
        result = test_function()
        print(f"✗ Inactive license should have raised exception but got: {result}")
    except ValidationError as e:
        print(f"✓ Inactive license: Correctly raised exception: {e}")
    except Exception as e:
        print(f"✗ Inactive license: Wrong exception type: {e}")


def test_license_retry_on_fail() -> None:
    """Test license_retry_on_fail decorator."""
    print("\nTesting license_retry_on_fail decorator...")

    client = MockLicenseClient(active=False)

    @license_retry_on_fail(client, max_retries=2)
    def test_function() -> str:
        return "Function executed"

    # Test with successful renewal
    client.set_renew_success(True)
    try:
        result = test_function()
        assert result == "Function executed"
        print("✓ Retry with successful renewal: Function executed")
    except Exception as e:
        print(f"✗ Retry failed: {e}")

    # Test with failed renewal
    client.set_renew_success(False)
    try:
        result = test_function()
        print(f"✗ Should have raised exception but got: {result}")
    except ValidationError as e:
        print(f"✓ Retry with failed renewal: Correctly raised exception: {e}")
    except Exception as e:
        print(f"✗ Wrong exception type: {e}")


def test_class_based_decorator() -> None:
    """Test decorator usage in class methods."""
    print("\nTesting class-based decorator usage...")

    class TestService:
        def __init__(self, client: MockLicenseClient) -> None:
            self.client = client

        def get_client(self) -> MockLicenseClient:
            return self.client

        @requires_active_license("client", "License required")
        def protected_method(self) -> str:
            return "Protected method executed"

        @license_protected(lambda self: self.client, "License required")
        def another_protected_method(self) -> str:
            return "Another protected method executed"

    client = MockLicenseClient(active=True)
    service = TestService(client)

    # Test with active license
    try:
        result = service.protected_method()
        assert result == "Protected method executed"
        print("✓ Class method with active license: Executed successfully")

        result = service.another_protected_method()
        assert result == "Another protected method executed"
        print("✓ Another class method with active license: Executed successfully")
    except Exception as e:
        print(f"✗ Class method failed: {e}")

    # Test with inactive license
    client.set_active(False)
    try:
        result = service.protected_method()
        print(f"✗ Should have raised exception but got: {result}")
    except ValidationError as e:
        print(f"✓ Class method with inactive license: Correctly raised exception: {e}")
    except Exception as e:
        print(f"✗ Wrong exception type: {e}")


if __name__ == "__main__":
    print("=== License Decorator Tests ===\n")

    test_requires_active_license()
    test_license_protected()
    test_license_retry_on_fail()
    test_class_based_decorator()

    print("\n=== Tests completed ===")
