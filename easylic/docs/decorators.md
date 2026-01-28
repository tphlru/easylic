# License Decorators

This module provides decorators for protecting functions and methods that should only run when a license is active.

## Available Decorators

### `requires_active_license`

The main decorator that ensures a function runs only when the license is active.

```python
from easylic import LicenseClient, requires_active_license

# Initialize client
client = LicenseClient()

# Direct client usage
@requires_active_license(client, "Premium feature requires active license")
def premium_function():
    return "Premium feature executed!"

# Class method usage
class MyService:
    def __init__(self):
        self.client = LicenseClient()
    
    @requires_active_license("client", "Service requires license")
    def protected_method(self):
        return "Protected method executed"
```

**Parameters:**
- `license_client`: LicenseClient instance, callable that returns one, or attribute name (string)
- `error_message`: Custom error message (default: "License is not active")
- `raise_exception`: Whether to raise exception (True) or return None (False)

### `license_protected`

Decorator that gets the license client dynamically via a function.

```python
def get_client():
    return global_license_client

@license_protected(get_client, "License required")
def protected_function():
    return "Function executed"
```

### `license_retry_on_fail`

Decorator that attempts to renew the license and retry execution.

```python
@license_retry_on_fail(client, max_retries=3, retry_delay=1.0)
def critical_function():
    return "Critical operation completed"
```

**Parameters:**
- `license_client`: LicenseClient instance
- `max_retries`: Maximum retry attempts (default: 3)
- `retry_delay`: Delay between retries in seconds (default: 1.0)

## Usage Examples

### Basic Function Protection

```python
from easylic import LicenseClient, requires_active_license

client = LicenseClient()

@requires_active_license(client)
def api_call():
    """This function will only run if license is active."""
    return "API call successful"

try:
    result = api_call()
    print(result)
except ValidationError as e:
    print(f"License error: {e}")
```

### Graceful Handling

```python
@requires_active_license(client, raise_exception=False)
def optional_feature():
    """Returns None if license is not active."""
    return "Optional feature executed"

result = optional_feature()
if result is None:
    print("Feature not available without license")
else:
    print(result)
```

### Class-Based Protection

```python
class DataService:
    def __init__(self):
        self.client = LicenseClient()
    
    @requires_active_license("client", "Data processing requires license")
    def process_data(self, data):
        return f"Processed: {data}"
    
    def get_client(self):
        return self.client
    
    @license_protected(get_client, "Admin access required")
    def admin_operation(self):
        return "Admin operation completed"
```

### Retry Logic

```python
@license_retry_on_fail(client, max_retries=2)
def mission_critical_function():
    """Will attempt license renewal and retry."""
    return "Critical operation completed"
```

## Error Handling

When `raise_exception=True` (default), the decorator raises a `ValidationError` with the specified error message.

When `raise_exception=False`, the decorator logs a warning and returns `None`.

## Integration with Existing Code

The decorators are designed to work seamlessly with the existing `LicenseClient` class:

```python
from easylic import LicenseClient, requires_active_license

# Your existing client setup
client = LicenseClient()

# Protect your functions
@requires_active_license(client)
def your_function():
    # Your existing code
    pass
```

The decorators check `client.is_license_active()` before allowing function execution, ensuring consistent behavior across your application.