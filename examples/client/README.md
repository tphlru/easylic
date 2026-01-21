# License Client Examples

This directory contains examples demonstrating how to use the `LicenseClient` class from the `easylic` library.

## Examples

### basic_usage.py
Demonstrates basic usage of the LicenseClient:
- Creating a client instance
- Starting a secure session
- Checking license status
- Renewing the session manually

Run with: `python basic_usage.py`

### threaded_usage.py
Shows how to run the LicenseClient in a background thread:
- Starting the client in a separate thread
- Custom error handling
- Main thread performing other work while license is managed in background

Run with: `python threaded_usage.py`

### status_check.py
Focuses on license status checking:
- Starting a session
- Repeatedly checking if the license is active
- Displaying session details
- Manual session renewal

Run with: `python status_check.py`

## Prerequisites

Before running these examples, ensure you have:

1. A valid license file (default: `license.json`)
2. Server public key in `server_keys/server_public.key`
3. A running license server at the configured URL

## Configuration

The examples use default configuration from `easylic.common.config.Config`. You can customize:

- `server_url`: License server URL
- `license_file`: Path to license file
- `log_level`: Logging verbosity
- `renew_interval`: Session renewal interval
- Other parameters as needed

See the `LicenseClient` constructor for all available options.