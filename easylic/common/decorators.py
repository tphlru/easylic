"""License decorators for function protection.
"""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from easylic.common.exceptions import ValidationError

logger = logging.getLogger(__name__)


def requires_active_license(
    license_client: Any | Callable[[Any], Any] | str,
    error_message: str = "License is not active",
    *,
    raise_exception: bool = True,
) -> Callable:
    """Decorator that ensures function runs only when license is active.

    Args:
        license_client: LicenseClient instance or callable that returns one
        error_message: Message to show when license is not active
        raise_exception: Whether to raise exception or return None

    Returns:
        Decorated function that only executes when license is active
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get client instance (direct, callable, or attribute name)
            if isinstance(license_client, str):
                # Attribute name - get from self
                if args:
                    client = getattr(args[0], license_client)
                else:
                    error_msg = (
                        f"Cannot get client attribute '{license_client}' without self"
                    )
                    raise ValueError(error_msg)
            elif callable(license_client):
                if args and hasattr(args[0], func.__name__):
                    # Method call - pass self
                    try:
                        client = license_client(args[0])
                    except TypeError:
                        # Fallback to calling without arguments
                        client = license_client()  # type: ignore[call-arg]
                else:
                    # Function call - call without arguments
                    client = license_client()  # type: ignore[call-arg]
            else:
                # Direct client instance
                client = license_client

            if not client.is_license_active():
                if raise_exception:
                    raise ValidationError(error_message)
                logger.warning("License check failed: %s", error_message)
                return None
            return func(*args, **kwargs)

        return wrapper

    return decorator


def license_protected(
    get_license_client: Callable[..., Any],
    error_message: str = "License is not active",
    *,
    raise_exception: bool = True,
) -> Callable:
    """Decorator that gets license client dynamically and checks license status.

    Args:
        get_license_client: Function that returns LicenseClient instance
        error_message: Message to show when license is not active
        raise_exception: Whether to raise exception or return None

    Returns:
        Decorated function that only executes when license is active
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            license_client = get_license_client()
            if not license_client.is_license_active():
                if raise_exception:
                    raise ValidationError(error_message)
                logger.warning("License check failed: %s", error_message)
                return None
            return func(*args, **kwargs)

        return wrapper

    return decorator


def license_retry_on_fail(
    license_client: Any,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> Callable:
    """Decorator that attempts to renew license and retry function execution.

    Args:
        license_client: LicenseClient instance
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds

    Returns:
        Decorated function with retry logic
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            for attempt in range(max_retries + 1):
                if license_client.is_license_active():
                    return func(*args, **kwargs)

                if attempt < max_retries:
                    if license_client.renew_session():
                        continue
                    time.sleep(retry_delay)
                else:
                    msg = f"License could not be activated after {max_retries} attempts"
                    raise ValidationError(msg)

            return None

        return wrapper

    return decorator
