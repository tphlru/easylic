"""
Custom exceptions for the license system.
"""

from __future__ import annotations


class ValidationError(Exception):
    """Exception for validation failures."""

    def __init__(self, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.status_code = status_code


class RateLimitError(ValidationError):
    """Exception for rate limiting."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 429)
