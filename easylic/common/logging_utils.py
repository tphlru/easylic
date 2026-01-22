"""
Logging utilities for consistent logging setup across the application.
"""

import logging


def setup_logger(logger: logging.Logger, log_level: int) -> None:
    """
    Set up a logger with a StreamHandler and standard formatter.

    Args:
        logger: The logger instance to configure
        log_level: The logging level to set
    """
    logger.setLevel(log_level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(log_level)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
