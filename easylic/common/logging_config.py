import logging
import logging.handlers
from pathlib import Path
from .config import Config


def setup_logging():
    """Configure logging for the application."""
    # Create logger
    logger = logging.getLogger('easylic')
    logger.setLevel(getattr(logging, Config.LOG_LEVEL))

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatters
    formatter = logging.Formatter(Config.LOG_FORMAT)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (rotating)
    if Config.LOG_FILE:
        log_path = Path(Config.LOG_FILE)
        log_path.parent.mkdir(exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# Global logger instance
logger = setup_logging()