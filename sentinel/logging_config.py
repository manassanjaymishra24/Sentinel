"""Centralized logging configuration for Sentinel.

This module provides setup and configuration for Python's standard logging module
across the Sentinel codebase. Enables consistent structured logging with configurable
levels, formats, and output destinations.

Usage:
    from sentinel.logging_config import setup_logging
    setup_logging()  # Configures root logger and all Sentinel loggers
    
    # Optionally set environment variables before setup:
    os.environ['LOG_LEVEL'] = 'DEBUG'  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    os.environ['LOG_FILE'] = 'sentinel.log'  # Optional file output
    setup_logging()
"""

import logging
import logging.handlers
import os
from pathlib import Path


def setup_logging(
    level: str | None = None,
    log_file: str | None = None,
    format_string: str | None = None,
) -> None:
    """Configure root logger and all Sentinel loggers with consistent format.
    
    Sets up logging infrastructure for the Sentinel application. Supports both
    console output and optional file logging. Uses environment variables for
    configuration if parameters not provided.
    
    Args:
        level: Logging level as string (default: from LOG_LEVEL env or 'INFO')
            Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL
        log_file: Optional log file path (default: from LOG_FILE env or None)
            Directory is created if it doesn't exist.  
        format_string: Custom log format (default: structured format with timestamp,
            level, logger name, and message)
            
    Example:
        # Configure from environment
        os.environ['LOG_LEVEL'] = 'DEBUG'
        os.environ['LOG_FILE'] = 'logs/sentinel.log'
        setup_logging()
        
        # Or configure directly
        setup_logging(level='WARNING', log_file='app.log')
        
    Note:
        Called automatically by entry points. Calling multiple times reconfigures
        the logger (useful for testing or dynamic reconfiguration).
    """
    # Resolve parameters from environment if not provided
    level = level or os.environ.get("LOG_LEVEL", "INFO").upper()
    log_file = log_file or os.environ.get("LOG_FILE")
    format_string = format_string or (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    
    # Validate log level
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(format_string)
    
    # Add console handler (always)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Add file handler if log_file is specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        root_logger.info(f"Logging to file: {log_path}")
    
    # Configure Sentinel loggers specifically
    for sentinel_module in [
        "sentinel",
        "sentinel.llm",
        "sentinel.network",
        "sentinel.storage",
        "sentinel.drift",
        "sentinel.reasoning",
        "sentinel.defense",
        "sentinel.events",
        "sentinel.audit",
        "sentinel.memory",
        "sentinel.review",
        "sentinel.response",
        "sentinel.monitor",
    ]:
        logger = logging.getLogger(sentinel_module)
        logger.setLevel(numeric_level)
    
    root_logger.debug(f"Logging configured: level={level}, file={log_file}")


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger instance for a module.
    
    Convenience function for getting loggers in Sentinel modules.
    Call setup_logging() once at program start, then use this to get
    module-specific loggers.
    
    Args:
        name: Logger name (typically __name__ in modules)
        
    Returns:
        logging.Logger configured instance
        
    Example:
        logger = get_logger(__name__)
        logger.info("Module initialized")
    """
    return logging.getLogger(name)


# Configure logging on module import
if os.environ.get("SENTINEL_SKIP_AUTO_LOGGING") != "1":
    setup_logging()
