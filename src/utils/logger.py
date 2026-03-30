"""Structured JSON logging for CloudWatch compatibility.

CRITICAL: Never log raw PII. All log messages pass through a sanitization
safety net that strips patterns resembling SSNs, credit cards, and emails.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

# Patterns used ONLY for log sanitization (safety net)
_SANITIZE_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    (re.compile(r"\b\d{9}\b"), "[REDACTED-SSN]"),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b"), "[REDACTED-CC]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED-EMAIL]"),
]


def sanitize_log_message(message: str) -> str:
    """Strip potential PII patterns from log messages as a safety net."""
    for pattern, replacement in _SANITIZE_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON for CloudWatch."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize_log_message(record.getMessage()),
        }

        # Add request_id if available
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id

        # Add any extra fields passed via the `extra` dict
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)

        # Include exception info if present
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": sanitize_log_message(str(record.exc_info[1])),
            }

        return json.dumps(log_entry, default=str)


class StructuredLogger(logging.Logger):
    """Logger subclass that supports extra structured fields."""

    def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False, stacklevel=1, **kwargs):
        if extra is None:
            extra = {}
        # Move non-standard extra fields into extra_fields
        extra_fields = {k: v for k, v in kwargs.items() if k not in ("exc_info", "stack_info", "stacklevel")}
        if extra_fields:
            extra["extra_fields"] = extra_fields
        super()._log(level, msg, args, exc_info=exc_info, extra=extra, stack_info=stack_info, stacklevel=stacklevel + 1)


# Register our custom logger class
logging.setLoggerClass(StructuredLogger)


def get_logger(name: str, level: str = "INFO") -> StructuredLogger:
    """Create a structured JSON logger.

    Args:
        name: Logger name (typically __name__).
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).

    Returns:
        A StructuredLogger that outputs CloudWatch-compatible JSON.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger
