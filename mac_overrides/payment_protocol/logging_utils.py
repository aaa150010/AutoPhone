from __future__ import annotations

import logging
import os
import re
import sys
import threading
from typing import Any, Callable
from urllib.parse import urlsplit

LogFn = Callable[[str], None]
_CONFIG_LOCK = threading.Lock()
_CONFIGURED = False
logger = logging.getLogger("gptphone.payment_protocol")


def configure_logging(
    *,
    level: str = "INFO",
    log_file: str = "",
    serialize: bool = False,
    force: bool = False,
) -> None:
    """Configure standard logging for CLI and threaded web tasks."""
    global _CONFIGURED
    with _CONFIG_LOCK:
        if _CONFIGURED and not force:
            return
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        if not logger.handlers:
            logger.addHandler(logging.StreamHandler(sys.stderr))
        if log_file:
            logger.addHandler(logging.FileHandler(log_file, encoding="utf-8"))
        _CONFIGURED = True


def log_context(**context: Any):
    """Return a logger carrying safe, searchable context fields."""
    return logging.LoggerAdapter(logger, context)


def stage_logger(enabled: bool, **context: Any) -> LogFn | None:
    if not enabled:
        return None

    def log(message: str) -> None:
        logger.info("%s", message)

    return log


def emit_log(log: LogFn | None, message: str) -> None:
    if log:
        log(message)


def safe_log_text(value: Any, limit: int = 500) -> str:
    text = str(value or "")
    text = re.sub(r"([a-z][a-z0-9+.-]*://)([^/@\s]+)@", r"\1***@", text, flags=re.I)
    text = re.sub(r"(Bearer\s+)[^\s,;]+", r"\1***", text, flags=re.I)
    return text if len(text) <= limit else text[:limit] + "..."


def compact_url(url: str) -> str:
    try:
        parsed = urlsplit(str(url or ""))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path[:80]}"
    except Exception:
        return str(url or "")[:120]
