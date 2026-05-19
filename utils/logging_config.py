"""
Logging configuration.

Sets up structured logging with a consistent format.
Sensitive values (API keys, credentials) must never be passed to loggers —
this module provides no special redaction because callers must sanitise first.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


def configure_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
) -> None:
    """
    Configure root logger.

    Attaches a StreamHandler (stderr) always, and optionally a FileHandler.
    Calling this more than once is safe — existing handlers are cleared first.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Clear existing handlers to prevent duplicate output on reconfiguration
    root.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
