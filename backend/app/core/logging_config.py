"""Structured logging configuration for the whole platform."""

from __future__ import annotations

import logging
import sys

from app.core.config import settings

_CONFIGURED = False

_AGENT_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-38s | %(message)s"


def setup_logging(level: str | None = None) -> None:
    """Install a single stdout handler with a consistent format."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    resolved = (level or settings.log_level).upper()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_AGENT_FORMAT, datefmt="%H:%M:%S"))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(resolved)

    # These are chatty and rarely useful during a hackathon demo.
    for noisy in ("uvicorn.access", "multipart", "asyncio", "docker"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, root.level))

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Module-level logger. Every agent execution is logged through this."""
    setup_logging()
    return logging.getLogger(name)
