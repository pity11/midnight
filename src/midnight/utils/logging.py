"""Structured logging via rich."""

from __future__ import annotations

import logging
from functools import lru_cache

from rich.logging import RichHandler


@lru_cache(maxsize=1)
def _configure() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )


def get_logger(name: str) -> logging.Logger:
    _configure()
    return logging.getLogger(name)
