"""Logging setup shared by every module.

One formatter for console and file keeps the terminal readable and the log
greppable. The file handler rotates, so a long-lived installation cannot fill
the disk.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)-16s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(
    name: str = "bugbounty",
    log_file: str | Path = "logs/toolkit.log",
    level: str = "INFO",
    max_bytes: int = 2_000_000,
    backups: int = 3,
) -> logging.Logger:
    """Create (or return) a logger writing to the console and a rotating file.

    Args:
        name: Logger name; using the same name twice returns the same logger.
        log_file: Path of the log file. Its parent directory is created.
        level: Logging level as text (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        max_bytes: Rotate the log file once it grows past this size.
        backups: How many rotated files to keep.

    Returns:
        A configured :class:`logging.Logger`. Calling it again with the same name
        does not add duplicate handlers.
    """
    logger = logging.getLogger(name)
    if logger.handlers:  # already configured in this process
        return logger

    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    path = Path(log_file)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            path, maxBytes=int(max_bytes), backupCount=int(backups), encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as error:  # a read-only checkout must not stop the run
        logger.warning("Could not open log file %s: %s (console logging only)", path, error)

    return logger
