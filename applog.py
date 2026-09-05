"""Persistent app log — written to ~/Library/Logs/LockBox/ so entries also
surface in macOS Console.app (which watches ~/Library/Logs by convention).
"""
from __future__ import annotations

import logging
import logging.handlers
import subprocess
import sys
from pathlib import Path

APP_NAME = "LockBox"


def _log_dir() -> Path:
    base = Path.home() / "Library" / "Logs" / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


LOG_DIR = _log_dir()
LOG_PATH = LOG_DIR / f"{APP_NAME}.log"

_logger = logging.getLogger(APP_NAME)
_logger.setLevel(logging.INFO)

if not _logger.handlers:
    _handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=2_000_000, backupCount=3,
    )
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
    ))
    _logger.addHandler(_handler)


def info(msg: str) -> None:
    _logger.info(msg)


def warning(msg: str) -> None:
    _logger.warning(msg)


def error(msg: str) -> None:
    _logger.error(msg)


def exception(msg: str) -> None:
    _logger.exception(msg)


def open_in_console() -> tuple[bool, str]:
    """Launch macOS Console.app pointed at this app's log file."""
    if sys.platform != "darwin":
        return False, "Console.app is only available on macOS."
    try:
        subprocess.run(["open", "-a", "Console", str(LOG_PATH)], check=True)
        return True, f"Opened {LOG_PATH} in Console"
    except Exception as e:
        return False, str(e)


def reveal_in_finder() -> tuple[bool, str]:
    """Reveal the log file in Finder."""
    if sys.platform != "darwin":
        return False, "Reveal in Finder is only available on macOS."
    try:
        subprocess.run(["open", "-R", str(LOG_PATH)], check=True)
        return True, f"Revealed {LOG_PATH} in Finder"
    except Exception as e:
        return False, str(e)
