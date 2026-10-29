"""
utils/logger.py — Central Logging
=================================
Instead of scattering print() everywhere, we use ONE shared logger that:

  1. Prints to the console (so you see output live), AND
  2. Writes to logs/scan.log with timestamps + severity levels.

This gives you a permanent, timestamped record of every scan —
"SOC-style auditing" (what a real security operations tool does).

  LOG LEVELS (least -> most severe):
    DEBUG    - detailed dev info
    INFO     - normal events ("scan started", "found 7 devices")
    WARNING  - notable but not fatal ("UNKNOWN device found")
    ERROR    - something failed ("nmap error")
    CRITICAL - severe failure

Usage from any module:
    from utils.logger import get_logger
    log = get_logger()
    log.info("Scan started")
    log.warning("Unknown device: 192.168.0.109")
"""

import os
import logging
from datetime import datetime

# Build absolute paths so logging works no matter where you run from.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

# Each program run gets its OWN log file, named with the start time. So:
#   run once -> logs/scan_2026-07-01_21-30-00.log
#   run again -> logs/scan_2026-07-01_21-45-12.log  (a brand-new file)
# This is decided once, when this module is first imported (i.e. once per run).
LOG_FILE = os.path.join(LOG_DIR, f"scan_{datetime.now():%Y-%m-%d_%H-%M-%S}.log")


def get_logger(name="scanner"):
    """
    Return a configured logger that writes to BOTH the console and a
    per-run log file (a fresh timestamped file each time you run the program).

    Calling this multiple times returns the SAME logger without adding
    duplicate handlers (which would print every line twice).
    """
    # Make sure the logs/ folder exists before we try to write to it.
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)

    # If we've already set this logger up, just return it. Without this guard,
    # each call would attach another file+console handler -> duplicate log lines.
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)   # capture INFO and above

    # A shared format: "2026-07-01 21:30:15 [INFO] message"
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Write to THIS run's log file (a new file per run).
    # NOTE: file-only by design — the console shows the clean, formatted report
    # (from main.py's print_* functions), while the full timestamped audit trail
    # lives in logs/scan_*.log. This keeps the terminal output professional.
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger


def main():
    """Quick test — writes a few sample log lines to console + a new log file."""
    log = get_logger()
    log.info("Logger test started")
    log.info("Found 7 devices")
    log.warning("UNKNOWN device found: 192.168.0.109")
    log.error("Example error: nmap not found")
    print(f"\nCheck the log file at: {LOG_FILE}")


if __name__ == "__main__":
    main()
