"""
Shared audit logger.

Writes every operational event both to the console and to a persistent log
file, tagged with the engagement metadata. The log is intended to be attached
to the assessment report (timestamp, host, technique, ATT&CK ID, result).
"""

import logging
import sys


def build_logger(name: str, log_file: str, engagement=None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    prefix = engagement.as_log_prefix() + " " if engagement else ""
    fmt = logging.Formatter(
        f"%(asctime)s | {prefix}%(levelname)s | %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    if engagement is not None:
        logger.info(
            "ENGAGEMENT start | scope_note=%r | started_at=%s",
            engagement.scope_note, engagement.started_at,
        )
    return logger
