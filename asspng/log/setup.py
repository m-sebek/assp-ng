# SPDX-License-Identifier: GPL-3.0-or-later
"""Non-blocking logging setup: one queue, one writer thread."""

from __future__ import annotations

import logging
import queue
from logging.handlers import QueueHandler, QueueListener, WatchedFileHandler
from pathlib import Path

from asspng.log.maillog import MAILLOG_LOGGER
from asspng.log.redact import RedactionFilter

_APP_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class _NotMaillog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name != MAILLOG_LOGGER


class _OnlyMaillog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name == MAILLOG_LOGGER


# Handlers installed per listener, so shutdown_logging can undo exactly its own work.
_installed: dict[int, tuple[QueueHandler, bool, int, int]] = {}


def configure_logging(level: str, log_dir: Path, *, journal: bool) -> QueueListener:
    """Install queue-based logging for ``asspng`` and return the started listener."""
    log_dir.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = []

    app = WatchedFileHandler(log_dir / "assp-ng.log", encoding="utf-8")
    app.setLevel(level.upper())
    app.setFormatter(logging.Formatter(_APP_FORMAT))
    app.addFilter(_NotMaillog())
    handlers.append(app)

    mail = WatchedFileHandler(log_dir / "maillog.log", encoding="utf-8")
    mail.setLevel(logging.INFO)
    mail.setFormatter(logging.Formatter("%(message)s"))
    mail.addFilter(_OnlyMaillog())
    handlers.append(mail)

    if journal:
        from systemd.journal import JournalHandler

        jh = JournalHandler(SYSLOG_IDENTIFIER="assp-ng")
        jh.setLevel(logging.WARNING)
        jh.addFilter(_NotMaillog())
        handlers.append(jh)

    log_queue: queue.SimpleQueue[logging.LogRecord] = queue.SimpleQueue()
    qh = QueueHandler(log_queue)
    qh.addFilter(RedactionFilter())
    listener = QueueListener(log_queue, *handlers, respect_handler_level=True)

    root = logging.getLogger("asspng")
    mail_logger = logging.getLogger(MAILLOG_LOGGER)
    _installed[id(listener)] = (qh, root.propagate, root.level, mail_logger.level)
    root.setLevel(min(logging.INFO, app.level))
    root.addHandler(qh)
    root.propagate = False
    mail_logger.setLevel(logging.INFO)
    listener.start()
    return listener


def shutdown_logging(listener: QueueListener) -> None:
    """Stop the writer thread (flushing the queue) and remove what configure installed."""
    saved = _installed.pop(id(listener), None)
    if saved is not None:
        qh, propagate, level, mail_level = saved
        root = logging.getLogger("asspng")
        root.removeHandler(qh)
        root.propagate = propagate
        root.setLevel(level)
        logging.getLogger(MAILLOG_LOGGER).setLevel(mail_level)
    listener.stop()
    for h in listener.handlers:
        h.close()
    listener.handlers = ()
