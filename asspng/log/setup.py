# SPDX-License-Identifier: GPL-3.0-or-later
"""Non-blocking logging setup: one queue, one writer thread.

The ``asspng`` loggers and, from WARNING up, every other logger (redis, sqlalchemy, asyncio and
other libraries, which log to the root logger) go through the same queue, so the redaction
filter sees every record before any handler does.

The queue is bounded. When the writer thread falls behind, for example on a stalled disk,
records are dropped and counted rather than held in memory or waited for, because the event
loop logs and must never block on the disk.
"""

from __future__ import annotations

import logging
import queue
from logging.handlers import QueueHandler, QueueListener, WatchedFileHandler
from pathlib import Path
from typing import Any

from asspng.log.maillog import MAILLOG_LOGGER
from asspng.log.redact import RedactionFilter

_APP_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_QUEUE_MAX = 10_000  # records waiting for the writer thread


class DroppingQueueHandler(QueueHandler):
    """A ``QueueHandler`` that never waits: a record that does not fit is dropped and counted.

    The next record that fits is preceded by a WARNING with the count. Counting is safe:
    ``Handler.handle`` holds the handler's lock around ``emit``.
    """

    def __init__(self, log_queue: queue.Queue[logging.LogRecord]) -> None:
        super().__init__(log_queue)
        self._bounded = log_queue
        self.dropped = 0

    def enqueue(self, record: logging.LogRecord) -> None:
        try:
            if self.dropped:
                self._bounded.put_nowait(self._dropped_record())
                self.dropped = 0
            self._bounded.put_nowait(record)
        except queue.Full:
            self.dropped += 1

    def _dropped_record(self) -> logging.LogRecord:
        return logging.LogRecord(__name__, logging.WARNING, __file__, 0,
                                 "%d log records dropped: the log writer fell behind",
                                 (self.dropped,), None)


class DrainingQueueListener(QueueListener):
    """A ``QueueListener`` whose ``stop()`` waits for room for its sentinel in a full queue,
    where the stock one fails with ``queue.Full``. ``stop()`` waits for the queue to drain
    anyway."""

    def __init__(self, log_queue: queue.Queue[Any], *handlers: logging.Handler,
                 respect_handler_level: bool = False) -> None:
        super().__init__(log_queue, *handlers, respect_handler_level=respect_handler_level)
        self._bounded = log_queue

    def enqueue_sentinel(self) -> None:
        self._bounded.put(self._sentinel)  # type: ignore[attr-defined]


class _NotMaillog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name != MAILLOG_LOGGER


class _OnlyMaillog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name == MAILLOG_LOGGER


# Handlers installed per listener, so shutdown_logging can undo exactly its own work:
# (asspng handler, root handler, asspng propagate, asspng level, maillog level).
_installed: dict[int, tuple[QueueHandler, QueueHandler, bool, int, int]] = {}


def _queue_handler(log_queue: queue.Queue[logging.LogRecord]) -> QueueHandler:
    handler = DroppingQueueHandler(log_queue)
    handler.addFilter(RedactionFilter())
    return handler


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

    log_queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=LOG_QUEUE_MAX)
    qh = _queue_handler(log_queue)
    # Libraries: their warnings and errors only, through the same redaction.
    third_party = _queue_handler(log_queue)
    third_party.setLevel(logging.WARNING)
    listener = DrainingQueueListener(log_queue, *handlers, respect_handler_level=True)

    root = logging.getLogger("asspng")
    mail_logger = logging.getLogger(MAILLOG_LOGGER)
    _installed[id(listener)] = (qh, third_party, root.propagate, root.level, mail_logger.level)
    root.setLevel(min(logging.INFO, app.level))
    root.addHandler(qh)
    root.propagate = False
    mail_logger.setLevel(logging.INFO)
    logging.getLogger().addHandler(third_party)
    listener.start()
    return listener


def shutdown_logging(listener: QueueListener) -> None:
    """Stop the writer thread (flushing the queue) and remove what configure installed."""
    saved = _installed.pop(id(listener), None)
    if saved is not None:
        qh, third_party, propagate, level, mail_level = saved
        logging.getLogger().removeHandler(third_party)
        root = logging.getLogger("asspng")
        root.removeHandler(qh)
        root.propagate = propagate
        root.setLevel(level)
        logging.getLogger(MAILLOG_LOGGER).setLevel(mail_level)
    listener.stop()
    for h in listener.handlers:
        h.close()
    listener.handlers = ()
