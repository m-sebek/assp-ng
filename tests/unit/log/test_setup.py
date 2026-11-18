# SPDX-License-Identifier: GPL-3.0-or-later
import logging
import queue
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from asspng.log.maillog import log_maillog
from asspng.log.setup import (
    LOG_QUEUE_MAX,
    DrainingQueueListener,
    DroppingQueueHandler,
    configure_logging,
    shutdown_logging,
)
from tests.unit.log.test_maillog import PASSWORD, make

pytestmark = pytest.mark.usefixtures("_clean")


@pytest.fixture
def _clean() -> Iterator[None]:
    yield
    for name in ("asspng", "asspng.maillog"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(logging.NOTSET)


def test_queue_listener_writes_files(tmp_path: Path) -> None:
    listener = configure_logging("INFO", tmp_path, journal=False)
    try:
        logging.getLogger("asspng.proxy").info("hello app")
        logging.getLogger("asspng.proxy").debug("too quiet")
        logging.getLogger("asspng.proxy").info("AUTH PLAIN %s", PASSWORD)
        log_maillog(make())
    finally:
        shutdown_logging(listener)
    app = (tmp_path / "assp-ng.log").read_text()
    mail = (tmp_path / "maillog.log").read_text()
    assert "INFO asspng.proxy: hello app" in app
    assert "too quiet" not in app
    assert "s=7f3a9c2e" not in app
    assert mail.splitlines()[0].startswith("2026-11-12T17:30:01+01:00 mx1 s=7f3a9c2e")
    assert len(mail.splitlines()) == 1
    assert PASSWORD not in app + mail
    assert "AUTH PLAIN <redacted>" in app
    assert logging.getLogger("asspng").handlers == []


def test_rotation_followed(tmp_path: Path) -> None:
    listener = configure_logging("INFO", tmp_path, journal=False)
    try:
        logging.getLogger("asspng.a").info("before")
        _flush(tmp_path / "assp-ng.log", "before")
        (tmp_path / "assp-ng.log").rename(tmp_path / "assp-ng.log.1")
        logging.getLogger("asspng.a").info("after")
    finally:
        shutdown_logging(listener)
    assert "after" in (tmp_path / "assp-ng.log").read_text()
    assert "before" in (tmp_path / "assp-ng.log.1").read_text()


def _flush(path: Path, needle: str) -> None:
    import time
    for _ in range(200):
        if path.exists() and needle in path.read_text():
            return
        time.sleep(0.01)
    raise AssertionError("log line not written")


def test_repeated_configure_does_not_leak(tmp_path: Path) -> None:
    for i in range(3):
        d = tmp_path / str(i)
        d.mkdir()
        shutdown_logging(configure_logging("INFO", d, journal=False))
    assert logging.getLogger("asspng").handlers == []


def test_third_party_warnings_reach_the_file_redacted(tmp_path: Path) -> None:
    # Libraries log to their own loggers (redis, sqlalchemy, asyncio). Without a handler on
    # the root logger their records went to logging's last-resort stderr handler, unredacted.
    root = logging.getLogger()
    before = list(root.handlers)
    listener = configure_logging("INFO", tmp_path, journal=False)
    try:
        logging.getLogger("redis.asyncio").warning("AUTH PLAIN %s", PASSWORD)
        logging.getLogger("sqlalchemy.pool").info("third-party info stays out")
    finally:
        shutdown_logging(listener)
    app = (tmp_path / "assp-ng.log").read_text()
    assert "WARNING redis.asyncio: AUTH PLAIN <redacted>" in app
    assert PASSWORD not in app
    assert "third-party info stays out" not in app
    assert root.handlers == before


def test_third_party_records_stay_out_of_the_maillog(tmp_path: Path) -> None:
    listener = configure_logging("INFO", tmp_path, journal=False)
    try:
        logging.getLogger("asyncio").error("Task exception was never retrieved")
    finally:
        shutdown_logging(listener)
    assert "Task exception" in (tmp_path / "assp-ng.log").read_text()
    assert (tmp_path / "maillog.log").read_text() == ""


def test_journal_handler_added(tmp_path: Path) -> None:
    from systemd.journal import JournalHandler
    listener = configure_logging("INFO", tmp_path, journal=True)
    try:
        j = [h for h in listener.handlers if isinstance(h, JournalHandler)]
        assert len(j) == 1 and j[0].level == logging.WARNING
    finally:
        shutdown_logging(listener)


def test_shutdown_restores_logger_state(tmp_path: Path) -> None:
    app, mail = logging.getLogger("asspng"), logging.getLogger("asspng.maillog")
    app.setLevel(logging.ERROR)
    mail.setLevel(logging.WARNING)
    before = (app.propagate, app.level, mail.propagate, mail.level, list(app.handlers))
    listener = configure_logging("DEBUG", tmp_path, journal=False)
    assert app.propagate is False and mail.level == logging.INFO
    shutdown_logging(listener)
    assert (app.propagate, app.level, mail.propagate, mail.level, list(app.handlers)) == before


def test_auth_flag_and_exception_reach_file_redacted(tmp_path: Path) -> None:
    listener = configure_logging("INFO", tmp_path, journal=False)
    try:
        log = logging.getLogger("asspng.proxy")
        log.info("%s", PASSWORD, extra={"auth": True})
        try:
            raise ValueError(f"AUTH PLAIN {PASSWORD}")
        except ValueError:
            log.exception("failed")
    finally:
        shutdown_logging(listener)
    app = (tmp_path / "assp-ng.log").read_text()
    assert PASSWORD not in app
    assert "<redacted>" in app and "ValueError: AUTH PLAIN <redacted>" in app


def test_log_queue_is_bounded(tmp_path: Path) -> None:
    listener = configure_logging("INFO", tmp_path, journal=False)
    try:
        assert isinstance(listener.queue, queue.Queue)
        assert listener.queue.maxsize == LOG_QUEUE_MAX == 10_000
    finally:
        shutdown_logging(listener)


def record(message: str) -> logging.LogRecord:
    return logging.makeLogRecord({"name": "asspng.test", "levelno": logging.INFO,
                                  "levelname": "INFO", "msg": message})


def test_full_log_queue_drops_and_counts_instead_of_waiting() -> None:
    # A stalled disk stops the writer thread: the queue must neither grow without limit nor
    # block the event loop that logs.
    log_queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=3)
    handler = DroppingQueueHandler(log_queue)
    for i in range(5):
        handler.handle(record(f"line {i}"))
    assert [log_queue.get_nowait().getMessage() for _ in range(3)] == [
        "line 0", "line 1", "line 2"]
    handler.handle(record("after"))
    warning, after = log_queue.get_nowait(), log_queue.get_nowait()
    assert warning.levelno == logging.WARNING
    assert warning.getMessage() == "2 log records dropped: the log writer fell behind"
    assert after.getMessage() == "after"
    assert log_queue.empty()


def test_listener_stop_waits_for_room_in_a_full_queue() -> None:
    gate = threading.Event()

    class Slow(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            gate.wait(5)

    log_queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=1)
    listener = DrainingQueueListener(log_queue, Slow())
    listener.start()
    log_queue.put(record("taken by the writer"))
    deadline = time.monotonic() + 5
    while not log_queue.empty() and time.monotonic() < deadline:
        time.sleep(0.01)
    log_queue.put(record("fills the queue"))
    stopper = threading.Thread(target=listener.stop)
    stopper.start()
    time.sleep(0.2)
    assert stopper.is_alive()  # waits for room instead of failing with queue.Full
    gate.set()
    stopper.join(5)
    assert not stopper.is_alive()
