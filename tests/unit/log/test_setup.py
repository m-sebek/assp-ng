# SPDX-License-Identifier: GPL-3.0-or-later
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from asspng.log.maillog import log_maillog
from asspng.log.setup import configure_logging, shutdown_logging
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
