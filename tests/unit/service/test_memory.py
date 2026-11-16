# SPDX-License-Identifier: GPL-3.0-or-later
import logging

import pytest

from asspng.service import memory
from asspng.service import systemd as sd
from asspng.service.memory import Housekeeper, MemoryGuard, malloc_trim, rss_mb


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_rss_mb_reads_statm() -> None:
    value = rss_mb()
    assert 1 < value < 100000


def test_guard() -> None:
    values = iter([100.0, 400.0, 360.0])
    guard = MemoryGuard(360, rss=lambda: next(values))
    assert guard.over_limit() is False
    assert guard.over_limit() is True
    assert guard.over_limit() is False


def test_malloc_trim_returns_bool(monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(malloc_trim(), bool)

    def boom(name: str) -> object:
        raise OSError("no libc")

    monkeypatch.setattr(memory.ctypes, "CDLL", boom)
    assert malloc_trim() is False

    class NoTrim:
        pass

    monkeypatch.setattr(memory.ctypes, "CDLL", lambda name: NoTrim())
    assert malloc_trim() is False


def test_housekeeper_idle_and_interval(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    clock = Clock()
    sessions = [3]
    expired: list[int] = []
    hk = Housekeeper(lambda: sessions[0], [lambda: expired.append(1)], clock,
                     idle_after_s=60, interval_s=600, low_load=10)
    assert hk.tick() is False            # sessions busy but below low_load, interval not due
    clock.now = 600
    assert hk.tick() is True             # interval under low load
    assert expired == [1]
    assert "rss" in caplog.text.lower()
    clock.now = 700
    assert hk.tick() is False
    sessions[0] = 50                     # heavy load: interval trigger suppressed
    clock.now = 2000
    assert hk.tick() is False
    sessions[0] = 0
    clock.now = 2010
    assert hk.tick() is True             # interval due again; idle period starts
    clock.now = 2069
    assert hk.tick() is False
    clock.now = 2070
    assert hk.tick() is True             # idle for 60 s
    clock.now = 2100
    assert hk.tick() is False            # only once per idle period
    sessions[0] = 1
    hk.tick()
    sessions[0] = 0
    clock.now = 2200
    hk.tick()
    clock.now = 2260
    assert hk.tick() is True             # a new idle period


def test_housekeeper_cache_failure_does_not_stop_tick(
        caplog: pytest.LogCaptureFixture) -> None:
    clock = Clock()
    calls: list[str] = []

    def bad() -> None:
        raise RuntimeError("cache broke")

    hk = Housekeeper(lambda: 0, [bad, lambda: calls.append("ok")], clock,
                     idle_after_s=0, interval_s=600)
    assert hk.tick() is True
    assert calls == ["ok"]
    assert "cache broke" in caplog.text or "RuntimeError" in caplog.text


def test_notify_noop_without_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    calls: list[str] = []
    monkeypatch.setattr(sd, "_daemon_notify", calls.append)
    sd.notify("READY=1")
    assert calls == []


def test_notify_calls_when_socket_set_and_never_raises(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent/sock")
    calls: list[str] = []
    monkeypatch.setattr(sd, "_daemon_notify", calls.append)
    sd.notify("WATCHDOG=1")
    assert calls == ["WATCHDOG=1"]

    def boom(message: str) -> None:
        raise OSError("bad socket")

    monkeypatch.setattr(sd, "_daemon_notify", boom)
    sd.notify("READY=1")
    monkeypatch.setattr(sd, "_daemon_notify", None)
    sd.notify("READY=1")


def test_housekeeper_order(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(memory.gc, "collect", lambda *a: order.append("gc") or 0)
    monkeypatch.setattr(memory, "malloc_trim", lambda: order.append("trim") or True)
    hk = Housekeeper(lambda: 0, [lambda: order.append("c1"), lambda: order.append("c2")],
                     Clock(), idle_after_s=0, interval_s=600)
    assert hk.tick() is True
    assert order == ["c1", "c2", "gc", "trim"]


def test_housekeeper_sessions_equal_low_load_no_interval_tick() -> None:
    clock = Clock()
    sessions = [10]
    hk = Housekeeper(lambda: sessions[0], [], clock, idle_after_s=60, interval_s=600,
                     low_load=10)
    clock.now = 5000
    assert hk.tick() is False
    sessions[0] = 9
    assert hk.tick() is True
