# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import logging
from pathlib import Path

import pytest

from asspng.domains import refresher as refresher_mod
from asspng.domains.index import DomainEntry, load_snapshot, save_snapshot
from asspng.domains.refresher import DomainHolder, DomainRefresher

ENTRIES = [DomainEntry("example.com", False)]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Source:
    def __init__(self, entries: list[DomainEntry] | None = None) -> None:
        self.entries = ENTRIES if entries is None else entries
        self.fail = False
        self.calls = 0

    def __call__(self) -> list[DomainEntry]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("mysql://user:secret@db down")
        return self.entries


def make(tmp_path: Path, source: Source, down: list[float] | None = None,
         clock: FakeClock | None = None,
         ) -> tuple[DomainRefresher, DomainHolder]:
    holder = DomainHolder()
    sink = down if down is not None else []
    r = DomainRefresher(source, holder, tmp_path / "snap.json", 60, sink.append,
                        clock=clock or FakeClock())
    return r, holder


async def test_db_success_writes_snapshot(tmp_path: Path) -> None:
    r, holder = make(tmp_path, Source())
    await r.refresh()
    assert holder.origin == "db"
    assert holder().is_local("example.com")
    assert load_snapshot(tmp_path / "snap.json") == ENTRIES


async def test_db_down_at_start_uses_snapshot(tmp_path: Path) -> None:
    save_snapshot(tmp_path / "snap.json", ENTRIES)
    source = Source()
    source.fail = True
    r, holder = make(tmp_path, source)
    await r.refresh()
    assert holder.origin == "snapshot"
    assert holder().available
    assert holder().is_local("example.com")


async def test_db_down_no_snapshot_unavailable(tmp_path: Path) -> None:
    source = Source()
    source.fail = True
    r, holder = make(tmp_path, source)
    await r.refresh()
    assert holder.origin == "none"
    assert not holder().available


async def test_failure_keeps_last_good(tmp_path: Path) -> None:
    source = Source()
    r, holder = make(tmp_path, source)
    await r.refresh()
    good = holder()
    save_snapshot(tmp_path / "snap.json", [DomainEntry("other.org", False)])
    source.fail = True
    await r.refresh()
    assert holder() is good
    assert holder.origin == "db"


async def test_event_triggers_refresh(tmp_path: Path) -> None:
    source = Source()
    r, _ = make(tmp_path, source)
    await r.on_event("domains-changed")
    assert source.calls == 1


async def test_db_down_duration_reported(tmp_path: Path) -> None:
    source = Source()
    source.fail = True
    clock = FakeClock()
    down: list[float] = []
    r, _ = make(tmp_path, source, down, clock)
    await r.refresh()
    clock.now += 400
    await r.refresh()
    assert down == [0.0, 400.0]


async def test_down_streak_resets_after_success(tmp_path: Path) -> None:
    source = Source()
    clock = FakeClock()
    down: list[float] = []
    r, _ = make(tmp_path, source, down, clock)
    source.fail = True
    await r.refresh()
    clock.now += 300
    await r.refresh()
    source.fail = False
    await r.refresh()
    assert down == [0.0, 300.0]
    clock.now += 1000
    source.fail = True
    await r.refresh()
    assert down == [0.0, 300.0, 0.0]


async def test_refresh_never_raises_and_hides_message(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    source = Source()
    source.fail = True
    r, _ = make(tmp_path, source)
    with caplog.at_level(logging.WARNING):
        await r.refresh()
    assert "RuntimeError" in caplog.text
    assert "secret" not in caplog.text


async def test_coalescing_three_concurrent_calls(tmp_path: Path) -> None:
    source = Source()
    r, _ = make(tmp_path, source)
    await asyncio.gather(r.refresh(), r.refresh(), r.refresh())
    assert 1 <= source.calls <= 2
    assert source.calls == 2


async def test_event_ignores_other_messages(tmp_path: Path) -> None:
    source = Source()
    r, _ = make(tmp_path, source)
    await r.on_event("something-else")
    await r.on_event("")
    assert source.calls == 0


async def test_on_event_never_raises(tmp_path: Path) -> None:
    source = Source()
    source.fail = True
    r, _ = make(tmp_path, source)
    await r.on_event("domains-changed")


async def test_on_db_down_exception_contained(tmp_path: Path) -> None:
    source = Source()
    source.fail = True
    holder = DomainHolder()

    def boom(_: float) -> None:
        raise ValueError("alert broke")

    r = DomainRefresher(source, holder, tmp_path / "snap.json", 60, boom)
    await r.refresh()
    assert holder.origin == "none"


async def test_snapshot_save_failure_keeps_new_index(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def bad_save(path: Path, entries: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(refresher_mod, "save_snapshot", bad_save)
    r, holder = make(tmp_path, Source())
    await r.refresh()
    assert holder.origin == "db"
    assert holder().is_local("example.com")


async def test_run_refreshes_periodically_and_propagates_cancel(tmp_path: Path) -> None:
    source = Source()
    holder = DomainHolder()
    r = DomainRefresher(source, holder, tmp_path / "snap.json", 0, lambda s: None)
    task = asyncio.create_task(r.run())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert source.calls >= 2


def test_holder_starts_unavailable() -> None:
    holder = DomainHolder()
    assert holder.origin == "none"
    assert not holder().available
