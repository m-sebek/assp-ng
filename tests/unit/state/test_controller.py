# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from asspng.state import MemoryStore, StateError, StateStore, StateTypeError
from asspng.state.controller import StateController, StateMode
from tests.conftest import FakeClock

N, D, T = StateMode.NORMAL, StateMode.DEGRADED, StateMode.TEMPFAIL


class FlakyStore(MemoryStore):
    """A working ``MemoryStore`` that raises ``error`` from every operation while set."""

    def __init__(self, clock: FakeClock) -> None:
        super().__init__(max_entries=1000, clock=clock.now)
        self.error: BaseException | None = None
        self.calls = 0

    def _hit(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error

    async def incr_window(self, key: str, window_s: int) -> int:
        self._hit()
        return await super().incr_window(key, window_s)

    async def incr(self, key: str, ttl_s: int | None) -> int:
        self._hit()
        return await super().incr(key, ttl_s)

    async def get(self, key: str) -> str | None:
        self._hit()
        return await super().get(key)

    async def get_hash(self, key: str) -> dict[str, str]:
        self._hit()
        return await super().get_hash(key)

    async def set_hash(self, key: str, values: Mapping[str, str], ttl_s: int | None) -> None:
        self._hit()
        await super().set_hash(key, values, ttl_s)

    async def delete(self, *keys: str) -> int:
        self._hit()
        return await super().delete(*keys)

    async def keys(self, pattern: str) -> list[str]:
        self._hit()
        return await super().keys(pattern)

    async def ttl(self, key: str) -> int | None:
        self._hit()
        return await super().ttl(key)

    async def ping(self) -> None:
        self._hit()

    async def publish(self, channel: str, message: str) -> None:
        self._hit()


@dataclass
class Rig:
    ctl: StateController
    primary: FlakyStore
    fallback: FlakyStore
    changes: list[tuple[StateMode, StateMode, str]] = field(default_factory=list)

    def primary_down(self, error: BaseException | None = None) -> None:
        self.primary.error = error if error is not None else StateError("redis down")

    async def degrade(self) -> None:
        self.primary_down()
        for _ in range(3):
            await self.ctl.incr("n", None)
        assert self.ctl.mode is D


def make(clock: FakeClock, **kwargs: Any) -> Rig:
    primary, fallback = FlakyStore(clock), FlakyStore(clock)
    changes: list[tuple[StateMode, StateMode, str]] = []
    ctl = StateController(
        primary,
        fallback,
        clock=clock.now,
        on_change=lambda old, new, reason: changes.append((old, new, reason)),
        **kwargs,
    )
    return Rig(ctl, primary, fallback, changes)


# One call of every StateStore protocol method.
CALLS: dict[str, Callable[[StateStore], Awaitable[object]]] = {
    "incr_window": lambda s: s.incr_window("k", 60),
    "incr": lambda s: s.incr("k", 60),
    "get": lambda s: s.get("k"),
    "get_hash": lambda s: s.get_hash("h"),
    "set_hash": lambda s: s.set_hash("h", {"a": "1"}, 60),
    "delete": lambda s: s.delete("k", "h"),
    "keys": lambda s: s.keys("*"),
    "ttl": lambda s: s.ttl("k"),
    "ping": lambda s: s.ping(),
    "publish": lambda s: s.publish("events", "hello"),
}


async def test_single_failure_stays_normal_uses_fallback(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    await rig.fallback.incr("k", None)  # the fallback already holds k=1
    rig.primary_down()
    assert await rig.ctl.incr("k", None) == 2
    assert rig.ctl.mode is N
    assert rig.changes == []
    rig.primary.error = None
    assert await rig.ctl.get("k") is None  # healthy again: answered by primary
    assert rig.ctl.mode is N


async def test_any_exception_from_primary_is_a_failure(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    rig.primary_down(ConnectionResetError("boom"))
    assert await rig.ctl.incr("k", None) == 1
    rig.primary_down(RuntimeError("bug"))
    await rig.ctl.incr("k", None)
    assert rig.ctl.mode is N
    rig.primary_down(OSError("unreachable"))
    assert await rig.ctl.incr("k", None) == 3
    assert rig.ctl.mode is D


async def test_three_failures_degrade(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    rig.primary_down()
    assert await rig.ctl.incr("k", None) == 1
    assert await rig.ctl.incr("k", None) == 2
    assert rig.ctl.mode is N
    assert await rig.ctl.incr("k", None) == 3  # the switching operation is still answered
    assert rig.ctl.mode is D
    assert rig.changes == [(N, D, "3 consecutive redis failures")]
    rig.primary.error = None
    primary_calls = rig.primary.calls
    assert await rig.ctl.incr("k", None) == 4  # DEGRADED: primary is not used any more
    assert rig.primary.calls == primary_calls


async def test_failures_to_degrade_is_configurable(fake_clock: FakeClock) -> None:
    rig = make(fake_clock, failures_to_degrade=5)
    rig.primary_down()
    for _ in range(4):
        await rig.ctl.incr("k", None)
    assert rig.ctl.mode is N
    await rig.ctl.incr("k", None)
    assert rig.changes == [(N, D, "5 consecutive redis failures")]


async def test_two_seconds_degrade(fake_clock: FakeClock) -> None:
    rig = make(fake_clock, failures_to_degrade=100)
    rig.primary_down()
    await rig.ctl.incr("k", None)
    fake_clock.advance(1.5)
    await rig.ctl.incr("k", None)
    assert rig.ctl.mode is N
    fake_clock.advance(0.5)
    assert await rig.ctl.incr("k", None) == 3
    assert rig.ctl.mode is D
    assert rig.changes == [(N, D, "redis unreachable for 2.0s")]


async def test_success_resets_failure_count_and_time(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    rig.primary_down()
    await rig.ctl.incr("k", None)
    await rig.ctl.incr("k", None)
    rig.primary.error = None
    await rig.ctl.get("k")
    fake_clock.advance(10)
    rig.primary_down()
    await rig.ctl.incr("k", None)  # 1st failure again, and the 2 s window starts anew
    await rig.ctl.incr("k", None)
    assert rig.ctl.mode is N
    assert rig.changes == []


async def test_strict_goes_tempfail(fake_clock: FakeClock) -> None:
    rig = make(fake_clock, strict=True)
    rig.primary_down()
    assert await rig.ctl.incr("k", None) == 1
    assert await rig.ctl.incr("k", None) == 2
    with pytest.raises(StateError, match="TEMPFAIL"):
        await rig.ctl.incr("k", None)
    assert rig.ctl.mode is T
    assert rig.changes == [(N, T, "3 consecutive redis failures")]
    assert await rig.fallback.get("k") == "2"  # the switching operation was not applied


async def test_strict_time_limit_goes_tempfail(fake_clock: FakeClock) -> None:
    rig = make(fake_clock, strict=True, unreachable_s=1.0)
    rig.primary_down()
    await rig.ctl.incr("k", None)
    fake_clock.advance(1.0)
    with pytest.raises(StateError):
        await rig.ctl.incr("k", None)
    assert rig.changes == [(N, T, "redis unreachable for 1.0s")]


async def test_fallback_error_tempfail(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    await rig.degrade()
    rig.fallback.error = MemoryError()
    with pytest.raises(StateError, match="TEMPFAIL"):
        await rig.ctl.get("n")
    assert rig.ctl.mode is T
    assert rig.changes[-1] == (D, T, "fallback store failed")


async def test_fallback_error_in_normal_tempfails(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    rig.primary_down()
    rig.fallback.error = StateError("memory broken")
    with pytest.raises(StateError, match="TEMPFAIL"):
        await rig.ctl.incr("k", None)
    assert rig.ctl.mode is T
    assert rig.changes == [(N, T, "fallback store failed")]


async def test_type_error_from_primary_is_not_a_failure(
    fake_clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    rig = make(fake_clock)
    await rig.primary.set_hash("secret-key", {"a": "1"}, None)
    rig.primary_down()
    await rig.ctl.incr("k", None)
    await rig.ctl.incr("k", None)  # 2 failures so far
    rig.primary.error = None
    caplog.clear()  # drop the WARNINGs of the 2 failures
    with caplog.at_level(logging.ERROR, logger="asspng.state.controller"):
        for _ in range(3):
            with pytest.raises(StateTypeError):
                await rig.ctl.get("secret-key")  # propagates: not answered by fallback
    assert rig.ctl.mode is N
    assert rig.fallback.calls == 2
    assert [r.levelno for r in caplog.records] == [logging.ERROR] * 3
    assert "get" in caplog.records[0].getMessage()
    assert "StateTypeError" in caplog.records[0].getMessage()
    assert all("secret-key" not in r.getMessage() for r in caplog.records)
    rig.primary_down()
    await rig.ctl.incr("k", None)  # the count was not reset: this is the 3rd failure
    assert rig.changes == [(N, D, "3 consecutive redis failures")]


async def test_type_error_from_fallback_when_degraded_is_not_tempfail(
    fake_clock: FakeClock,
) -> None:
    rig = make(fake_clock)
    await rig.degrade()
    await rig.ctl.set_hash("h", {"a": "1"}, None)
    with pytest.raises(StateTypeError):
        await rig.ctl.get("h")
    assert rig.ctl.mode is D
    assert rig.changes == [(N, D, "3 consecutive redis failures")]
    assert await rig.ctl.get_hash("h") == {"a": "1"}  # still served from memory


async def test_type_error_from_fallback_in_normal_is_not_tempfail(
    fake_clock: FakeClock,
) -> None:
    rig = make(fake_clock)
    await rig.fallback.set_hash("h", {"a": "1"}, None)
    rig.primary_down()
    with pytest.raises(StateTypeError):
        await rig.ctl.get("h")
    assert rig.ctl.mode is N
    assert rig.changes == []


@pytest.mark.parametrize("name", list(CALLS))
async def test_tempfail_raises_without_touching_stores(fake_clock: FakeClock, name: str) -> None:
    rig = make(fake_clock)
    rig.ctl.force_tempfail("test")
    with pytest.raises(StateError, match=r"^state unavailable \(TEMPFAIL\)$"):
        await CALLS[name](rig.ctl)
    assert (rig.primary.calls, rig.fallback.calls) == (0, 0)


@pytest.mark.parametrize("name", list(CALLS))
async def test_every_method_falls_back_on_primary_failure(
    fake_clock: FakeClock, name: str
) -> None:
    rig = make(fake_clock)
    rig.primary_down()
    await CALLS[name](rig.ctl)
    assert (rig.primary.calls, rig.fallback.calls) == (1, 1)


@pytest.mark.parametrize("name", list(CALLS))
async def test_every_method_uses_only_fallback_when_degraded(
    fake_clock: FakeClock, name: str
) -> None:
    rig = make(fake_clock)
    await rig.degrade()
    rig.primary.error = None
    before = (rig.primary.calls, rig.fallback.calls)
    await CALLS[name](rig.ctl)
    assert (rig.primary.calls, rig.fallback.calls) == (before[0], before[1] + 1)


async def test_methods_pass_arguments_and_results_through(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    ctl = rig.ctl
    assert await ctl.incr_window("w", 30) == 1
    assert await ctl.incr("c", None) == 1
    assert await ctl.get("c") == "1"
    await ctl.set_hash("h", {"a": "1"}, 60)
    assert await ctl.get_hash("h") == {"a": "1"}
    assert await ctl.ttl("w") == 30
    assert sorted(await ctl.keys("*")) == ["c", "h", "w"]
    assert await ctl.delete("c", "h", "missing") == 2
    await ctl.ping()
    await ctl.publish("events", "x")
    assert sorted(await rig.primary.keys("*")) == ["w"]
    assert rig.fallback.calls == 0


async def test_in_flight_failure_does_not_leave_tempfail(
    fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = make(fake_clock, failures_to_degrade=1)
    gate = asyncio.Event()

    async def slow_failing_incr(key: str, ttl_s: int | None) -> int:
        await gate.wait()
        raise StateError("redis timeout")

    monkeypatch.setattr(rig.primary, "incr", slow_failing_incr)
    task = asyncio.create_task(rig.ctl.incr("k", None))
    await asyncio.sleep(0)  # the operation now waits on primary
    rig.ctl.force_tempfail("memory soft limit reached")
    gate.set()
    with pytest.raises(StateError, match="TEMPFAIL"):
        await task
    assert rig.ctl.mode is T
    assert rig.changes == [(N, T, "memory soft limit reached")]
    assert rig.fallback.calls == 0


async def test_cancellation_is_not_a_failure(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    rig.primary_down(asyncio.CancelledError())
    for _ in range(3):
        with pytest.raises(asyncio.CancelledError):
            await rig.ctl.incr("k", None)
    assert rig.ctl.mode is N
    assert rig.fallback.calls == 0


async def test_probe_recovers_and_clears(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    await rig.degrade()
    assert await rig.fallback.get("n") == "3"
    rig.primary.error = None
    await rig.ctl.probe()
    assert rig.ctl.mode is N
    assert rig.changes[-1] == (D, N, "redis recovered")
    assert await rig.fallback.get("n") is None  # memory state is discarded
    assert await rig.ctl.incr("n", None) == 1  # answered by primary again
    rig.primary_down()
    await rig.ctl.incr("n", None)
    await rig.ctl.incr("n", None)
    assert rig.ctl.mode is N  # failure counters were reset on recovery


async def test_probe_recovers_from_tempfail(fake_clock: FakeClock) -> None:
    rig = make(fake_clock, strict=True)
    rig.primary_down()
    await rig.ctl.incr("k", None)
    rig.primary.error = None
    rig.ctl.force_tempfail("memory soft limit reached")
    await rig.ctl.probe()
    assert rig.ctl.mode is N
    assert rig.changes == [(N, T, "memory soft limit reached"), (T, N, "redis recovered")]
    assert await rig.fallback.get("k") is None


async def test_probe_failure_stays_silent(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    await rig.degrade()
    changes = list(rig.changes)
    await rig.ctl.probe()
    await rig.ctl.probe()
    assert rig.ctl.mode is D
    assert rig.changes == changes
    assert await rig.fallback.get("n") == "3"  # memory state kept


async def test_concurrent_probes_recover_once(
    fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = make(fake_clock)
    await rig.degrade()
    rig.primary.error = None
    gates = [asyncio.Event(), asyncio.Event()]
    waiting = list(gates)

    async def gated_ping() -> None:
        await waiting.pop(0).wait()

    monkeypatch.setattr(rig.primary, "ping", gated_ping)
    first = asyncio.create_task(rig.ctl.probe())
    second = asyncio.create_task(rig.ctl.probe())
    await asyncio.sleep(0)  # both probes now wait for their ping
    gates[0].set()
    await first
    rig.primary_down()
    await rig.ctl.incr("k", None)  # NORMAL again: this failure is answered by fallback
    gates[1].set()
    await second  # must not clear fallback or notify a second time
    assert rig.changes[1:] == [(D, N, "redis recovered")]
    assert await rig.fallback.get("k") == "1"


async def test_probe_in_normal_does_nothing(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    await rig.fallback.incr("k", None)
    await rig.ctl.probe()
    assert rig.primary.calls == 0
    assert await rig.fallback.get("k") == "1"
    assert rig.changes == []


async def test_force_tempfail(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    rig.ctl.force_tempfail("operator request")
    rig.ctl.force_tempfail("again")  # already TEMPFAIL: no-op
    assert rig.ctl.mode is T
    assert rig.changes == [(N, T, "operator request")]

    rig = make(fake_clock)
    await rig.degrade()
    rig.ctl.force_tempfail("memory soft limit reached")
    assert rig.changes[-1] == (D, T, "memory soft limit reached")


async def test_on_change_called_with_reason(fake_clock: FakeClock) -> None:
    rig = make(fake_clock)
    await rig.degrade()
    rig.fallback.error = StateError("memory broken")
    with pytest.raises(StateError):
        await rig.ctl.get("n")
    with pytest.raises(StateError):  # TEMPFAIL again: no further change
        await rig.ctl.get("n")
    rig.primary.error = None
    await rig.ctl.probe()
    await rig.ctl.probe()  # NORMAL already: no further change
    assert rig.changes == [
        (N, D, "3 consecutive redis failures"),
        (D, T, "fallback store failed"),
        (T, N, "redis recovered"),
    ]


async def test_on_change_error_is_logged_and_ignored(
    fake_clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    primary, fallback = FlakyStore(fake_clock), FlakyStore(fake_clock)

    def broken(old: StateMode, new: StateMode, reason: str) -> None:
        raise RuntimeError("callback bug")

    ctl = StateController(
        primary, fallback, failures_to_degrade=1, clock=fake_clock.now, on_change=broken
    )
    primary.error = StateError("redis down")
    with caplog.at_level(logging.ERROR, logger="asspng.state.controller"):
        assert await ctl.incr("k", None) == 1
    assert ctl.mode is D
    assert [r.levelno for r in caplog.records] == [logging.ERROR]
    assert caplog.records[0].exc_info is not None


async def test_watchers_see_transitions_until_unwatched(
    fake_clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    """A session's debug tap watches the mode (spec 8.11); a failing watcher is logged and
    stops neither on_change nor the other watchers."""
    rig = make(fake_clock)
    seen: list[tuple[StateMode, StateMode, str]] = []

    def broken(old: StateMode, new: StateMode, reason: str) -> None:
        raise RuntimeError("watcher bug")

    unwatch = rig.ctl.watch(lambda old, new, reason: seen.append((old, new, reason)))
    unwatch_broken = rig.ctl.watch(broken)
    with caplog.at_level(logging.ERROR, logger="asspng.state.controller"):
        rig.ctl.force_tempfail("operator request")
    assert seen == rig.changes == [(N, T, "operator request")]
    assert len(caplog.records) == 1
    unwatch()
    unwatch_broken()
    unwatch()  # idempotent
    await rig.ctl.probe()
    assert rig.changes[-1] == (T, N, "redis recovered")
    assert seen == [(N, T, "operator request")]
