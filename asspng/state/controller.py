# SPDX-License-Identifier: GPL-3.0-or-later
"""Degraded-mode controller: hot state on Redis with an in-memory fallback (spec 6.2)."""

import logging
from collections.abc import Awaitable, Callable, Mapping
from enum import Enum
from functools import partial
from typing import TypeVar

from asspng.state.base import StateError, StateStore, StateTypeError
from asspng.state.memory_store import MemoryStore

log = logging.getLogger(__name__)

_T = TypeVar("_T")
ModeCallback = Callable[["StateMode", "StateMode", str], None]
_TEMPFAIL_MESSAGE = "state unavailable (TEMPFAIL)"


class StateMode(Enum):
    """Where state operations go: Redis, memory only, or nowhere (mail is refused with 4xx)."""

    NORMAL = "normal"
    DEGRADED = "degraded"
    TEMPFAIL = "tempfail"


class StateController(StateStore):
    """``StateStore`` that switches between ``primary`` (Redis) and ``fallback`` (memory).

    - NORMAL: operations run on ``primary``. Any exception from it is a failure, and that
      operation is answered by ``fallback`` instead. The ``failures_to_degrade``-th
      consecutive failure, or a failure ``unreachable_s`` or more after the first one, switches
      to DEGRADED (TEMPFAIL when ``strict``). A ``primary`` success resets the failure count.
    - DEGRADED: operations run on ``fallback`` only. Any exception from it switches to TEMPFAIL.
    - TEMPFAIL: operations raise ``StateError`` without touching either store.

    In NORMAL and DEGRADED, a ``StateTypeError`` from either store (a bug, not an outage) is
    logged and propagates unchanged: it is not a failure, changes no counter and causes no
    transition.

    ``probe()``, called periodically, returns to NORMAL once ``primary`` answers a ping and
    discards the memory state. ``on_change(old, new, reason)`` is called once per transition,
    and so is every callback registered with ``watch()``.
    Cancellation (``asyncio.CancelledError``) is not a failure.
    """

    def __init__(
        self,
        primary: StateStore,
        fallback: MemoryStore,
        *,
        failures_to_degrade: int = 3,
        unreachable_s: float = 2.0,
        strict: bool = False,
        clock: Callable[[], float],
        on_change: Callable[[StateMode, StateMode, str], None],
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._failures_to_degrade = failures_to_degrade
        self._unreachable_s = unreachable_s
        self._mode_on_failure = StateMode.TEMPFAIL if strict else StateMode.DEGRADED
        self._clock = clock
        self._on_change = on_change
        self._watchers: set[ModeCallback] = set()
        self._mode = StateMode.NORMAL
        self._consecutive_failures = 0
        self._first_failure_at: float | None = None

    @property
    def mode(self) -> StateMode:
        return self._mode

    def watch(self, callback: ModeCallback) -> Callable[[], None]:
        """Also call ``callback(old, new, reason)`` on each transition, until the returned
        function is called (a session's debug tap, spec 8.11)."""
        self._watchers.add(callback)
        return partial(self._watchers.discard, callback)

    async def probe(self) -> None:
        """Return to NORMAL if ``primary`` is reachable again; a no-op in NORMAL."""
        if self._mode is StateMode.NORMAL:
            return
        try:
            await self._primary.ping()
        except Exception:
            return  # still down: keep the mode, and do not notify again
        self._recover()

    def _recover(self) -> None:
        if self._mode is StateMode.NORMAL:  # a concurrent probe recovered first
            return
        self._fallback.clear()  # memory state is discarded
        self._reset_failures()
        self._switch(StateMode.NORMAL, "redis recovered")

    def force_tempfail(self, reason: str) -> None:
        """Refuse mail temporarily until ``probe()`` finds ``primary`` healthy."""
        self._switch(StateMode.TEMPFAIL, reason)

    def _switch(self, new: StateMode, reason: str) -> None:
        old = self._mode
        if new is old:
            return
        self._mode = new
        for callback in (self._on_change, *self._watchers):
            try:
                callback(old, new, reason)
            except Exception:
                log.exception("state mode change callback failed")

    def _reset_failures(self) -> None:
        self._consecutive_failures = 0
        self._first_failure_at = None

    def _primary_failed(self, exc: Exception) -> None:
        log.warning("redis state operation failed (%s)", type(exc).__name__)
        if self._mode is not StateMode.NORMAL:
            return  # started before a concurrent switch, which already left NORMAL
        now = self._clock()
        self._consecutive_failures += 1
        if self._first_failure_at is None:
            self._first_failure_at = now
        elapsed = now - self._first_failure_at
        if self._consecutive_failures >= self._failures_to_degrade:
            self._switch(
                self._mode_on_failure, f"{self._consecutive_failures} consecutive redis failures"
            )
        elif elapsed >= self._unreachable_s:
            self._switch(self._mode_on_failure, f"redis unreachable for {elapsed:.1f}s")

    async def _run(self, name: str, op: Callable[[StateStore], Awaitable[_T]]) -> _T:
        """Run one store operation according to the current mode."""
        try:
            return await self._dispatch(op)
        except StateTypeError as exc:
            log.error("state %s hit a key of another type (%s): a bug, not an outage",
                      name, type(exc).__name__)
            raise

    async def _dispatch(self, op: Callable[[StateStore], Awaitable[_T]]) -> _T:
        if self._mode is StateMode.NORMAL:
            try:
                result = await op(self._primary)
            except StateTypeError:
                raise  # the store answered: no failure, counters untouched
            except Exception as exc:
                self._primary_failed(exc)
            else:
                self._reset_failures()
                return result
        if self._mode is StateMode.TEMPFAIL:
            raise StateError(_TEMPFAIL_MESSAGE)
        try:
            return await op(self._fallback)
        except StateTypeError:
            raise  # no TEMPFAIL: one wrong-type key must not refuse all mail
        except Exception as exc:
            log.error("memory state operation failed (%s)", type(exc).__name__)
            self._switch(StateMode.TEMPFAIL, "fallback store failed")
            raise StateError(_TEMPFAIL_MESSAGE) from exc

    async def incr_window(self, key: str, window_s: int) -> int:
        return await self._run("incr_window", lambda s: s.incr_window(key, window_s))

    async def incr(self, key: str, ttl_s: int | None) -> int:
        return await self._run("incr", lambda s: s.incr(key, ttl_s))

    async def get(self, key: str) -> str | None:
        return await self._run("get", lambda s: s.get(key))

    async def get_hash(self, key: str) -> dict[str, str]:
        return await self._run("get_hash", lambda s: s.get_hash(key))

    async def set_hash(self, key: str, values: Mapping[str, str], ttl_s: int | None) -> None:
        await self._run("set_hash", lambda s: s.set_hash(key, values, ttl_s))

    async def delete(self, *keys: str) -> int:
        return await self._run("delete", lambda s: s.delete(*keys))

    async def keys(self, pattern: str) -> list[str]:
        return await self._run("keys", lambda s: s.keys(pattern))

    async def ttl(self, key: str) -> int | None:
        return await self._run("ttl", lambda s: s.ttl(key))

    async def ping(self) -> None:
        await self._run("ping", lambda s: s.ping())

    async def publish(self, channel: str, message: str) -> None:
        await self._run("publish", lambda s: s.publish(channel, message))
