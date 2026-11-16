# SPDX-License-Identifier: GPL-3.0-or-later
"""In-process state store with TTLs and LRU eviction (the degraded-mode fallback)."""

import fnmatch
import math
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from asspng.state.base import StateStore, StateTypeError


@dataclass(slots=True)
class _Entry:
    value: int | dict[str, str]
    expires_at: float | None


class MemoryStore(StateStore):
    """Redis-like store in process memory.

    Expiry is applied lazily on access. When a new key would exceed ``max_entries``, expired
    keys are purged first, then the least recently used keys are evicted. ``max_entries``
    counts keys, not hash fields. ``ping`` and ``publish`` are no-ops (no cross-instance
    events exist in degraded mode).
    """

    def __init__(self, max_entries: int, clock: Callable[[], float]) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max = max_entries
        self._clock = clock
        self._data: OrderedDict[str, _Entry] = OrderedDict()
        # Lower bound on the smallest stored expires_at; a stale (too low) bound is safe.
        self._next_expiry = math.inf

    def clear(self) -> None:
        self._data.clear()
        self._next_expiry = math.inf

    def _live(self, key: str, touch: bool = True) -> _Entry | None:
        """Return the live entry for ``key`` (purging it if expired), optionally marking use."""
        entry = self._data.get(key)
        if entry is None:
            return None
        if entry.expires_at is not None and entry.expires_at < self._clock():
            del self._data[key]
            return None
        if touch:
            self._data.move_to_end(key)
        return entry

    def _purge_expired(self) -> None:
        """Drop expired entries; skipped entirely while nothing can have expired yet."""
        if self._clock() <= self._next_expiry:
            return
        self._scan_expired()

    def _scan_expired(self) -> None:
        now = self._clock()
        nxt = math.inf
        for key, entry in list(self._data.items()):
            if entry.expires_at is None:
                continue
            if entry.expires_at < now:
                del self._data[key]
            elif entry.expires_at < nxt:
                nxt = entry.expires_at
        self._next_expiry = nxt

    def _store(self, key: str, value: int | dict[str, str], expires_at: float | None) -> None:
        if expires_at is not None and expires_at < self._next_expiry:
            self._next_expiry = expires_at
        if key in self._data:
            self._data[key] = _Entry(value, expires_at)
            self._data.move_to_end(key)
            return
        if len(self._data) >= self._max:
            self._purge_expired()
            while len(self._data) >= self._max:
                self._data.popitem(last=False)
        self._data[key] = _Entry(value, expires_at)

    def _expiry(self, ttl_s: int | None) -> float | None:
        return None if ttl_s is None else self._clock() + ttl_s

    def _counter(self, key: str) -> tuple[int, float | None]:
        """Current value and expiry of a counter key (``(0, None)`` if missing)."""
        entry = self._live(key)
        if entry is None:
            return 0, None
        if not isinstance(entry.value, int):
            raise StateTypeError(f"wrong type for key {key!r}: not a counter")
        return entry.value, entry.expires_at

    async def incr_window(self, key: str, window_s: int) -> int:
        value, expires_at = self._counter(key)
        if expires_at is None and value == 0:
            expires_at = self._expiry(window_s)
        value += 1
        self._store(key, value, expires_at)
        return value

    async def incr(self, key: str, ttl_s: int | None) -> int:
        value, _ = self._counter(key)
        value += 1
        self._store(key, value, self._expiry(ttl_s))
        return value

    async def get(self, key: str) -> str | None:
        entry = self._live(key)
        if entry is None:
            return None
        if not isinstance(entry.value, int):
            raise StateTypeError(f"wrong type for key {key!r}: not a string")
        return str(entry.value)

    async def get_hash(self, key: str) -> dict[str, str]:
        entry = self._live(key)
        if entry is None:
            return {}
        if not isinstance(entry.value, dict):
            raise StateTypeError(f"wrong type for key {key!r}: not a hash")
        return dict(entry.value)

    async def set_hash(self, key: str, values: Mapping[str, str], ttl_s: int | None) -> None:
        if not values:  # Redis: an empty hash does not exist
            self._live(key, touch=False)
            self._data.pop(key, None)
            return
        self._store(key, dict(values), self._expiry(ttl_s))

    async def delete(self, *keys: str) -> int:
        removed = 0
        for key in keys:
            if self._live(key, touch=False) is not None:
                del self._data[key]
                removed += 1
        return removed

    async def keys(self, pattern: str) -> list[str]:
        self._purge_expired()
        return [k for k in self._data if fnmatch.fnmatchcase(k, pattern)]

    async def ttl(self, key: str) -> int | None:
        entry = self._live(key, touch=False)
        if entry is None or entry.expires_at is None:
            return None
        return max(1, math.ceil(entry.expires_at - self._clock() - 1e-9))

    async def ping(self) -> None:
        return None

    async def publish(self, channel: str, message: str) -> None:
        return None
