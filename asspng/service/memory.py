# SPDX-License-Identifier: GPL-3.0-or-later
"""Memory guard and idle housekeeping (design 8.7)."""

from __future__ import annotations

import ctypes
import gc
import logging
import os
from collections.abc import Callable, Sequence

log = logging.getLogger(__name__)


def rss_mb() -> float:
    """Resident set size of this process in MiB, from ``/proc/self/statm``."""
    with open("/proc/self/statm", encoding="ascii") as fh:
        resident_pages = int(fh.read().split()[1])
    return resident_pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)


def malloc_trim() -> bool:
    """Ask glibc to return freed memory to the OS; ``False`` when unavailable."""
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim(0)
    except (OSError, AttributeError):
        return False
    return True


class MemoryGuard:
    """Tells whether RSS is above the soft limit."""

    def __init__(self, soft_limit_mb: float, rss: Callable[[], float] = rss_mb) -> None:
        self._limit = soft_limit_mb
        self._rss = rss

    def over_limit(self) -> bool:
        return self._rss() > self._limit


class Housekeeper:
    """Expires caches, collects garbage and trims malloc when idle or periodically.

    ``tick()`` is called regularly by the application. It runs once per idle period after
    ``idle_after_s`` without sessions, and every ``interval_s`` while fewer than ``low_load``
    sessions are active. ``clock`` returns seconds.
    """

    def __init__(
        self,
        sessions: Callable[[], int],
        expire_caches: Sequence[Callable[[], None]],
        clock: Callable[[], float],
        idle_after_s: int,
        interval_s: int,
        low_load: int = 10,
    ) -> None:
        self._sessions = sessions
        self._caches = list(expire_caches)
        self._clock = clock
        self._idle_after = idle_after_s
        self._interval = interval_s
        self._low_load = low_load
        self._last_run = clock()
        self._idle_since: float | None = None
        self._idle_done = False

    def tick(self) -> bool:
        now = self._clock()
        count = self._sessions()
        due = False
        if count == 0:
            if self._idle_since is None:
                self._idle_since = now
            if not self._idle_done and now - self._idle_since >= self._idle_after:
                due = True
                self._idle_done = True
        else:
            self._idle_since = None
            self._idle_done = False
        if not due and count < self._low_load and now - self._last_run >= self._interval:
            due = True
        if not due:
            return False
        self._last_run = now
        self._run()
        return True

    def _run(self) -> None:
        before = self._rss_safe()
        for expire in self._caches:
            try:
                expire()
            except Exception:
                log.exception("cache expiry failed during housekeeping")
        gc.collect()
        trimmed = malloc_trim()
        log.debug("housekeeping: rss %.1f MB -> %.1f MB (malloc_trim=%s)",
                  before, self._rss_safe(), trimmed)

    @staticmethod
    def _rss_safe() -> float:
        try:
            return rss_mb()
        except (OSError, ValueError, IndexError):
            return -1.0
