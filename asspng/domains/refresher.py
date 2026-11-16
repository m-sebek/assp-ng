# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep the in-memory local-domain index fresh from the database.

The database is the source of truth. A JSON snapshot is the fallback when the database is
unreachable and nothing has been loaded yet. Failures are logged by exception type only,
because a database error message can carry connection details.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path

from asspng.domains.index import DomainEntry, DomainIndex, load_snapshot, save_snapshot

log = logging.getLogger(__name__)

EVENT_DOMAINS_CHANGED = "domains-changed"


class DomainHolder:
    """Current index plus where it came from: "db", "snapshot" or "none"."""

    def __init__(self) -> None:
        self.index: DomainIndex = DomainIndex.unavailable()
        self.origin: str = "none"

    def __call__(self) -> DomainIndex:
        return self.index


class DomainRefresher:
    def __init__(
        self,
        source_load: Callable[[], list[DomainEntry]],
        holder: DomainHolder,
        snapshot: Path,
        interval_s: int,
        on_db_down: Callable[[float], None],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source_load = source_load
        self._holder = holder
        self._snapshot = snapshot
        self._interval_s = interval_s
        self._on_db_down = on_db_down
        self._clock = clock
        self._lock = asyncio.Lock()
        self._pending = False
        self._loaded = False
        self._down_since: float | None = None

    async def refresh(self) -> None:
        """Reload the index. Never raises. Overlapping calls are coalesced."""
        self._pending = True
        async with self._lock:
            while self._pending:
                self._pending = False
                try:
                    await self._refresh_once()
                except Exception as exc:  # noqa: BLE001 - refresh must never raise
                    log.warning("domain refresh failed unexpectedly: %s", type(exc).__name__)

    async def _refresh_once(self) -> None:
        try:
            entries = await asyncio.to_thread(self._source_load)
        except Exception as exc:  # noqa: BLE001
            log.warning("loading local domains from the database failed: %s", type(exc).__name__)
            await self._on_failure()
            return
        self._down_since = None
        self._loaded = True
        self._holder.index = DomainIndex(entries)
        self._holder.origin = "db"
        try:
            await asyncio.to_thread(save_snapshot, self._snapshot, entries)
        except Exception as exc:  # noqa: BLE001
            log.warning("saving the local domain snapshot failed: %s", type(exc).__name__)

    async def _on_failure(self) -> None:
        now = self._clock()
        if self._down_since is None:
            self._down_since = now
        if not self._loaded:
            await self._fall_back()
        try:
            self._on_db_down(now - self._down_since)
        except Exception as exc:  # noqa: BLE001
            log.warning("on_db_down callback failed: %s", type(exc).__name__)

    async def _fall_back(self) -> None:
        try:
            entries = await asyncio.to_thread(load_snapshot, self._snapshot)
        except Exception as exc:  # noqa: BLE001
            log.warning("loading the local domain snapshot failed: %s", type(exc).__name__)
            entries = None
        if entries is None:
            self._holder.index = DomainIndex.unavailable()
            self._holder.origin = "none"
            return
        self._holder.index = DomainIndex(entries)
        self._holder.origin = "snapshot"

    async def run(self) -> None:
        """Refresh now, then every interval; stops only on cancellation."""
        while True:
            await self.refresh()
            await asyncio.sleep(self._interval_s)

    async def on_event(self, msg: str) -> None:
        if msg == EVENT_DOMAINS_CHANGED:
            await self.refresh()
