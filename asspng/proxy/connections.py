# SPDX-License-Identifier: GPL-3.0-or-later
"""In-process count of open client connections, per network key."""


class ConnectionTracker:
    """Counts open connections per network. Per instance; counts never go negative."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._total = 0

    def acquire(self, net: str) -> int:
        """Register a connection from ``net`` and return its new count."""
        count = self._counts.get(net, 0) + 1
        self._counts[net] = count
        self._total += 1
        return count

    def release(self, net: str) -> None:
        """Forget one connection from ``net``; unknown networks are ignored."""
        count = self._counts.get(net, 0)
        if count <= 0:
            return
        if count == 1:
            del self._counts[net]
        else:
            self._counts[net] = count - 1
        self._total -= 1

    def count(self, net: str) -> int:
        return self._counts.get(net, 0)

    @property
    def total(self) -> int:
        return self._total
