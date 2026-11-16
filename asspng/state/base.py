# SPDX-License-Identifier: GPL-3.0-or-later
"""The asynchronous state store protocol used for hot state (penalty box, rate limits)."""

from collections.abc import Mapping
from typing import Protocol, runtime_checkable


class StateError(Exception):
    """A state store operation failed (backend error, or ``StateTypeError``)."""


class StateTypeError(StateError):
    """The key holds a different type; a programming error, not an availability problem."""


@runtime_checkable
class StateStore(Protocol):
    """Hot-state storage. Keys are given without any backend prefix; values are ``str``."""

    async def incr_window(self, key: str, window_s: int) -> int:
        """Increment a counter; the expiry is set only when the key is created (fixed window)."""
        ...

    async def incr(self, key: str, ttl_s: int | None) -> int:
        """Increment a counter; the TTL is refreshed on every call (``None``: no expiry)."""
        ...

    async def get(self, key: str) -> str | None:
        """Return the value of a counter or string key, or ``None`` if missing."""
        ...

    async def get_hash(self, key: str) -> dict[str, str]:
        """Return a hash, or ``{}`` if the key is missing."""
        ...

    async def set_hash(self, key: str, values: Mapping[str, str], ttl_s: int | None) -> None:
        """Replace the whole hash (``ttl_s=None``: no expiry)."""
        ...

    async def delete(self, *keys: str) -> int:
        """Delete keys; return how many existing keys were removed."""
        ...

    async def keys(self, pattern: str) -> list[str]:
        """Return the keys matching a glob pattern, in unspecified order.

        Only the ``*`` and ``?`` wildcards are portable between ``MemoryStore`` and Redis.
        """
        ...

    async def ttl(self, key: str) -> int | None:
        """Remaining seconds (rounded up), or ``None`` for a missing key or no expiry."""
        ...

    async def ping(self) -> None:
        """Check that the backend is reachable; raise ``StateError`` otherwise."""
        ...

    async def publish(self, channel: str, message: str) -> None:
        """Publish an event to other instances."""
        ...
