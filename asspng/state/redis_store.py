# SPDX-License-Identifier: GPL-3.0-or-later
"""Redis-backed state store and pub/sub event bus (shared between proxy instances)."""

import asyncio
import contextlib
import logging
import math
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, TypeVar

import redis.asyncio
from redis.exceptions import RedisError, ResponseError

from asspng.state.base import StateError, StateStore, StateTypeError

log = logging.getLogger(__name__)

_T = TypeVar("_T")
_GLOB_SPECIALS = "\\*?[]"
_SCAN_COUNT = 500
# Atomic INCR + TTL refresh that fails (with no side effects) on a non-string key.
_INCR_SCRIPT = """
local t = redis.call('TYPE', KEYS[1]).ok
if t ~= 'none' and t ~= 'string' then
  return redis.error_reply('WRONGTYPE Operation against a key holding the wrong kind of value')
end
local v = redis.call('INCR', KEYS[1])
if ARGV[1] == '' then
  redis.call('PERSIST', KEYS[1])
else
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return v
"""


# Atomic hash update (StateStore.update_hash) that fails with no side effects on a key of
# another type or a non-integer field. ARGV: ttl ('' = none), then three counted lists of
# field/value pairs: the additions, the values to set and the defaults.
_UPDATE_HASH_SCRIPT = """
local t = redis.call('TYPE', KEYS[1]).ok
if t ~= 'none' and t ~= 'hash' then
  return redis.error_reply('WRONGTYPE Operation against a key holding the wrong kind of value')
end
local i = 2
local function pairs_at()
  local n = tonumber(ARGV[i])
  local list = {}
  for j = 1, n do
    list[j] = {ARGV[i + 2 * j - 1], ARGV[i + 2 * j]}
  end
  i = i + 2 * n + 1
  return list
end
local adds, sets, defaults = pairs_at(), pairs_at(), pairs_at()
local results = {}
for j, pair in ipairs(adds) do
  local old = redis.call('HGET', KEYS[1], pair[1])
  local value = tonumber(old or '0')
  if value == nil or math.floor(value) ~= value then
    return redis.error_reply('WRONGTYPE hash field is not an integer')
  end
  results[j] = value + tonumber(pair[2])
end
for j, pair in ipairs(adds) do
  redis.call('HSET', KEYS[1], pair[1], results[j])
end
for _, pair in ipairs(sets) do
  redis.call('HSET', KEYS[1], pair[1], pair[2])
end
for _, pair in ipairs(defaults) do
  redis.call('HSETNX', KEYS[1], pair[1], pair[2])
end
if ARGV[1] == '' then
  redis.call('PERSIST', KEYS[1])
else
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return results
"""


def _pair_args(items: Mapping[str, object]) -> list[str]:
    args = [str(len(items))]
    for field, value in items.items():
        args += [field, str(value)]
    return args


def _escape_glob(text: str) -> str:
    return "".join("\\" + c if c in _GLOB_SPECIALS else c for c in text)


class RedisStore(StateStore):
    """``StateStore`` on Redis. All keys are stored under ``prefix``.

    Every backend, OS and timeout error is raised as ``StateError``, a ``WRONGTYPE`` reply as
    ``StateTypeError``; messages carry the operation and the exception type only, never keys
    or values.
    """

    def __init__(self, url: str, prefix: str, op_timeout_s: float) -> None:
        self._prefix = prefix
        self._timeout = op_timeout_s
        self._redis: Any = redis.asyncio.Redis.from_url(
            url,
            decode_responses=True,
            socket_timeout=op_timeout_s,
            socket_connect_timeout=op_timeout_s,
        )

    async def close(self) -> None:
        try:
            await self._redis.aclose()
        except (RedisError, OSError):
            pass

    async def _run(self, op: str, call: Callable[[], Awaitable[_T]]) -> _T:
        try:
            async with asyncio.timeout(self._timeout):
                return await call()
        except (RedisError, OSError, TimeoutError) as exc:
            if isinstance(exc, ResponseError) and str(exc).startswith("WRONGTYPE"):
                raise StateTypeError(f"redis {op} failed: wrong type") from exc
            raise StateError(f"redis {op} failed: {type(exc).__name__}") from exc

    async def _transaction(self, op: str, *commands: tuple[str, tuple[Any, ...]],
                           ) -> list[Any]:
        """Run ``commands`` (method name, args) in one MULTI/EXEC and return all results."""
        async def call() -> list[Any]:
            async with self._redis.pipeline(transaction=True) as pipe:
                for name, args in commands:
                    getattr(pipe, name)(*args)
                # raise_on_error=True would replace the reply text (WRONGTYPE) with a summary
                result: list[Any] = await pipe.execute(raise_on_error=False)
                for item in result:
                    if isinstance(item, Exception):
                        raise item
                return result

        return await self._run(op, call)

    async def incr_window(self, key: str, window_s: int) -> int:
        k = self._prefix + key
        results = await self._transaction(
            "incr_window", ("set", (k, 0, window_s, None, True)), ("incr", (k,)))
        return int(results[1])

    async def incr(self, key: str, ttl_s: int | None) -> int:
        k = self._prefix + key
        ttl_arg = "" if ttl_s is None else str(ttl_s)
        result: int = await self._run(
            "incr", lambda: self._redis.eval(_INCR_SCRIPT, 1, k, ttl_arg))
        return int(result)

    async def get(self, key: str) -> str | None:
        value: str | None = await self._run("get", lambda: self._redis.get(self._prefix + key))
        return value

    async def get_hash(self, key: str) -> dict[str, str]:
        value: dict[str, str] = await self._run(
            "get_hash", lambda: self._redis.hgetall(self._prefix + key))
        return value

    async def set_hash(self, key: str, values: Mapping[str, str], ttl_s: int | None) -> None:
        k = self._prefix + key
        commands: list[tuple[str, tuple[Any, ...]]] = [("delete", (k,))]
        if values:
            commands.append(("hset", (k, None, None, dict(values))))
            if ttl_s is not None:
                commands.append(("expire", (k, ttl_s)))
        await self._transaction("set_hash", *commands)

    async def update_hash(self, key: str, *, add: Mapping[str, int], values: Mapping[str, str],
                          defaults: Mapping[str, str], ttl_s: int | None) -> dict[str, int]:
        args = ["" if ttl_s is None else str(ttl_s), *_pair_args(add), *_pair_args(values),
                *_pair_args(defaults)]
        results: list[int] = await self._run(
            "update_hash",
            lambda: self._redis.eval(_UPDATE_HASH_SCRIPT, 1, self._prefix + key, *args))
        return {field: int(value) for field, value in zip(add, results)}

    async def delete(self, *keys: str) -> int:
        if not keys:
            return 0
        prefixed = [self._prefix + k for k in keys]
        removed: int = await self._run("delete", lambda: self._redis.delete(*prefixed))
        return removed

    async def keys(self, pattern: str) -> list[str]:
        match = _escape_glob(self._prefix) + pattern
        cut = len(self._prefix)

        async def scan() -> list[str]:
            found: set[str] = set()  # SCAN may return a key more than once
            async for key in self._redis.scan_iter(match=match, count=_SCAN_COUNT):
                found.add(key[cut:])
            return list(found)

        return await self._run("keys", scan)

    async def ttl(self, key: str) -> int | None:
        ms: int = await self._run("ttl", lambda: self._redis.pttl(self._prefix + key))
        if ms < 0:  # -2: missing key, -1: no expiry
            return None
        return max(1, math.ceil(ms / 1000))

    async def ping(self) -> None:
        await self._run("ping", lambda: self._redis.ping())

    async def publish(self, channel: str, message: str) -> None:
        await self._run("publish", lambda: self._redis.publish(self._prefix + channel, message))


class EventBus:
    """Delivers events published on ``<prefix>events`` to a handler, reconnecting on errors."""

    def __init__(self, url: str, prefix: str, reconnect_delay_s: float = 5.0,
                 poll_timeout_s: float = 30.0) -> None:
        self._url = url
        self._channel = prefix + "events"
        self._delay = reconnect_delay_s
        self._poll = poll_timeout_s
        self._stop = asyncio.Event()

    async def run(self, handler: Callable[[str], Awaitable[None]],
                  on_subscribed: Callable[[], Awaitable[None]] | None = None) -> None:
        """Consume events until ``close()``.

        Redis, OS and timeout errors on subscribe or read are logged at WARNING and the
        subscription is re-established after the reconnect delay. Handler errors are logged
        (exception type only) and do not affect the subscription.

        Pub/sub does not replay: events published while disconnected are lost. If given,
        ``on_subscribed`` is awaited after every successful subscribe (the first one and each
        reconnect) so the consumer can resynchronise; its exceptions are logged and ignored.
        """
        while not self._stop.is_set():
            try:
                await self._consume(handler, on_subscribed)
            except (RedisError, OSError, TimeoutError) as exc:
                log.warning("event bus connection error (%s); reconnecting in %.1f s",
                            type(exc).__name__, self._delay)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), self._delay)

    @staticmethod
    async def _guarded(what: str, call: Callable[[], Awaitable[None]]) -> None:
        try:
            await call()
        except Exception as exc:
            log.warning("event bus %s failed (%s)", what, type(exc).__name__)

    async def _consume(self, handler: Callable[[str], Awaitable[None]],
                       on_subscribed: Callable[[], Awaitable[None]] | None) -> None:
        client: Any = redis.asyncio.Redis.from_url(
            self._url, decode_responses=True, socket_connect_timeout=5, socket_keepalive=True)
        pubsub = client.pubsub()
        stopper: asyncio.Future[Any] | None = None
        reader: asyncio.Future[Any] | None = None
        try:
            await pubsub.subscribe(self._channel)
            if on_subscribed is not None:
                await self._guarded("on_subscribed callback", on_subscribed)
            stopper = asyncio.ensure_future(self._stop.wait())
            while not self._stop.is_set():
                read: asyncio.Future[Any] = asyncio.ensure_future(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=self._poll))
                reader = read
                await asyncio.wait({read, stopper}, return_when=asyncio.FIRST_COMPLETED)
                if not read.done():
                    return
                message = read.result()
                if message is None:  # quiet period: probe the link
                    await pubsub.ping()
                elif message["type"] == "message":
                    data = message["data"]
                    await self._guarded("handler", lambda: handler(data))
        finally:
            for task in (reader, stopper):
                if task is not None:
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            with contextlib.suppress(RedisError, OSError):
                await pubsub.aclose()
                await client.aclose()

    async def close(self) -> None:
        """Ask ``run()`` to stop. Callers must await the ``run`` task afterwards: its
        connections are only released when it returns."""
        self._stop.set()
