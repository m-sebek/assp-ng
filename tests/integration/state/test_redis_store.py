# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import time
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
import redis.asyncio

from asspng.state import StateError, StateTypeError
from asspng.state.redis_store import EventBus, RedisStore
from tests.support.redis_server import RedisServer
from tests.support.store_contract import StoreContract, StoreEnv


def new_prefix() -> str:
    return f"t:{uuid4().hex}:"


class TestRedisStoreContract(StoreContract):
    @pytest.fixture
    async def store_env(self, redis_server: RedisServer) -> AsyncIterator[StoreEnv]:
        store = RedisStore(redis_server.url, new_prefix(), op_timeout_s=2.0)

        async def advance(seconds: float) -> None:
            await asyncio.sleep(seconds + 0.1)

        try:
            yield StoreEnv(store=store, advance=advance, kind="redis")
        finally:
            await store.close()


@pytest.fixture
async def raw(redis_server: RedisServer) -> AsyncIterator["redis.asyncio.Redis"]:
    client = redis.asyncio.Redis.from_url(redis_server.url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


async def test_prefix_applied(redis_server: RedisServer, raw: "redis.asyncio.Redis") -> None:
    store = RedisStore(redis_server.url, "asspng:", op_timeout_s=2.0)
    try:
        await store.incr("x", None)
        assert await raw.exists("asspng:x") == 1
        assert await raw.exists("x") == 0
        await store.delete("x")
    finally:
        await store.close()


async def test_prefix_isolates_stores(redis_server: RedisServer) -> None:
    a = RedisStore(redis_server.url, new_prefix(), op_timeout_s=2.0)
    b = RedisStore(redis_server.url, new_prefix(), op_timeout_s=2.0)
    try:
        await a.incr("k", None)
        assert await b.get("k") is None
        assert await b.keys("*") == []
        assert await a.keys("*") == ["k"]
    finally:
        await a.close()
        await b.close()


async def test_keys_escapes_glob_chars_in_prefix(redis_server: RedisServer) -> None:
    weird = RedisStore(redis_server.url, "w[a]*?\\:", op_timeout_s=2.0)
    other = RedisStore(redis_server.url, "wa:", op_timeout_s=2.0)
    try:
        await weird.incr("k1", None)
        await other.incr("k2", None)
        assert await weird.keys("*") == ["k1"]
        assert await other.keys("*") == ["k2"]
    finally:
        await weird.delete("k1")
        await other.delete("k2")
        await weird.close()
        await other.close()


async def test_incr_window_always_has_ttl(redis_server: RedisServer,
                                          raw: "redis.asyncio.Redis") -> None:
    prefix = new_prefix()
    store = RedisStore(redis_server.url, prefix, op_timeout_s=2.0)
    try:
        for _ in range(3):
            await store.incr_window("k", 30)
        assert 0 < await raw.pttl(prefix + "k") <= 30_000
    finally:
        await store.close()


async def test_publish_reaches_subscriber(redis_server: RedisServer,
                                          raw: "redis.asyncio.Redis") -> None:
    prefix = new_prefix()
    store = RedisStore(redis_server.url, prefix, op_timeout_s=2.0)
    pubsub = raw.pubsub()
    try:
        await pubsub.subscribe(prefix + "events")
        await pubsub.get_message(timeout=2)  # subscribe confirmation
        await store.publish("events", "hi")
        msg = await pubsub.get_message(timeout=2)
        assert msg is not None and msg["data"] == "hi"
    finally:
        await pubsub.aclose()
        await store.close()


async def test_errors_become_state_error(redis_server: RedisServer) -> None:
    store = RedisStore(redis_server.url, new_prefix(), op_timeout_s=0.3)
    try:
        await store.ping()
        redis_server.stop()
        try:
            started = time.monotonic()
            with pytest.raises(StateError) as info:
                await store.incr("secret-key", 5)
            assert time.monotonic() - started < 0.5
            assert "secret-key" not in str(info.value)
            for call in (store.ping, lambda: store.get("k"), lambda: store.keys("*"),
                         lambda: store.publish("c", "m"), lambda: store.ttl("k"),
                         lambda: store.get_hash("k"), lambda: store.delete("k"),
                         lambda: store.set_hash("k", {"a": "1"}, 1),
                         lambda: store.incr_window("k", 1)):
                with pytest.raises(StateError):
                    await call()
        finally:
            redis_server.start()
        await store.ping()  # recovers once the server is back
    finally:
        await store.close()


async def test_only_wrongtype_is_state_type_error(
    redis_server: RedisServer, raw: "redis.asyncio.Redis"
) -> None:
    prefix = new_prefix()
    store = RedisStore(redis_server.url, prefix, op_timeout_s=2.0)
    try:
        await store.set_hash("secret-key", {"a": "1"}, None)
        for call in (lambda: store.get("secret-key"),  # plain command
                     lambda: store.incr("secret-key", 5),  # Lua script
                     lambda: store.incr_window("secret-key", 5)):  # MULTI/EXEC
            with pytest.raises(StateTypeError) as info:
                await call()
            assert "secret-key" not in str(info.value)
        await raw.set(prefix + "n", "not-a-number")
        with pytest.raises(StateError) as other:
            await store.incr("n", None)
        assert not isinstance(other.value, StateTypeError)
    finally:
        await store.close()


async def test_unreachable_server_is_state_error() -> None:
    store = RedisStore("redis://127.0.0.1:1/0", "p:", op_timeout_s=0.3)
    try:
        with pytest.raises(StateError):
            await store.ping()
    finally:
        await store.close()


async def _wait_for(queue: "asyncio.Queue[str]", store: RedisStore, message: str) -> str:
    """Publish until the subscriber (whose subscription time is unknown) receives it."""
    async with asyncio.timeout(5):
        while True:
            await store.publish("events", message)
            try:
                return await asyncio.wait_for(queue.get(), 0.1)
            except TimeoutError:
                continue


async def test_event_bus_receives(redis_server: RedisServer) -> None:
    prefix = new_prefix()
    store = RedisStore(redis_server.url, prefix, op_timeout_s=2.0)
    bus = EventBus(redis_server.url, prefix)
    queue: asyncio.Queue[str] = asyncio.Queue()

    async def handler(message: str) -> None:
        await queue.put(message)

    task = asyncio.create_task(bus.run(handler))
    try:
        assert await _wait_for(queue, store, "domains-changed") == "domains-changed"
    finally:
        await bus.close()
        await asyncio.wait_for(task, 2)
        await store.close()


async def test_event_bus_ignores_other_prefix(redis_server: RedisServer) -> None:
    prefix = new_prefix()
    mine = RedisStore(redis_server.url, prefix, op_timeout_s=2.0)
    other = RedisStore(redis_server.url, new_prefix(), op_timeout_s=2.0)
    bus = EventBus(redis_server.url, prefix)
    queue: asyncio.Queue[str] = asyncio.Queue()
    subscribed = asyncio.Event()

    async def handler(message: str) -> None:
        await queue.put(message)

    async def on_subscribed() -> None:
        subscribed.set()

    task = asyncio.create_task(bus.run(handler, on_subscribed))
    try:
        await asyncio.wait_for(subscribed.wait(), 5)
        await other.publish("events", "foreign")
        await mine.publish("events", "mine")
        assert await asyncio.wait_for(queue.get(), 2) == "mine"
        await asyncio.sleep(0.2)
        assert queue.empty()
    finally:
        await bus.close()
        await asyncio.wait_for(task, 2)
        await mine.close()
        await other.close()


async def test_event_bus_handler_error_keeps_subscription(
        redis_server: RedisServer, caplog: pytest.LogCaptureFixture) -> None:
    prefix = new_prefix()
    store = RedisStore(redis_server.url, prefix, op_timeout_s=2.0)
    bus = EventBus(redis_server.url, prefix, reconnect_delay_s=0.1)
    queue: asyncio.Queue[str] = asyncio.Queue()
    subscribed: list[int] = []
    ready = asyncio.Event()

    async def handler(message: str) -> None:
        if message == "boom-payload":
            raise ValueError("secret detail")
        await queue.put(message)

    async def on_subscribed() -> None:
        subscribed.append(1)
        ready.set()

    caplog.set_level("WARNING")
    task = asyncio.create_task(bus.run(handler, on_subscribed))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        await store.publish("events", "boom-payload")
        await store.publish("events", "second")
        assert await asyncio.wait_for(queue.get(), 2) == "second"
        assert subscribed == [1]  # no reconnect
        assert "ValueError" in caplog.text
        assert "boom-payload" not in caplog.text and "secret detail" not in caplog.text
    finally:
        await bus.close()
        await asyncio.wait_for(task, 2)
        await store.close()


async def test_event_bus_on_subscribed_called_again_after_reconnect(
        redis_server: RedisServer) -> None:
    bus = EventBus(redis_server.url, new_prefix(), reconnect_delay_s=0.1)
    calls = 0
    cond = asyncio.Condition()

    async def handler(message: str) -> None:
        return None

    async def on_subscribed() -> None:
        nonlocal calls
        async with cond:
            calls += 1
            cond.notify_all()
        if calls == 1:
            raise RuntimeError("ignored")  # exceptions in the callback must not break the bus

    async def wait_calls(n: int) -> None:
        async with cond:
            await asyncio.wait_for(cond.wait_for(lambda: calls >= n), 5)

    task = asyncio.create_task(bus.run(handler, on_subscribed))
    try:
        await wait_calls(1)
        redis_server.stop()
        await asyncio.sleep(0.3)
        redis_server.start()
        await wait_calls(2)
        assert calls == 2
    finally:
        redis_server.start()
        await bus.close()
        await asyncio.wait_for(task, 2)


async def test_event_bus_reconnects_after_server_restart(redis_server: RedisServer) -> None:
    prefix = new_prefix()
    bus = EventBus(redis_server.url, prefix, reconnect_delay_s=0.1)
    queue: asyncio.Queue[str] = asyncio.Queue()

    async def handler(message: str) -> None:
        await queue.put(message)

    task = asyncio.create_task(bus.run(handler))
    store = RedisStore(redis_server.url, prefix, op_timeout_s=2.0)
    try:
        assert await _wait_for(queue, store, "before") == "before"
        redis_server.stop()
        await asyncio.sleep(0.3)
        redis_server.start()
        while not queue.empty():
            queue.get_nowait()
        assert await _wait_for(queue, store, "after") == "after"
    finally:
        redis_server.start()
        await bus.close()
        await asyncio.wait_for(task, 2)
        await store.close()


async def test_event_bus_close_before_run_returns(redis_server: RedisServer) -> None:
    bus = EventBus(redis_server.url, new_prefix())
    await bus.close()

    async def handler(message: str) -> None:
        raise AssertionError("no event expected")

    await asyncio.wait_for(bus.run(handler), 2)
