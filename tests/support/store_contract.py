# SPDX-License-Identifier: GPL-3.0-or-later
"""Behaviour contract shared by every ``StateStore`` implementation.

A test module subclasses ``StoreContract`` and provides a ``store_env`` fixture. Tests that
need time to pass call ``env.advance`` (fake clock for ``MemoryStore``, real sleep for Redis),
so windows and TTLs here are 1-2 seconds and no exact-millisecond boundaries are asserted.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import pytest

from asspng.state import StateStore, StateTypeError


@dataclass(slots=True)
class StoreEnv:
    store: StateStore
    advance: Callable[[float], Awaitable[None]]
    kind: str


class StoreContract:
    async def test_is_state_store(self, store_env: StoreEnv) -> None:
        assert isinstance(store_env.store, StateStore)

    async def test_incr_window_expires_after_window(self, store_env: StoreEnv) -> None:
        s = store_env.store
        assert await s.incr_window("rl:a", 2) == 1
        assert await s.incr_window("rl:a", 2) == 2
        assert await s.get("rl:a") == "2"
        await store_env.advance(2.1)
        assert await s.get("rl:a") is None
        assert await s.incr_window("rl:a", 2) == 1

    async def test_incr_window_ttl_not_extended(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.incr_window("k", 2)
        await store_env.advance(1.2)
        assert await s.incr_window("k", 2) == 2
        await store_env.advance(1.0)  # 2.2 s since creation: gone unless the TTL was extended
        assert await s.get("k") is None
        assert await s.incr_window("k", 2) == 1

    async def test_incr_refreshes_ttl(self, store_env: StoreEnv) -> None:
        s = store_env.store
        assert await s.incr("k", 2) == 1
        await store_env.advance(1.0)
        assert await s.incr("k", 2) == 2
        assert await s.ttl("k") == 2
        assert await s.get("k") == "2"

    async def test_incr_without_ttl_persists(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.incr("k", 10)
        assert await s.incr("k", None) == 2
        assert await s.ttl("k") is None
        assert await s.get("k") == "2"

    async def test_incr_window_on_persistent_key_adds_no_expiry(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.incr("k", None)
        assert await s.incr_window("k", 10) == 2
        assert await s.ttl("k") is None

    async def test_incr_window_sets_ttl_once(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.incr_window("k", 10)
        await s.incr_window("k", 99)
        assert await s.ttl("k") == 10

    async def test_hash_roundtrip_and_replace(self, store_env: StoreEnv) -> None:
        s = store_env.store
        assert await s.get_hash("h") == {}
        await s.set_hash("h", {"a": "1", "b": "2"}, 5)
        await s.set_hash("h", {"c": "3"}, 5)
        assert await s.get_hash("h") == {"c": "3"}
        assert await s.ttl("h") == 5
        await s.set_hash("p", {"a": "1"}, None)
        assert await s.ttl("p") is None
        assert await s.ttl("missing") is None

    async def test_hash_expires(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.set_hash("h", {"a": "1"}, 1)
        assert await s.ttl("h") == 1
        await store_env.advance(1.1)
        assert await s.get_hash("h") == {}
        assert await s.ttl("h") is None

    async def test_set_hash_replaces_ttl(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.set_hash("h", {"a": "1"}, 5)
        await s.set_hash("h", {"a": "2"}, None)
        assert await s.ttl("h") is None

    async def test_set_hash_empty_deletes_key(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.set_hash("h", {"a": "1"}, None)
        await s.set_hash("h", {}, 5)
        assert await s.keys("*") == []
        assert await s.get_hash("h") == {}
        await s.set_hash("never", {}, None)
        assert await s.keys("*") == []

    async def test_type_mismatch_raises(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.set_hash("h", {"a": "1"}, None)
        await s.incr("c", None)
        with pytest.raises(StateTypeError):
            await s.get("h")
        with pytest.raises(StateTypeError):
            await s.incr("h", None)
        with pytest.raises(StateTypeError):
            await s.incr_window("h", 5)
        with pytest.raises(StateTypeError):
            await s.get_hash("c")

    async def test_incr_on_hash_has_no_side_effects(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.set_hash("h", {"a": "1"}, None)
        with pytest.raises(StateTypeError):
            await s.incr("h", 5)
        assert await s.get_hash("h") == {"a": "1"}
        assert await s.ttl("h") is None

    async def test_type_mismatch_leaves_hash_intact(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.set_hash("h", {"a": "1"}, None)
        with pytest.raises(StateTypeError):
            await s.incr_window("h", 5)
        assert await s.get_hash("h") == {"a": "1"}
        assert await s.ttl("h") is None

    async def test_keys_glob(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.incr("pb:1.2.3.0", None)
        await s.incr("pb:block:1.2.3.0", None)
        await s.incr("rl:x:y", None)
        assert sorted(await s.keys("pb:*")) == ["pb:1.2.3.0", "pb:block:1.2.3.0"]
        assert await s.keys("pb:??.2.3.0") == []
        assert await s.keys("pb:?.2.3.0") == ["pb:1.2.3.0"]
        assert await s.keys("nomatch*") == []
        assert sorted(await s.keys("*")) == ["pb:1.2.3.0", "pb:block:1.2.3.0", "rl:x:y"]

    async def test_delete_counts_existing_keys(self, store_env: StoreEnv) -> None:
        s = store_env.store
        await s.incr("a", None)
        await s.incr("b", None)
        assert await s.delete("a", "b", "zzz") == 2
        assert await s.get("a") is None
        assert await s.delete("a") == 0

    async def test_ping_and_publish(self, store_env: StoreEnv) -> None:
        assert await store_env.store.ping() is None
        assert await store_env.store.publish("events", "hello") is None
