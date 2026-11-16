# SPDX-License-Identifier: GPL-3.0-or-later
import pytest

from asspng.state import MemoryStore
from tests.conftest import FakeClock
from tests.support.store_contract import StoreContract, StoreEnv


def make(clock: FakeClock, max_entries: int = 100) -> MemoryStore:
    return MemoryStore(max_entries=max_entries, clock=clock.now)


class TestMemoryStoreContract(StoreContract):
    @pytest.fixture
    def store_env(self, fake_clock: FakeClock) -> StoreEnv:
        async def advance(seconds: float) -> None:
            fake_clock.advance(seconds)

        return StoreEnv(store=make(fake_clock), advance=advance, kind="memory")


async def test_lru_eviction_at_capacity(fake_clock: FakeClock) -> None:
    s = make(fake_clock, max_entries=3)
    for k in ("a", "b", "c"):
        await s.incr(k, None)
    await s.get("a")  # a is now most recently used; b is the oldest
    await s.incr("d", None)
    assert sorted(await s.keys("*")) == ["a", "c", "d"]
    await s.incr("a", None)  # existing key: no eviction
    assert sorted(await s.keys("*")) == ["a", "c", "d"]


async def test_eviction_purges_expired_first(fake_clock: FakeClock) -> None:
    s = make(fake_clock, max_entries=3)
    await s.incr("old", None)
    await s.incr("new", None)
    await s.incr("short", 5)  # most recently used, but expired below
    fake_clock.advance(5.5)
    await s.incr("x", None)  # without purge-first, the LRU victim would be the live "old"
    assert sorted(await s.keys("*")) == ["new", "old", "x"]


async def test_full_store_of_live_keys_evicts_only_lru(fake_clock: FakeClock) -> None:
    s = make(fake_clock, max_entries=3)
    for k in ("a", "b", "c"):
        await s.incr(k, 100)
    await s.incr("d", 100)
    assert sorted(await s.keys("*")) == ["b", "c", "d"]


async def test_inserts_at_capacity_do_not_scan_when_nothing_expired(
    fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = make(fake_clock, max_entries=5)
    scans = 0
    original = s._scan_expired

    def spy() -> None:
        nonlocal scans
        scans += 1
        original()

    monkeypatch.setattr(s, "_scan_expired", spy)
    for i in range(5):
        await s.incr(f"k{i}", 1000)
    for i in range(5, 50):
        await s.incr(f"k{i}", 1000)
    assert scans == 0
    assert len(await s.keys("*")) == 5
    fake_clock.advance(1001)
    await s.incr("fresh", None)
    assert scans == 1
    assert await s.keys("*") == ["fresh"]


async def test_expiry_boundary_matches_redis(fake_clock: FakeClock) -> None:
    s = make(fake_clock)
    await s.incr("k", 10)
    fake_clock.advance(10)  # Redis: expired only once now > expires_at
    assert await s.get("k") == "1"
    assert await s.ttl("k") == 1
    fake_clock.advance(0.001)
    assert await s.get("k") is None


async def test_ttl_ceil_is_float_safe(fake_clock: FakeClock) -> None:
    s = make(fake_clock)
    await s.incr("k", 10)
    fake_clock.advance(0.1 + 0.2)  # 0.30000000000000004
    assert await s.ttl("k") == 10  # ceil(9.7)
    fake_clock.advance(9.7 - 0.3 + 0.3)
    assert await s.ttl("k") == 1


async def test_ttl_does_not_touch_lru(fake_clock: FakeClock) -> None:
    s = make(fake_clock, max_entries=2)
    await s.incr("a", 100)
    await s.incr("b", 100)
    await s.ttl("a")
    await s.incr("c", 100)
    assert sorted(await s.keys("*")) == ["b", "c"]


async def test_set_hash_evicts_lru_at_capacity(fake_clock: FakeClock) -> None:
    s = make(fake_clock, max_entries=2)
    await s.incr("a", None)
    await s.incr("b", None)
    await s.set_hash("h", {"x": "1"}, None)
    assert sorted(await s.keys("*")) == ["b", "h"]


async def test_delete_frees_capacity(fake_clock: FakeClock) -> None:
    s = make(fake_clock, max_entries=2)
    await s.incr("a", None)
    await s.incr("b", None)
    await s.delete("a")
    await s.incr("c", None)
    assert sorted(await s.keys("*")) == ["b", "c"]


async def test_hash_fields_do_not_count(fake_clock: FakeClock) -> None:
    s = make(fake_clock, max_entries=2)
    await s.set_hash("h", {str(i): "x" for i in range(50)}, None)
    await s.incr("c", None)
    assert sorted(await s.keys("*")) == ["c", "h"]


async def test_clear(fake_clock: FakeClock) -> None:
    s = make(fake_clock)
    await s.incr("a", None)
    await s.set_hash("h", {"x": "1"}, 5)
    s.clear()
    assert await s.keys("*") == []
    assert await s.get("a") is None
    assert await s.get_hash("h") == {}


def test_invalid_max_entries(fake_clock: FakeClock) -> None:
    with pytest.raises(ValueError):
        make(fake_clock, max_entries=0)


async def test_expired_keys_are_invisible_to_keys_and_delete(fake_clock: FakeClock) -> None:
    s = make(fake_clock)
    await s.incr("a", None)
    await s.incr("b", 1)
    await s.incr("pb:gone", 1)
    fake_clock.advance(1.5)
    assert await s.keys("pb:*") == []
    assert await s.delete("a", "b", "zzz") == 1
    assert await s.get("a") is None
