# SPDX-License-Identifier: GPL-3.0-or-later
"""Penalty box: score accumulation, escalating blocks, history, and the connect check."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest

from asspng.checks.base import CheckContext, Phase
from asspng.checks.penalty_box import PenaltyBox, PenaltyBoxCheck
from asspng.config.model import ListenerKind
from asspng.smtp.replies import R_TRY_LATER
from asspng.state.base import StateError
from asspng.state.memory_store import MemoryStore
from tests.conftest import FakeClock

H = 3600
D = 86400
NET = "192.0.2.0/24"


@pytest.fixture
def store(fake_clock: FakeClock) -> MemoryStore:
    return MemoryStore(1000, fake_clock.now)


@pytest.fixture
def make_box(store: MemoryStore, fake_clock: FakeClock) -> Callable[..., PenaltyBox]:
    def factory(**overrides: Any) -> PenaltyBox:
        params: dict[str, Any] = {
            "threshold": 100,
            "score_cap": 150,
            "score_ttl_s": 24 * H,
            "ladder_s": (24 * H, 7 * D, 30 * D),
            "history_s": 90 * D,
            "clock": fake_clock.now,
        }
        params.update(overrides)
        return PenaltyBox(store, **params)

    return factory


@pytest.fixture
def box(make_box: Callable[..., PenaltyBox]) -> PenaltyBox:
    return make_box()


async def test_first_block_24h(box: PenaltyBox, store: MemoryStore, fake_clock: FakeClock) -> None:
    st = await box.add_score(NET, 60, "bad")
    assert st.score == 60 and st.hits == 1 and st.blocked_until is None and st.level == 0
    st = await box.add_score(NET, 40, "worse")
    assert st.blocked_until == fake_clock.now() + 24 * H
    assert st.level == 1 and st.history == 1 and st.score == 0
    assert await box.blocked_until(NET) == fake_clock.now() + 24 * H
    assert await store.get_hash("pb:" + NET) == {}
    assert (await store.get_hash("pb:block:" + NET))["level"] == "1"
    fake_clock.advance(24 * H + 1)
    assert await box.blocked_until(NET) is None


async def test_no_accumulation_while_blocked(box: PenaltyBox) -> None:
    await box.add_score(NET, 100, "x")
    st = await box.add_score(NET, 50, "y")
    assert st.level == 1 and st.score == 0 and st.history == 1


async def test_nonpositive_points_is_noop(box: PenaltyBox) -> None:
    st = await box.add_score(NET, 0, "x")
    assert st.score == 0 and st.hits == 0
    assert await box.list() == []


async def test_second_block_7d(box: PenaltyBox, fake_clock: FakeClock) -> None:
    await box.add_score(NET, 100, "a")
    fake_clock.advance(24 * H + 1)
    st = await box.add_score(NET, 100, "b")
    assert st.level == 2 and st.history == 2
    assert st.blocked_until == fake_clock.now() + 7 * D


async def test_third_and_later_30d(box: PenaltyBox, fake_clock: FakeClock) -> None:
    await box.add_score(NET, 100, "a")
    fake_clock.advance(24 * H + 1)
    await box.add_score(NET, 100, "b")
    fake_clock.advance(7 * D + 1)
    st = await box.add_score(NET, 100, "c")
    assert st.level == 3 and st.blocked_until == fake_clock.now() + 30 * D
    fake_clock.advance(30 * D + 1)
    st = await box.add_score(NET, 100, "d")
    assert st.level == 3 and st.history == 4
    assert st.blocked_until == fake_clock.now() + 30 * D


async def test_history_expires_after_90d_restarts_level1(
    box: PenaltyBox, fake_clock: FakeClock
) -> None:
    await box.add_score(NET, 100, "a")
    fake_clock.advance(91 * D)
    st = await box.add_score(NET, 100, "b")
    assert st.level == 1 and st.history == 1
    assert st.blocked_until == fake_clock.now() + 24 * H


async def test_score_capped(make_box: Callable[..., PenaltyBox]) -> None:
    # A threshold above the cap is never reached, so the cap is observable.
    capped = make_box(threshold=1000)
    st = await capped.add_score(NET, 100, "a")
    st = await capped.add_score(NET, 100, "b")
    assert st.score == 150 and st.hits == 2


async def test_history_ttl_refreshed_by_each_block(
    box: PenaltyBox, fake_clock: FakeClock
) -> None:
    await box.add_score(NET, 100, "a")
    fake_clock.advance(60 * D)
    st = await box.add_score(NET, 100, "b")
    assert st.level == 2
    fake_clock.advance(89 * D)  # > 90 d after the first block, < 90 d after the second
    st = await box.add_score(NET, 100, "c")
    assert st.level == 3 and st.history == 3


async def test_score_expires_24h_after_last_hit(box: PenaltyBox, fake_clock: FakeClock) -> None:
    await box.add_score(NET, 40, "a")
    fake_clock.advance(23 * H)
    st = await box.add_score(NET, 40, "b")  # sliding TTL
    assert st.score == 80
    fake_clock.advance(23 * H)
    assert (await box.status(NET)).score == 80
    fake_clock.advance(2 * H)
    st = await box.status(NET)
    assert st.score == 0 and st.hits == 0


async def test_remove_keeps_history_unless_forget(box: PenaltyBox) -> None:
    await box.add_score(NET, 100, "a")
    await box.remove(NET)
    st = await box.status(NET)
    assert st.blocked_until is None and st.level == 0 and st.history == 1
    st = await box.add_score(NET, 100, "b")
    assert st.level == 2
    await box.remove(NET, forget=True)
    st = await box.status(NET)
    assert st.history == 0 and st.blocked_until is None
    st = await box.add_score(NET, 100, "c")
    assert st.level == 1


async def test_manual_block_no_history(box: PenaltyBox, fake_clock: FakeClock) -> None:
    await box.block(NET, 3600, "manual")
    st = await box.status(NET)
    assert st.level == 0 and st.history == 0 and st.reason == "manual"
    assert st.blocked_until == fake_clock.now() + 3600
    fake_clock.advance(3601)
    assert await box.blocked_until(NET) is None


async def test_manual_block_does_not_shorten_an_active_block(
        box: PenaltyBox, fake_clock: FakeClock) -> None:
    await box.add_score(NET, 100, "auto")  # level 1: 24 h
    until = (await box.status(NET)).blocked_until
    assert await box.block(NET, H, "manual") == until  # the block in force is returned
    st = await box.status(NET)
    assert (st.blocked_until, st.level, st.reason) == (until, 1, "auto")


async def test_manual_block_extends_a_shorter_block(
        box: PenaltyBox, fake_clock: FakeClock) -> None:
    await box.block(NET, H, "first")
    assert await box.block(NET, 2 * D, "longer") == fake_clock.now() + 2 * D
    st = await box.status(NET)
    assert (st.blocked_until, st.level, st.reason) == (fake_clock.now() + 2 * D, 0, "longer")


class YieldingStore:
    """Delegates to a store but yields to the event loop before every operation, as a store
    behind a network connection does, so concurrent callers interleave."""

    def __init__(self, inner: MemoryStore) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not asyncio.iscoroutinefunction(attr):
            return attr

        async def call(*args: Any, **kwargs: Any) -> Any:
            await asyncio.sleep(0)
            return await attr(*args, **kwargs)

        return call


async def test_concurrent_scores_are_all_counted(
        make_box: Callable[..., PenaltyBox], store: MemoryStore, fake_clock: FakeClock) -> None:
    box = PenaltyBox(cast(Any, YieldingStore(store)), threshold=100, score_cap=150,
                     score_ttl_s=24 * H, ladder_s=(24 * H, 7 * D), history_s=90 * D,
                     clock=fake_clock.now)
    await asyncio.gather(*(box.add_score(NET, 10, f"hit {i}") for i in range(5)))
    st = await box.status(NET)
    assert (st.score, st.hits) == (50, 5)


async def test_concurrent_threshold_crossings_block_once(
        store: MemoryStore, fake_clock: FakeClock) -> None:
    box = PenaltyBox(cast(Any, YieldingStore(store)), threshold=100, score_cap=150,
                     score_ttl_s=24 * H, ladder_s=(24 * H, 7 * D), history_s=90 * D,
                     clock=fake_clock.now)
    await box.add_score(NET, 60, "first")
    await asyncio.gather(box.add_score(NET, 50, "a"), box.add_score(NET, 50, "b"))
    st = await box.status(NET)
    assert (st.level, st.history) == (1, 1)  # one block on the first step, not two
    assert st.blocked_until == fake_clock.now() + 24 * H


async def test_list_sorted_with_ipv6(box: PenaltyBox) -> None:
    v6 = "2001:db8::/64"
    await box.add_score(v6, 100, "a")
    await box.add_score("198.51.100.0/24", 10, "b")
    await box.add_score("2001:db8:1::/64", 5, "c")
    await box.remove("203.0.113.0/24")
    await box.block("10.0.0.0/8", 60, "m")
    nets = [s.net for s in await box.list()]
    assert nets == sorted(
        ["198.51.100.0/24", v6, "10.0.0.0/8", "2001:db8:1::/64"]
    )
    by_net = {s.net: s for s in await box.list()}
    assert by_net[v6].level == 1 and by_net["198.51.100.0/24"].score == 10
    assert by_net["2001:db8:1::/64"].score == 5


def _ctx(kind: ListenerKind, trusted: bool = False) -> CheckContext:
    session = SimpleNamespace(
        net_key=NET, listener=SimpleNamespace(kind=kind), trusted=trusted
    )
    return cast(CheckContext, cast(Any, SimpleNamespace(session=session)))


async def test_check_only_on_smtp_listener(box: PenaltyBox) -> None:
    check = PenaltyBoxCheck(box)
    assert check.name == "penalty_box"
    assert check.phases == frozenset({Phase.CONNECT})
    assert check.exempt == frozenset({"trusted"})
    ctx = _ctx(ListenerKind.SMTP)
    assert not (await check.run(ctx, Phase.CONNECT)).hit
    await box.add_score(NET, 100, "bad actor")
    res = await check.run(ctx, Phase.CONNECT)
    assert res.hit and res.temporary and res.reply == R_TRY_LATER
    assert res.msg_score == 0 and res.ip_score == 0
    assert res.reason.startswith("blocked until 1970-")
    assert "(level 1): bad actor" in res.reason
    for kind in (ListenerKind.SUBMISSION, ListenerKind.SUBMISSIONS):
        assert not (await check.run(_ctx(kind), Phase.CONNECT)).hit


async def test_check_propagates_state_error(box: PenaltyBox) -> None:
    class Broken(MemoryStore):
        async def get_hash(self, key: str) -> dict[str, str]:
            raise StateError("down")

    broken = PenaltyBox(
        Broken(10, lambda: 0.0), threshold=100, score_cap=150, score_ttl_s=H,
        ladder_s=(H,), history_s=D, clock=lambda: 0.0,
    )
    with pytest.raises(StateError):
        await PenaltyBoxCheck(broken).run(_ctx(ListenerKind.SMTP), Phase.CONNECT)
