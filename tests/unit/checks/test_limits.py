# SPDX-License-Identifier: GPL-3.0-or-later
"""Limit checks: connections, session, AUTH failures and per-user rates."""
from __future__ import annotations

import dataclasses
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from asspng.checks.base import CheckContext, Phase, SessionInfo, TransactionInfo
from asspng.checks.limits import (
    AuthLimitsCheck,
    ConnLimitsCheck,
    SessionLimitsCheck,
    UserRateCheck,
)
from asspng.config.loader import load_config
from asspng.config.policy import PolicyResolver
from asspng.net.ipnet import parse_ip
from asspng.proxy.connections import ConnectionTracker
from asspng.smtp.address import Address
from asspng.smtp.replies import R_AUTH_TEMPFAIL, R_RATE, Reply
from asspng.state.memory_store import MemoryStore
from tests.conftest import FakeClock

NET = "192.0.2.0/24"


class Env:
    def __init__(self, etc_dir: Path, clock: FakeClock, *, system: dict[str, object] | None = None,
                 sender_policy: str = "") -> None:
        snap = load_config(etc_dir)
        snap = dataclasses.replace(snap, system={**snap.system, **(system or {})})
        resolver = PolicyResolver(snap)
        self.store = MemoryStore(1000, clock.now)
        self.tracker = ConnectionTracker()
        self.session = SessionInfo(
            "s1", parse_ip("192.0.2.7"), NET, snap.listeners[0], None, None, None,
            False, False, 0, 0, 0)
        self.txn = TransactionInfo(
            1, None, [], None, resolver.for_recipient(Address("bob", "example.com")),
            0, [], [], False, None)
        self.ctx = CheckContext(
            self.session, self.txn, snap, resolver.default_policy(), resolver.for_sender(""),
            self.store, clock.now, self.tracker)


class JunkStore:
    """Wraps a store; every ``get`` returns a non-integer value."""

    def __init__(self, inner: MemoryStore) -> None:
        self._inner = inner

    async def get(self, key: str) -> str | None:
        return "junk"

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


MakeEnv = Callable[..., Env]


@pytest.fixture
def make_env(etc_dir: Path, fake_clock: FakeClock) -> MakeEnv:
    def factory(**system: object) -> Env:
        return Env(etc_dir, fake_clock, system=system)
    return factory


async def test_concurrent_limit(make_env: MakeEnv) -> None:
    env = make_env(**{"limits.net.concurrent": 2})
    check = ConnLimitsCheck()
    for _ in range(2):
        env.tracker.acquire(NET)
    assert not (await check.run(env.ctx, Phase.CONNECT)).hit
    env.tracker.acquire(NET)
    res = await check.run(env.ctx, Phase.CONNECT)
    assert res.hit and res.temporary
    assert res.reply == Reply.of(421, "4.7.0 Too many connections")
    assert res.reason == "concurrent connections 3 > 2"
    assert res.msg_score == 0 and res.ip_score == 0


async def test_per_minute_limit_resets_next_window(
        make_env: MakeEnv, fake_clock: FakeClock) -> None:
    env = make_env(**{"limits.net.connections_per_minute": 3})
    check = ConnLimitsCheck()
    for _ in range(3):
        assert not (await check.run(env.ctx, Phase.CONNECT)).hit
    res = await check.run(env.ctx, Phase.CONNECT)
    assert res.hit and res.reason == "connections per minute 4 > 3"
    fake_clock.advance(61)
    assert not (await check.run(env.ctx, Phase.CONNECT)).hit


async def test_exempt_network_skipped(make_env: MakeEnv) -> None:
    env = make_env(**{"limits.net.concurrent": 1, "limits.net.connections_per_minute": 1})
    env.session.exempt = True
    for _ in range(3):
        env.tracker.acquire(NET)
    for _ in range(3):
        assert not (await ConnLimitsCheck().run(env.ctx, Phase.CONNECT)).hit
    assert await env.store.get("rl:conn:" + NET) is None


async def test_messages_per_session(make_env: MakeEnv) -> None:
    env = make_env(**{"limits.session.messages": 2})
    check = SessionLimitsCheck()
    env.session.messages = 1
    assert not (await check.run(env.ctx, Phase.MAIL)).hit
    env.session.messages = 2
    res = await check.run(env.ctx, Phase.MAIL)
    assert res.hit and res.temporary
    assert res.reply == Reply.of(421, "4.7.0 Too many messages")
    assert res.reason == "messages per session 2 >= 2"


async def test_auth_net_limit(make_env: MakeEnv) -> None:
    env = make_env(**{"limits.auth.failures_per_net": 2})
    check = AuthLimitsCheck()
    assert not (await check.run(env.ctx, Phase.AUTH)).hit
    await AuthLimitsCheck.record_failure(env.store, NET, None, 900)
    assert not (await check.run(env.ctx, Phase.AUTH)).hit
    await AuthLimitsCheck.record_failure(env.store, NET, None, 900)
    res = await check.run(env.ctx, Phase.AUTH)
    assert res.hit and res.temporary and res.reply == R_AUTH_TEMPFAIL
    assert res.reason == "authentication failures per network 2 >= 2"
    assert await env.store.get("rl:authfail:user:x") is None


async def test_auth_user_limit_across_nets(make_env: MakeEnv) -> None:
    env = make_env()
    for i in range(3):
        net = f"198.51.{i}.0/24"
        await AuthLimitsCheck.record_failure(env.store, net, "Alice@Example.com", 900)
    assert not await AuthLimitsCheck.user_blocked(env.store, "alice@example.com", 4)
    assert await AuthLimitsCheck.user_blocked(env.store, "ALICE@example.com", 3)
    assert not await AuthLimitsCheck.user_blocked(env.store, "bob@example.com", 1)
    assert await env.store.get("rl:authfail:user:alice@example.com") == "3"


def _user_limits(env: Env, **limits: int) -> None:
    assert env.ctx.sender_policy is not None
    env.ctx.sender_policy = dataclasses.replace(
        env.ctx.sender_policy,
        values={**env.ctx.sender_policy.values,
                **{f"limits.user.{k}": v for k, v in limits.items()}})


async def test_user_rate_minute_and_hour(make_env: MakeEnv, fake_clock: FakeClock) -> None:
    env = make_env()
    env.session.auth_user = "Alice"
    _user_limits(env, messages_per_minute=2, messages_per_hour=100)
    check = UserRateCheck()
    for _ in range(2):
        assert not (await check.run(env.ctx, Phase.MAIL)).hit
    res = await check.run(env.ctx, Phase.MAIL)
    assert res.hit and res.temporary and res.reply == R_RATE
    assert res.reason == "messages per minute 3 > 2"
    assert "alice" not in res.reason.lower()
    fake_clock.advance(61)
    assert not (await check.run(env.ctx, Phase.MAIL)).hit


async def test_user_rate_hour_boundary(make_env: MakeEnv) -> None:
    env = make_env()
    env.session.auth_user = "Alice"
    _user_limits(env, messages_per_minute=100, messages_per_hour=3)
    check = UserRateCheck()
    for _ in range(3):  # exactly the hourly limit passes
        assert not (await check.run(env.ctx, Phase.MAIL)).hit
    res = await check.run(env.ctx, Phase.MAIL)
    assert res.hit and res.reply == R_RATE and res.reason == "messages per hour 4 > 3"
    assert await env.store.get("rl:umsg:h:alice") == "4"


async def test_user_rate_recipients_boundary(make_env: MakeEnv) -> None:
    env = make_env()
    env.session.auth_user = "Alice"
    _user_limits(env, recipients_per_hour=2)
    check = UserRateCheck()
    for _ in range(2):
        assert not (await check.run(env.ctx, Phase.RCPT)).hit
    res = await check.run(env.ctx, Phase.RCPT)
    assert res.hit and res.reply == R_RATE and res.reason == "recipients per hour 3 > 2"


async def test_non_integer_auth_counter_is_zero(
        make_env: MakeEnv, caplog: pytest.LogCaptureFixture) -> None:
    env = make_env(**{"limits.auth.failures_per_net": 1})
    env.ctx.state = JunkStore(env.store)
    with caplog.at_level("WARNING"):
        assert not (await AuthLimitsCheck().run(env.ctx, Phase.AUTH)).hit
    assert "non-integer" in caplog.text
    assert not await AuthLimitsCheck.user_blocked(env.ctx.state, "bob", 1)


async def test_user_rate_ignores_unauthenticated(make_env: MakeEnv) -> None:
    env = make_env()
    check = UserRateCheck()
    for phase in (Phase.MAIL, Phase.RCPT):
        assert not (await check.run(env.ctx, phase)).hit
    assert await env.store.keys("rl:u*") == []
