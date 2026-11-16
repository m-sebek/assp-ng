# SPDX-License-Identifier: GPL-3.0-or-later
"""Limit checks: connections, session size, AUTH failures and per-user sending rates.

Rate counters are fixed-window counters in the state store: ``rl:conn:<net>``,
``rl:authfail:net:<net>``, ``rl:authfail:user:<user>``, ``rl:umsg:m|h:<user>`` and
``rl:urcpt:h:<user>``. User names are lower-cased in keys and never appear in reasons.
"""
from __future__ import annotations

import logging
from typing import cast

from asspng.checks.base import NEUTRAL, CheckContext, CheckResult, Phase
from asspng.smtp.replies import (
    R_AUTH_TEMPFAIL,
    R_RATE,
    R_TOO_MANY_CONN,
    R_TOO_MANY_MSG,
    Reply,
)
from asspng.state.base import StateStore

_log = logging.getLogger(__name__)

_MINUTE = 60
_HOUR = 3600


def _limit(ctx: CheckContext, key: str) -> int:
    return cast(int, ctx.setting(key))


async def _counter(state: StateStore, key: str) -> int:
    """Read a stored counter; a missing or non-integer value counts as 0."""
    raw = await state.get(key)
    if raw is None:
        return 0
    try:
        return int(raw)
    except ValueError:
        _log.warning("non-integer value in state counter %s; treated as 0", key.rsplit(":", 1)[0])
        return 0


def _hit(reason: str, reply: Reply) -> CheckResult:
    return CheckResult(True, msg_score=0, ip_score=0, reason=reason, reply=reply, temporary=True)


class ConnLimitsCheck:
    """Concurrent connections and new connections per minute, per client network."""

    name = "conn_limits"
    phases = frozenset({Phase.CONNECT})
    exempt: frozenset[str] = frozenset()

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        if ctx.session.exempt:
            return NEUTRAL
        net = ctx.session.net_key
        concurrent = ctx.connections.count(net)  # includes this connection
        limit = _limit(ctx, "limits.net.concurrent")
        if concurrent > limit:
            return _hit(f"concurrent connections {concurrent} > {limit}", R_TOO_MANY_CONN)
        count = await ctx.state.incr_window("rl:conn:" + net, _MINUTE)
        limit = _limit(ctx, "limits.net.connections_per_minute")
        if count > limit:
            return _hit(f"connections per minute {count} > {limit}", R_TOO_MANY_CONN)
        return NEUTRAL


class SessionLimitsCheck:
    """Messages per session (MAIL). The recipients per message are limited by the session
    itself (452 before the RCPT checks run), so there is no RCPT branch here."""

    name = "session_limits"
    phases = frozenset({Phase.MAIL})
    exempt: frozenset[str] = frozenset()

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        limit = _limit(ctx, "limits.session.messages")
        if ctx.session.messages >= limit:
            return _hit(f"messages per session {ctx.session.messages} >= {limit}",
                        R_TOO_MANY_MSG)
        return NEUTRAL


class AuthLimitsCheck:
    """Failed AUTH attempts. The user name is unknown at the AUTH phase, so ``run`` only
    checks the network counter; the session uses ``user_blocked`` once it has the name."""

    name = "auth_limits"
    phases = frozenset({Phase.AUTH})
    exempt: frozenset[str] = frozenset()

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        count = await _counter(ctx.state, "rl:authfail:net:" + ctx.session.net_key)
        limit = _limit(ctx, "limits.auth.failures_per_net")
        if count >= limit:
            return _hit(f"authentication failures per network {count} >= {limit}",
                        R_AUTH_TEMPFAIL)
        return NEUTRAL

    @staticmethod
    async def user_blocked(state: StateStore, username: str, limit: int) -> bool:
        return await _counter(state, "rl:authfail:user:" + username.lower()) >= limit

    @staticmethod
    async def record_failure(
        state: StateStore, net: str, username: str | None, window_s: int
    ) -> None:
        await state.incr_window("rl:authfail:net:" + net, window_s)
        if username is not None:
            await state.incr_window("rl:authfail:user:" + username.lower(), window_s)


class UserRateCheck:
    """Messages and recipients per authenticated user (MAIL and RCPT)."""

    name = "user_rate"
    phases = frozenset({Phase.MAIL, Phase.RCPT})
    exempt: frozenset[str] = frozenset()

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        user = ctx.session.auth_user
        if user is None:
            return NEUTRAL
        user = user.lower()
        # Both counters also count attempts that end up rejected (by ruling).
        if phase is Phase.MAIL:
            per_min = await ctx.state.incr_window("rl:umsg:m:" + user, _MINUTE)
            per_hour = await ctx.state.incr_window("rl:umsg:h:" + user, _HOUR)
            limit = _limit(ctx, "limits.user.messages_per_minute")
            if per_min > limit:
                return _hit(f"messages per minute {per_min} > {limit}", R_RATE)
            limit = _limit(ctx, "limits.user.messages_per_hour")
            if per_hour > limit:
                return _hit(f"messages per hour {per_hour} > {limit}", R_RATE)
        elif phase is Phase.RCPT:
            count = await ctx.state.incr_window("rl:urcpt:h:" + user, _HOUR)
            limit = _limit(ctx, "limits.user.recipients_per_hour")
            if count > limit:
                return _hit(f"recipients per hour {count} > {limit}", R_RATE)
        return NEUTRAL
