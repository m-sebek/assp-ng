# SPDX-License-Identifier: GPL-3.0-or-later
"""Penalty box: networks collect IP score and are blocked with escalating durations.

Keys: ``pb:<net>`` (score, reason, hits, first, last), ``pb:block:<net>`` (until, level,
reason) and ``pb:hist:<net>`` (a counter of past blocks). All hash fields are strings.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from asspng.checks.base import NEUTRAL, CheckContext, CheckResult, Phase
from asspng.config.model import ListenerKind
from asspng.smtp.replies import R_TRY_LATER
from asspng.state.base import StateStore

_P = "pb:"
_BLOCK = "pb:block:"
_HIST = "pb:hist:"


@dataclass(frozen=True)
class PenaltyStatus:
    net: str
    score: int
    reason: str
    hits: int
    blocked_until: float | None
    level: int
    history: int


class PenaltyBox:
    def __init__(
        self,
        store: StateStore,
        *,
        threshold: int,
        score_cap: int,
        score_ttl_s: int,
        ladder_s: Sequence[int],
        history_s: int,
        clock: Callable[[], float],
    ) -> None:
        if not ladder_s:
            raise ValueError("ladder_s must not be empty")
        self._store = store
        self._threshold = threshold
        self._cap = score_cap
        self._score_ttl = score_ttl_s
        self._ladder = tuple(ladder_s)
        self._history_s = history_s
        self._clock = clock

    async def _block_hash(self, net: str) -> dict[str, str]:
        """Return the block hash if the block is still in force, else ``{}``."""
        block = await self._store.get_hash(_BLOCK + net)
        if block and float(block.get("until", "0")) > self._clock():
            return block
        return {}

    async def blocked_until(self, net: str) -> float | None:
        block = await self._block_hash(net)
        return float(block["until"]) if block else None

    async def status(self, net: str) -> PenaltyStatus:
        block = await self._block_hash(net)
        entry = await self._store.get_hash(_P + net)
        hist = await self._store.get(_HIST + net)
        return PenaltyStatus(
            net=net,
            score=int(entry.get("score", "0")),
            reason=block.get("reason", "") if block else entry.get("reason", ""),
            hits=int(entry.get("hits", "0")),
            blocked_until=float(block["until"]) if block else None,
            level=int(block.get("level", "0")) if block else 0,
            history=int(hist) if hist is not None else 0,
        )

    async def add_score(self, net: str, points: int, reason: str) -> PenaltyStatus:
        if points <= 0 or await self._block_hash(net):
            return await self.status(net)
        now = self._clock()
        entry = await self._store.get_hash(_P + net)
        score = min(self._cap, int(entry.get("score", "0")) + points)
        if score >= self._threshold:
            history = await self._store.incr(_HIST + net, self._history_s)
            level = min(history, len(self._ladder))
            await self._set_block(net, self._ladder[level - 1], level, reason)
            await self._store.delete(_P + net)
            return await self.status(net)
        await self._store.set_hash(
            _P + net,
            {
                "score": str(score),
                "reason": reason,
                "hits": str(int(entry.get("hits", "0")) + 1),
                "first": entry.get("first", repr(now)),
                "last": repr(now),
            },
            self._score_ttl,
        )
        return await self.status(net)

    async def _set_block(self, net: str, duration_s: int, level: int, reason: str) -> None:
        until = self._clock() + duration_s
        await self._store.set_hash(
            _BLOCK + net,
            {"until": repr(until), "level": str(level), "reason": reason},
            duration_s,
        )

    async def block(self, net: str, duration_s: int, reason: str) -> None:
        """Manual block: level 0, the escalation history is not touched."""
        await self._set_block(net, duration_s, 0, reason)

    async def remove(self, net: str, *, forget: bool = False) -> None:
        keys = [_P + net, _BLOCK + net]
        if forget:
            keys.append(_HIST + net)
        await self._store.delete(*keys)

    async def list(self) -> list[PenaltyStatus]:
        nets: set[str] = set()
        for key in await self._store.keys(_P + "*"):
            if key.startswith(_BLOCK):
                nets.add(key[len(_BLOCK):])
            elif key.startswith(_HIST):
                nets.add(key[len(_HIST):])
            else:
                nets.add(key[len(_P):])
        return [await self.status(net) for net in sorted(nets)]


class PenaltyBoxCheck:
    """Refuse connections from blocked networks (port-25 listeners only)."""

    name = "penalty_box"
    phases = frozenset({Phase.CONNECT})
    exempt = frozenset({"trusted"})

    def __init__(self, box: PenaltyBox) -> None:
        self._box = box

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        if ctx.session.listener.kind is not ListenerKind.SMTP:
            return NEUTRAL
        net = ctx.session.net_key
        status = await self._box.status(net)
        if status.blocked_until is None:
            return NEUTRAL
        stamp = datetime.fromtimestamp(status.blocked_until, UTC).isoformat(timespec="seconds")
        return CheckResult(
            True,
            reason=f"blocked until {stamp} (level {status.level}): {status.reason}",
            reply=R_TRY_LATER,
            temporary=True,
        )
