# SPDX-License-Identifier: GPL-3.0-or-later
"""Decision engine: applies check modes, test mode, message and IP scoring (ASSP v1 semantics).

Score precedence: the effective message or IP score of a hit is the check result's score when
it is non-zero, otherwise the configured ``checks.<name>.msg_score`` / ``ip_score``. Core
checks return 0, so configuration decides, and an admin can disable a check's score by setting
it to 0. A non-zero message score, positive or negative (bonuses), is added in SCORE mode; only
a positive IP score is sent to the IP score sink.

Debug output (spec 8.11): every check decision goes to the context's tap as one ``CHK`` line
with the phase, the check, its outcome (pass, error, exempt, reject, tempfail, would-reject,
monitor or score), the hit's effective message and IP scores and the duration in ms. Reaching
the score limit is a decision of its own (check ``score_limit``).
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from enum import Enum

from asspng.checks.base import (
    Check,
    CheckContext,
    CheckResult,
    CheckSettings,
    Mode,
    Phase,
    spared_from_ip_score,
)
from asspng.log.debug import CHK
from asspng.smtp.replies import R_SCORE, Reply

R_REJECT = Reply.of(554, "5.7.1 Rejected by policy")
R_TEMPFAIL = Reply.of(451, "4.7.1 Try again later")

_log = logging.getLogger("asspng.checks")


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"expected an integer setting, got {value!r}")
    return value


class Outcome(Enum):
    CONTINUE = "continue"
    REJECT = "reject"
    TEMPFAIL = "tempfail"


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reply: Reply | None = None
    would_reject: tuple[str, ...] = ()


class CheckEngine:
    def __init__(
        self,
        checks: Sequence[Check],
        ip_score_sink: Callable[[CheckContext, int, str], Awaitable[None]],
        on_error: Callable[[str, BaseException], None],
    ) -> None:
        self._checks = tuple(checks)
        self._sink = ip_score_sink
        self._on_error = on_error

    async def run_phase(self, phase: Phase, ctx: CheckContext) -> Decision:
        notes: list[str] = []
        testmode = bool(self._read(ctx, "testmode"))
        for check in self._checks:
            if phase not in check.phases:
                continue
            settings = self._settings(check, ctx)
            if settings is None or settings.mode is Mode.OFF:
                continue
            if self._exempt(check, ctx):
                _tap(ctx, phase, check.name, "exempt")
                continue
            started = time.perf_counter()
            result = await self._run_check(check, ctx, phase, settings.timeout_s)
            ms = (time.perf_counter() - started) * 1000
            if result is None or not result.hit:
                _tap(ctx, phase, check.name, "error" if result is None else "pass", ms=ms)
                continue
            await self._ip_score(ctx, settings, result)
            ended = self._apply(check, ctx, settings, result, testmode, notes)
            _tap(ctx, phase, check.name, _hit_outcome(settings.mode, testmode, result),
                 score=result.msg_score or settings.msg_score,
                 ip_score=result.ip_score or settings.ip_score, ms=ms, reason=result.reason)
            if ended is not None:
                self._record(ctx, notes)
                return Decision(ended[0], ended[1], tuple(notes))
        rejected = self._score_limit(ctx, phase, notes)
        self._record(ctx, notes)
        if rejected is not None:
            return Decision(Outcome.REJECT, rejected, tuple(notes))
        return Decision(Outcome.CONTINUE, None, tuple(notes))

    def _settings(self, check: Check, ctx: CheckContext) -> CheckSettings | None:
        prefix = f"checks.{check.name}"
        try:
            return CheckSettings(
                mode=Mode(ctx.setting(f"{prefix}.mode")),
                msg_score=_as_int(ctx.setting(f"{prefix}.msg_score")),
                ip_score=_as_int(ctx.setting(f"{prefix}.ip_score")),
                timeout_s=_as_int(ctx.setting(f"{prefix}.timeout_ms")) / 1000,
            )
        except Exception as exc:  # a broken setting must never block mail
            self._on_error(check.name, exc)
            return None

    @staticmethod
    def _exempt(check: Check, ctx: CheckContext) -> bool:
        return ("trusted" in check.exempt and ctx.session.trusted) or (
            "authenticated" in check.exempt and bool(ctx.session.auth_user))

    async def _run_check(self, check: Check, ctx: CheckContext, phase: Phase,
                         timeout_s: float) -> CheckResult | None:
        """The check's result; None when it failed (it counts as no hit)."""
        try:
            return await asyncio.wait_for(check.run(ctx, phase), timeout_s)
        except Exception as exc:  # includes TimeoutError; CancelledError propagates
            self._on_error(check.name, exc)
            return None

    async def _ip_score(self, ctx: CheckContext, settings: CheckSettings,
                        result: CheckResult) -> None:
        score = result.ip_score or settings.ip_score
        if score <= 0 or spared_from_ip_score(ctx.session):
            return
        try:
            await self._sink(ctx, score, result.reason)
        except Exception as exc:
            self._on_error("ip_score", exc)

    def _read(self, ctx: CheckContext, key: str) -> object:
        """Read a policy setting; on error report it and use the built-in default."""
        try:
            return ctx.setting(key)
        except Exception as exc:
            self._on_error(key, exc)
            setting = ctx.registry.get(key)
            return ctx.registry.coerce(key, setting.default)

    @staticmethod
    def _apply(check: Check, ctx: CheckContext, settings: CheckSettings, result: CheckResult,
               testmode: bool, notes: list[str]) -> tuple[Outcome, Reply] | None:
        """Apply one hit; return (outcome, reply) when it ends the phase."""
        note = f"{check.name}: {result.reason}"
        mode = settings.mode
        if mode is Mode.BLOCK and not testmode:
            if result.temporary:
                return Outcome.TEMPFAIL, result.reply or R_TEMPFAIL
            return Outcome.REJECT, result.reply or R_REJECT
        session_id = ctx.session.session_id
        if mode in (Mode.BLOCK, Mode.TEST):
            notes.append(note)
            _log.info("s=%s would reject: %s", session_id, note)
        elif mode is Mode.MONITOR:
            _log.info("s=%s monitor: %s", session_id, note)
        elif mode is Mode.SCORE:
            score = result.msg_score or settings.msg_score
            if score != 0:
                _add_score(ctx, note, score)
        return None

    def _score_limit(self, ctx: CheckContext, phase: Phase, notes: list[str]) -> Reply | None:
        """Update warn state; return R_SCORE when the message must be rejected."""
        txn = ctx.txn
        if txn is None:
            return None
        score = txn.score
        limit = _as_int(self._read(ctx, "scoring.limit"))
        warn = _as_int(self._read(ctx, "scoring.warn"))
        if score >= warn:
            txn.warn = True
        if score < limit:
            return None
        testmode = bool(self._read(ctx, "testmode"))
        _tap(ctx, phase, "score_limit", "would-reject" if testmode else "reject", score=score,
             reason=f"score {score} >= {limit}")
        if not testmode:
            return R_SCORE
        if not txn.score_limit_noted:
            txn.score_limit_noted = True
            note = f"score: {score} >= {limit}"
            notes.append(note)
            _log.info("s=%s would reject: %s", ctx.session.session_id, note)
        return None

    @staticmethod
    def _record(ctx: CheckContext, notes: list[str]) -> None:
        """Keep the notes on the transaction or, before MAIL, on the session (R62)."""
        if ctx.txn is not None:
            ctx.txn.would_reject.extend(notes)
            return
        kept = ctx.session.would_reject
        for note in notes:
            if note not in kept:  # a repeated phase (a second EHLO) notes nothing new
                kept.append(note)


def _hit_outcome(mode: Mode, testmode: bool, result: CheckResult) -> str:
    """The debug name of what a hit did (see ``CheckEngine._apply``)."""
    if mode is Mode.BLOCK and not testmode:
        return "tempfail" if result.temporary else "reject"
    if mode in (Mode.BLOCK, Mode.TEST):
        return "would-reject"
    return "monitor" if mode is Mode.MONITOR else "score"


def _tap(ctx: CheckContext, phase: Phase, check: str, outcome: str, *, score: int = 0,
         ip_score: int = 0, ms: float = 0.0, reason: str = "") -> None:
    """One ``CHK`` line on the session's debug tap; the reason comes last (free text)."""
    if ctx.tap is None:
        return
    text = (f"phase={phase.name} check={check} outcome={outcome} score={score} "
            f"ip_score={ip_score} ms={ms:.1f}")
    ctx.tap(CHK, f"{text} reason={reason}" if reason else text)


def _add_score(ctx: CheckContext, note: str, score: int) -> None:
    """Add a message score to the transaction or, before MAIL, to the session (R62)."""
    if ctx.txn is not None:
        ctx.txn.score += score
        ctx.txn.reasons.append((note, score))
        return
    session = ctx.session
    if (note, score) in session.reasons:  # a repeated phase must not count twice
        return
    session.score += score
    session.reasons.append((note, score))
