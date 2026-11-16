# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import dataclasses
import logging
import re
from pathlib import Path

import pytest

from asspng.checks.base import (
    NEUTRAL,
    CheckContext,
    CheckResult,
    Phase,
    SessionInfo,
    TransactionInfo,
)
from asspng.checks.engine import R_REJECT, R_TEMPFAIL, CheckEngine, Decision, Outcome
from asspng.config.loader import load_config
from asspng.config.policy import PolicyResolver
from asspng.net.ipnet import parse_ip
from asspng.proxy.connections import ConnectionTracker
from asspng.smtp.address import Address
from asspng.smtp.replies import R_SCORE, Reply
from asspng.state.memory_store import MemoryStore


class Stub:
    def __init__(self, name: str, result: CheckResult = NEUTRAL, *,
                 exempt: frozenset[str] = frozenset(), raises: Exception | None = None,
                 delay: float = 0.0, phases: frozenset[Phase] | None = None) -> None:
        self.name = name
        self.phases = phases or frozenset(Phase)
        self.exempt = exempt
        self.result, self.raises, self.delay = result, raises, delay
        self.calls = 0

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raises:
            raise self.raises
        return self.result


class Env:
    def __init__(self, etc_dir: Path, system: dict[str, object] | None = None,
                 ip: str = "8.8.8.8", with_txn: bool = True,
                 domain_policy: str = "") -> None:
        if domain_policy:
            (etc_dir / "domain.d").mkdir()
            (etc_dir / "domain.d" / "example.com.toml").write_text(domain_policy)
        snap = load_config(etc_dir)
        snap = dataclasses.replace(snap, system={**snap.system, **(system or {})})
        resolver = PolicyResolver(snap)
        self.session = SessionInfo(
            "s1", parse_ip(ip), ip + "/32", snap.listeners[0], None, None, None,
            False, False, 0, 0, 0)
        rcpt = Address("bob", "example.com")
        self.txn = TransactionInfo(
            1, None, [rcpt], rcpt, resolver.for_recipient(rcpt), 0, [], [], False,
            None) if with_txn else None
        self.ctx = CheckContext(
            self.session, self.txn, snap, resolver.default_policy(), resolver.for_sender(""),
            MemoryStore(100, lambda: 0.0), lambda: 0.0, ConnectionTracker())
        self.sink_calls: list[tuple[int, str]] = []
        self.errors: list[tuple[str, BaseException]] = []

    async def _sink(self, ctx: CheckContext, score: int, reason: str) -> None:
        self.sink_calls.append((score, reason))

    def engine(self, *checks: Stub) -> CheckEngine:
        return CheckEngine(checks, self._sink, lambda n, e: self.errors.append((n, e)))

    async def run(self, *checks: Stub, phase: Phase = Phase.RCPT) -> Decision:
        return await self.engine(*checks).run_phase(phase, self.ctx)


def mode(name: str, value: str, **extra: object) -> dict[str, object]:
    out: dict[str, object] = {f"checks.{name}.mode": value}
    out.update({f"checks.{name}.{k}": v for k, v in extra.items()})
    return out


HIT = CheckResult(True, reason="bad", ip_score=5)


async def test_block_rejects(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    d = await env.run(Stub("penalty_box", HIT))
    assert (d.outcome, d.reply) == (Outcome.REJECT, R_REJECT)
    custom = Reply.of(550, "5.7.1 nope")
    d = await env.run(Stub("penalty_box", CheckResult(True, reason="x", reply=custom)))
    assert d.reply == custom


async def test_temporary_block_tempfails(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    d = await env.run(Stub("penalty_box", CheckResult(True, reason="x", temporary=True)))
    assert (d.outcome, d.reply) == (Outcome.TEMPFAIL, R_TEMPFAIL)


async def test_testmode_converts_block_to_would_reject(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"), domain_policy="testmode = true\n")
    d = await env.run(Stub("penalty_box", HIT))
    assert d.outcome is Outcome.CONTINUE
    assert d.would_reject == ("penalty_box: bad",)
    assert env.txn is not None and env.txn.would_reject == ["penalty_box: bad"]


async def test_test_mode_check_records_would_reject(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "test"))
    d = await env.run(Stub("penalty_box", HIT))
    assert d.outcome is Outcome.CONTINUE and d.would_reject == ("penalty_box: bad",)


async def test_would_reject_without_txn_is_kept_on_the_session(etc_dir: Path) -> None:
    """R62: CONNECT/HELO/AUTH notes reach every later transaction through the session."""
    env = Env(etc_dir, mode("penalty_box", "test"), with_txn=False)
    d = await env.run(Stub("penalty_box", HIT), phase=Phase.CONNECT)
    assert d.would_reject == ("penalty_box: bad",)
    assert env.session.would_reject == ["penalty_box: bad"]


async def test_repeated_session_phase_keeps_one_note_and_score(etc_dir: Path) -> None:
    """A second EHLO runs the HELO checks again; the same hit must not count twice."""
    env = Env(etc_dir, {**mode("penalty_box", "test"),
                        **mode("session_limits", "score", msg_score=5)}, with_txn=False)
    for _ in range(2):
        await env.run(Stub("penalty_box", HIT), Stub("session_limits", HIT), phase=Phase.HELO)
    assert env.session.would_reject == ["penalty_box: bad"]
    assert (env.session.score, env.session.reasons) == (5, [("session_limits: bad", 5)])


async def test_score_accumulates_and_limit_rejects(etc_dir: Path) -> None:
    env = Env(etc_dir, {**mode("penalty_box", "score", msg_score=30),
                        **mode("session_limits", "score", msg_score=25)})
    hit = CheckResult(True, reason="r")
    d = await env.run(Stub("penalty_box", hit))
    assert d.outcome is Outcome.CONTINUE
    assert env.txn is not None and env.txn.score == 30
    assert env.txn.warn is False
    d = await env.run(Stub("session_limits", hit))
    assert (d.outcome, d.reply) == (Outcome.REJECT, R_SCORE)
    assert env.txn.score == 55 and env.txn.warn is True
    assert env.txn.reasons == [("penalty_box: r", 30), ("session_limits: r", 25)]


async def test_score_limit_in_testmode_notes_once(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "score", msg_score=60),
              domain_policy="testmode = true\n")
    d = await env.run(Stub("penalty_box", NEUTRAL))
    assert d.outcome is Outcome.CONTINUE
    d = await env.run(Stub("penalty_box", CheckResult(True, reason="r")))
    assert d.outcome is Outcome.CONTINUE and d.would_reject == ("score: 60 >= 50",)
    d = await env.run(Stub("penalty_box", NEUTRAL))
    assert d.would_reject == ()
    assert env.txn is not None and env.txn.would_reject == ["score: 60 >= 50"]


async def test_warn_marks(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "score", msg_score=40))
    d = await env.run(Stub("penalty_box", CheckResult(True, reason="r")))
    assert d.outcome is Outcome.CONTINUE
    assert env.txn is not None and env.txn.warn is True


async def test_score_without_txn_is_kept_on_the_session(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "score", msg_score=99, ip_score=3), with_txn=False)
    d = await env.run(Stub("penalty_box", CheckResult(True, reason="r")),
                      phase=Phase.CONNECT)
    assert d.outcome is Outcome.CONTINUE  # the score limit applies from MAIL on
    assert env.sink_calls == [(3, "r")]
    assert (env.session.score, env.session.reasons) == (99, [("penalty_box: r", 99)])


async def test_monitor_logs_only(etc_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    env = Env(etc_dir, mode("penalty_box", "monitor"))
    with caplog.at_level(logging.INFO, logger="asspng.checks"):
        d = await env.run(Stub("penalty_box", HIT))
    assert d == Decision(Outcome.CONTINUE)
    assert env.txn is not None and (env.txn.score, env.txn.would_reject) == (0, [])
    assert "penalty_box: bad" in caplog.text


async def test_off_skipped(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "off"))
    stub = Stub("penalty_box", HIT)
    assert (await env.run(stub)).outcome is Outcome.CONTINUE
    assert stub.calls == 0


async def test_phase_filter(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    stub = Stub("penalty_box", HIT, phases=frozenset({Phase.BODY}))
    assert (await env.run(stub, phase=Phase.RCPT)).outcome is Outcome.CONTINUE
    assert stub.calls == 0


async def test_exempt_authenticated_skipped(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    env.session.auth_user = "bob@example.com"
    stub = Stub("penalty_box", HIT, exempt=frozenset({"authenticated"}))
    assert (await env.run(stub)).outcome is Outcome.CONTINUE
    assert stub.calls == 0
    env.session.auth_user = None
    env.session.trusted = True
    assert (await env.run(Stub("penalty_box", HIT, exempt=frozenset({"trusted"})))
            ).outcome is Outcome.CONTINUE
    assert (await env.run(Stub("penalty_box", HIT))).outcome is Outcome.REJECT


async def test_exception_is_neutral_and_reported(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    boom = RuntimeError("boom")
    d = await env.run(Stub("penalty_box", raises=boom))
    assert d.outcome is Outcome.CONTINUE
    assert env.errors == [("penalty_box", boom)]


async def test_timeout_is_neutral(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block", timeout_ms=10))
    d = await env.run(Stub("penalty_box", HIT, delay=1.0))
    assert d.outcome is Outcome.CONTINUE
    assert len(env.errors) == 1 and isinstance(env.errors[0][1], TimeoutError)


async def test_cancellation_propagates(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    with pytest.raises(asyncio.CancelledError):
        await env.run(Stub("penalty_box", raises=asyncio.CancelledError()))
    assert env.errors == []


async def test_sink_error_is_neutral(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "monitor"))

    async def bad_sink(ctx: CheckContext, score: int, reason: str) -> None:
        raise RuntimeError("sink")

    engine = CheckEngine([Stub("penalty_box", HIT)], bad_sink,
                         lambda n, e: env.errors.append((n, e)))
    assert (await engine.run_phase(Phase.RCPT, env.ctx)).outcome is Outcome.CONTINUE
    assert [name for name, _ in env.errors] == ["ip_score"]


async def test_sink_error_does_not_change_block_decision(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))

    async def bad_sink(ctx: CheckContext, score: int, reason: str) -> None:
        raise RuntimeError("sink")

    engine = CheckEngine([Stub("penalty_box", HIT)], bad_sink,
                         lambda n, e: env.errors.append((n, e)))
    d = await engine.run_phase(Phase.RCPT, env.ctx)
    assert (d.outcome, d.reply) == (Outcome.REJECT, R_REJECT)
    assert [name for name, _ in env.errors] == ["ip_score"]


async def test_ip_score_sent_for_public_client(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "monitor"))
    await env.run(Stub("penalty_box", HIT))
    assert env.sink_calls == [(5, "bad")]


async def test_ip_score_not_sent_for_private_or_trusted(etc_dir: Path) -> None:
    stub = Stub("penalty_box", HIT)
    private = Env(etc_dir, mode("penalty_box", "monitor"), ip="192.168.1.9")
    await private.run(stub)
    assert private.sink_calls == []
    for attr, value in (("trusted", True), ("exempt", True), ("auth_user", "u@example.com")):
        env = Env(etc_dir, mode("penalty_box", "monitor"))
        setattr(env.session, attr, value)
        await env.run(stub)
        assert env.sink_calls == [], attr


@pytest.mark.parametrize("score,testmode,outcome,noted", [
    (50, False, Outcome.REJECT, False),
    (49, False, Outcome.CONTINUE, False),
    (50, True, Outcome.CONTINUE, True),
    (49, True, Outcome.CONTINUE, False),
])
async def test_score_limit_boundary(etc_dir: Path, score: int, testmode: bool,
                                    outcome: Outcome, noted: bool) -> None:
    env = Env(etc_dir, mode("penalty_box", "score", msg_score=score),
              domain_policy=f"testmode = {str(testmode).lower()}\n")
    d = await env.run(Stub("penalty_box", CheckResult(True, reason="r")))
    assert d.outcome is outcome
    assert d.would_reject == (("score: 50 >= 50",) if noted else ())


@pytest.mark.parametrize("score,warn", [(35, True), (34, False)])
async def test_warn_boundary(etc_dir: Path, score: int, warn: bool) -> None:
    env = Env(etc_dir, mode("penalty_box", "score", msg_score=score))
    await env.run(Stub("penalty_box", CheckResult(True, reason="r")))
    assert env.txn is not None and env.txn.warn is warn


async def test_result_scores_override_configured(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "score", msg_score=10, ip_score=2))
    await env.run(Stub("penalty_box", CheckResult(True, msg_score=7, ip_score=4, reason="r")))
    assert env.txn is not None and env.txn.score == 7
    assert env.sink_calls == [(4, "r")]
    await env.run(Stub("penalty_box", CheckResult(True, reason="r")))
    assert env.txn.score == 17 and env.sink_calls[-1] == (2, "r")


async def test_negative_message_score_lowers_total(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "score"))
    assert env.txn is not None
    env.txn.score = 20
    await env.run(Stub("penalty_box", CheckResult(True, msg_score=-5, reason="r")))
    assert env.txn.score == 15 and env.txn.reasons == [("penalty_box: r", -5)]


async def test_zero_ip_score_skips_sink(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "monitor", ip_score=0))
    await env.run(Stub("penalty_box", CheckResult(True, reason="r")))
    await env.run(Stub("penalty_box", CheckResult(True, reason="r", ip_score=-3)))
    assert env.sink_calls == []


async def test_would_reject_is_logged(etc_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    env = Env(etc_dir, mode("penalty_box", "test"))
    with caplog.at_level(logging.INFO, logger="asspng.checks"):
        await env.run(Stub("penalty_box", HIT))
    assert "s=s1 would reject: penalty_box: bad" in caplog.text


async def test_monitor_and_score_limit_logs_name_the_session(
        etc_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    env = Env(etc_dir, {**mode("penalty_box", "monitor"),
                        **mode("session_limits", "score", msg_score=60)},
              domain_policy="testmode = true\n")
    with caplog.at_level(logging.INFO, logger="asspng.checks"):
        await env.run(Stub("penalty_box", HIT), Stub("session_limits", HIT))
    assert "s=s1 monitor: penalty_box: bad" in caplog.text
    assert "s=s1 would reject: score: 60 >= 50" in caplog.text


async def test_broken_setting_reported_and_check_skipped(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "bogus"))
    stub = Stub("penalty_box", HIT)
    assert (await env.run(stub)).outcome is Outcome.CONTINUE
    assert stub.calls == 0
    assert [n for n, _ in env.errors] == ["penalty_box"]


async def test_broken_policy_setting_uses_defaults(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "score", msg_score=60))
    assert env.txn is not None and env.txn.policy is not None
    values = dict(env.txn.policy.values)
    for key in ("testmode", "scoring.limit", "scoring.warn"):
        del values[key]
    env.txn.policy = dataclasses.replace(env.txn.policy, values=values)
    d = await env.run(Stub("penalty_box", CheckResult(True, reason="r")))
    assert (d.outcome, d.reply) == (Outcome.REJECT, R_SCORE)
    assert {n for n, _ in env.errors} == {"testmode", "scoring.limit", "scoring.warn"}
    assert env.txn.warn is True


async def test_non_exempt_check_runs_for_authenticated(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    env.session.auth_user = "bob@example.com"
    stub = Stub("penalty_box", HIT, exempt=frozenset({"trusted"}))
    assert (await env.run(stub)).outcome is Outcome.REJECT
    assert stub.calls == 1


async def test_testmode_without_txn_uses_default_policy(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("testmode = true\n")
    env = Env(etc_dir, mode("penalty_box", "block"), with_txn=False)
    d = await env.run(Stub("penalty_box", HIT), phase=Phase.CONNECT)
    assert d.outcome is Outcome.CONTINUE and d.would_reject == ("penalty_box: bad",)


# --- debug tap (spec 8.11) ------------------------------------------------------------------

CHK_MS = r"ms=\d+\.\d"


def tapped(env: Env) -> list[str]:
    lines: list[str] = []
    env.ctx.tap = lambda direction, text: lines.append(f"{direction} {text}")
    return lines


async def test_tap_gets_one_chk_line_per_decision(etc_dir: Path) -> None:
    env = Env(etc_dir, {**mode("penalty_box", "score", msg_score=3, ip_score=0),
                        **mode("session_limits", "block"), **mode("auth_limits", "monitor"),
                        **mode("user_rate", "block"), **mode("conn_limits", "block")})
    lines = tapped(env)
    env.session.trusted = True
    d = await env.run(
        Stub("penalty_box", CheckResult(True, reason="listed")),
        Stub("session_limits", raises=RuntimeError("boom")),
        Stub("auth_limits", CheckResult(True, reason="watch me", ip_score=4)),
        Stub("user_rate", HIT, exempt=frozenset({"trusted"})),
        Stub("conn_limits", CheckResult(True, reason="too many", temporary=True)),
        Stub("conn_limits", HIT),  # never runs: the phase ended
        phase=Phase.MAIL)
    assert d.outcome is Outcome.TEMPFAIL
    expected = [
        rf"CHK phase=MAIL check=penalty_box outcome=score score=3 ip_score=0 {CHK_MS} "
        r"reason=listed",
        rf"CHK phase=MAIL check=session_limits outcome=error score=0 ip_score=0 {CHK_MS}",
        rf"CHK phase=MAIL check=auth_limits outcome=monitor score=\d+ ip_score=4 {CHK_MS} "
        r"reason=watch me",
        r"CHK phase=MAIL check=user_rate outcome=exempt score=0 ip_score=0 ms=0\.0",
        rf"CHK phase=MAIL check=conn_limits outcome=tempfail score=\d+ ip_score=\d+ {CHK_MS} "
        r"reason=too many",
    ]
    assert len(lines) == len(expected), lines
    for pattern, line in zip(expected, lines):
        assert re.fullmatch(pattern, line), (pattern, line)


async def test_tap_pass_line_carries_the_duration(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    lines = tapped(env)
    await env.run(Stub("penalty_box", delay=0.05), phase=Phase.CONNECT)
    [line] = lines
    match = re.fullmatch(r"CHK phase=CONNECT check=penalty_box outcome=pass score=0 "
                         r"ip_score=0 ms=(\d+\.\d)", line)
    assert match is not None, line
    assert float(match.group(1)) >= 50


async def test_tap_reports_a_block_in_test_mode_as_would_reject(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"), domain_policy="testmode = true\n")
    lines = tapped(env)
    await env.run(Stub("penalty_box", HIT))
    [line] = lines
    assert line.startswith("CHK phase=RCPT check=penalty_box outcome=would-reject ")


@pytest.mark.parametrize("testmode,outcome", [(False, "reject"), (True, "would-reject")])
async def test_tap_reports_the_score_limit(etc_dir: Path, testmode: bool, outcome: str) -> None:
    env = Env(etc_dir, mode("conn_limits", "score", msg_score=60),
              domain_policy="testmode = true\n" if testmode else "")
    lines = tapped(env)
    await env.run(Stub("conn_limits", CheckResult(True, reason="spammy")))
    assert len(lines) == 2, lines
    assert lines[0].startswith("CHK phase=RCPT check=conn_limits outcome=score score=60 ")
    assert lines[1] == (f"CHK phase=RCPT check=score_limit outcome={outcome} score=60 "
                        "ip_score=0 ms=0.0 reason=score 60 >= 50")


async def test_no_tap_no_lines(etc_dir: Path) -> None:
    env = Env(etc_dir, mode("penalty_box", "block"))
    assert env.ctx.tap is None
    assert (await env.run(Stub("penalty_box", HIT))).outcome is Outcome.REJECT
