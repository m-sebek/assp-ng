# SPDX-License-Identifier: GPL-3.0-or-later
"""Application helpers (``app_tasks``, ``app_build``): loops, alerts, memory watch, health
counters, control commands, the reload change report and the component builders."""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import os
import sys
import time
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import pytest

from asspng.checks.base import CheckContext, Phase, SessionInfo
from asspng.config.loader import load_config
from asspng.config.model import CertificateConfig
from asspng.config.policy import PolicyResolver
from asspng.config.registry import Level
from asspng.config.settings import REGISTRY
from asspng.proxy.connections import ConnectionTracker
from asspng.log.debug import DebugRules
from asspng.service.alerts import Alerter
from asspng.service.app_build import build_runtime, host_port, journal_wanted
from asspng.service.app_tasks import (
    AlertingHealth,
    Alerts,
    RESTART_KEYS,
    MemoryWatch,
    close_writer,
    config_changes,
    control_handlers,
    pin_restart_keys,
    run_every,
    supervise,
)
from asspng.service.health import HealthState
from asspng.service.memory import MemoryGuard
from asspng.state.controller import StateController, StateMode
from asspng.state.memory_store import MemoryStore


class RecordingAlerter(Alerter):
    def __init__(self) -> None:
        super().__init__(email="", webhook="", smtp_server="127.0.0.1:25", min_interval_s=1800,
                         clock=time.time, instance="t")
        self.sent: list[tuple[str, str]] = []

    async def notify(self, event: str, message: str) -> bool:
        self.sent.append((event, message))
        return True


@pytest.fixture
def alerts() -> tuple[Alerts, RecordingAlerter, list[asyncio.Task[Any]]]:
    alerter = RecordingAlerter()
    tasks: list[asyncio.Task[Any]] = []

    def spawn(coro: Coroutine[Any, Any, object]) -> None:
        tasks.append(asyncio.ensure_future(coro))

    return Alerts(alerter, spawn), alerter, tasks


async def settle(tasks: list[asyncio.Task[Any]]) -> None:
    await asyncio.gather(*tasks)


# --- loops -------------------------------------------------------------------------------------


async def test_run_every_survives_errors(caplog: pytest.LogCaptureFixture) -> None:
    calls: list[int] = []

    async def job() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("secret detail")

    task = asyncio.create_task(run_every("tick", 0.01, job, immediately=True))
    while len(calls) < 3:
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert "tick failed: RuntimeError" in caplog.text
    assert "secret detail" not in caplog.text


async def test_run_every_waits_first_unless_immediately() -> None:
    calls: list[int] = []

    async def job() -> None:
        calls.append(1)

    task = asyncio.create_task(run_every("tick", 10, job))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == []


async def test_supervise_restarts_after_an_error(caplog: pytest.LogCaptureFixture) -> None:
    runs: list[int] = []

    async def run() -> None:
        runs.append(1)
        if len(runs) == 1:
            raise OSError("boom")

    await asyncio.wait_for(supervise("bus", run, retry_s=0.01), 2)
    assert len(runs) == 2
    assert "bus failed: OSError; restarting" in caplog.text


async def test_close_writer_aborts_a_stuck_close() -> None:
    class Stuck:
        aborted = False

        def __init__(self) -> None:
            self.transport = self

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            await asyncio.Event().wait()

        def abort(self) -> None:
            self.aborted = True

    writer = Stuck()
    await close_writer(writer, 0.01)  # type: ignore[arg-type]
    assert writer.aborted


# --- alerts ------------------------------------------------------------------------------------


@pytest.mark.parametrize("old,new,event", [
    (StateMode.NORMAL, StateMode.DEGRADED, "state-degraded"),
    (StateMode.DEGRADED, StateMode.NORMAL, "state-normal"),
    (StateMode.DEGRADED, StateMode.TEMPFAIL, "state-tempfail"),
    (StateMode.NORMAL, StateMode.TEMPFAIL, "state-tempfail"),
    (StateMode.TEMPFAIL, StateMode.NORMAL, None),
])
async def test_state_change_alerts(
    alerts: tuple[Alerts, RecordingAlerter, list[asyncio.Task[Any]]],
    old: StateMode, new: StateMode, event: str | None,
) -> None:
    sender, alerter, tasks = alerts
    sender.state_changed(old, new, "why")
    await settle(tasks)
    assert [e for e, _ in alerter.sent] == ([event] if event else [])


async def test_database_and_certificate_alerts(
    alerts: tuple[Alerts, RecordingAlerter, list[asyncio.Task[Any]]]
) -> None:
    sender, alerter, tasks = alerts
    sender.database_down(299)
    sender.database_down(300)
    sender.certificates({"far": 14, "near": 13})
    sender.certificates({"far": 60})
    await settle(tasks)
    assert [e for e, _ in alerter.sent] == ["database-down", "certificate-expiry"]
    assert alerter.sent[1][1].endswith("near: 13 days")


async def test_alerting_health_alerts_on_the_third_failure_in_a_row(
    alerts: tuple[Alerts, RecordingAlerter, list[asyncio.Task[Any]]]
) -> None:
    sender, alerter, tasks = alerts
    health = AlertingHealth(HealthState(), sender.backend_down)
    results = [health.backend_result("inbound", ok) for ok in
               (False, False, True, False, False, False, False)]
    health.record("accepted")
    await settle(tasks)
    assert results == [1, 2, 0, 1, 2, 3, 4]
    assert alerter.sent == [("backend-down-inbound",
                             "the backend of listener inbound failed 3 times in a row")]


class FakeGuard(MemoryGuard):
    def __init__(self) -> None:
        super().__init__(1)
        self.over = False

    def over_limit(self) -> bool:
        return self.over


async def test_memory_watch_alerts_once_per_crossing_and_tempfails_when_degraded(
    alerts: tuple[Alerts, RecordingAlerter, list[asyncio.Task[Any]]]
) -> None:
    sender, alerter, tasks = alerts
    state = StateController(MemoryStore(10, time.time), MemoryStore(10, time.time),
                            clock=time.time, on_change=lambda old, new, reason: None)
    guard = FakeGuard()
    watch = MemoryWatch(guard, 360, state, sender)
    watch.check()
    guard.over = True
    watch.check()
    watch.check()
    assert state.mode is StateMode.NORMAL  # over the limit, but Redis is fine
    state._switch(StateMode.DEGRADED, "test")
    watch.check()
    assert state.mode is StateMode.TEMPFAIL
    guard.over = False
    watch.check()
    guard.over = True
    watch.check()
    await settle(tasks)
    assert [e for e, _ in alerter.sent] == ["memory-limit", "memory-limit"]


# --- control commands --------------------------------------------------------------------------


@pytest.fixture
def handlers(tmp_path: Path) -> dict[str, Any]:
    rules = DebugRules(tmp_path / "rules.json", time.time, default_s=60, max_s=600,
                       max_all_s=120)
    return control_handlers(rules, lambda: {"status": "ok"})


async def test_debug_commands(handlers: dict[str, Any]) -> None:
    first = await handlers["debug.on"]({"kind": "from", "value": "A@Example.org"})
    assert (first["kind"], first["value"], first["headers"]) == ("from", "a@example.org", False)
    second = await handlers["debug.on"]({"kind": "all", "duration_s": 60, "headers": True})
    assert await handlers["debug.list"]({}) == [first, second]
    assert await handlers["debug.off"]({"id": "nope"}) == {"removed": 0}
    assert await handlers["debug.off"]({"id": first["id"]}) == {"removed": 1}
    assert await handlers["debug.off"]({"all": True}) == {"removed": 1}
    assert await handlers["status"]({}) == {"status": "ok"}


@pytest.mark.parametrize("command,args,message", [
    ("debug.on", {"kind": "planet"}, "unknown rule kind"),
    ("debug.on", {}, "unknown rule kind"),
    ("debug.on", {"kind": "ip", "value": 7}, "value must be of type str"),
    ("debug.on", {"kind": "ip", "value": "1.2.3.4", "duration_s": True}, "duration_s must be"),
    ("debug.on", {"kind": "ip", "value": "1.2.3.4", "headers": "yes"}, "headers must be"),
    ("debug.on", {"kind": "all", "duration_s": 3600}, "exceeds the maximum"),
    ("debug.on", {"kind": "ip", "value": "not-an-ip"}, ""),
    ("debug.off", {}, "give the rule id or all"),
    ("debug.off", {"id": 5}, "id must be of type str"),
])
async def test_debug_command_errors(handlers: dict[str, Any], command: str,
                                    args: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await handlers[command](args)


# --- reload report -----------------------------------------------------------------------------


def test_config_changes(etc_dir: Path) -> None:
    old = load_config(etc_dir)
    (etc_dir / "default.toml").write_text("[scoring]\nlimit = 60\n")
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml").write_text("testmode = true\n")
    new = load_config(etc_dir)
    new = dataclasses.replace(
        new, system={**new.system, "redis.url": "redis://elsewhere/0", "timeouts.command": 9},
        listeners=(dataclasses.replace(new.listeners[0], port=2525),),
        certificates=(CertificateConfig("main", ("a.test",), Path("/c"), Path("/k")),))
    changes = config_changes(old, new)
    assert changes == [
        (f"redis.url changed in {etc_dir / 'assp-ng.toml'} (system)", "restart required"),
        (f"timeouts.command changed in {etc_dir / 'assp-ng.toml'} (system)", ""),
        (f"[[listener]] changed in {etc_dir / 'assp-ng.toml'} (system)", "restart required"),
        (f"[[tls.certificate]] changed in {etc_dir / 'assp-ng.toml'} (system)", ""),
        (f"scoring.limit changed in {etc_dir / 'default.toml'} (recipient)", ""),
        (f"testmode changed in {etc_dir / 'domain.d' / 'example.com.toml'} (recipient)", ""),
    ]
    assert "elsewhere" not in repr(changes)  # values are never shown
    assert config_changes(new, new) == []


def test_spool_change_needs_a_restart(etc_dir: Path) -> None:
    """C8: the spool directory is created (0700) and emptied only at start."""
    old = load_config(etc_dir)
    new = dataclasses.replace(old, system={**old.system, "paths.spool": "/srv/other-spool"})
    assert config_changes(old, new) == [
        (f"paths.spool changed in {etc_dir / 'assp-ng.toml'} (system)", "restart required")]


def test_restart_keys_are_system_settings() -> None:
    assert all(REGISTRY.get(key).level is Level.SYSTEM for key in RESTART_KEYS)


def test_pin_restart_keys_keeps_the_running_values(etc_dir: Path) -> None:
    """C8: a reload changes new sessions only in what does not need a restart."""
    running = load_config(etc_dir)
    changed = {key: f"/changed/{key}" for key in RESTART_KEYS}
    loaded = dataclasses.replace(running, system={
        **running.system, **changed, "hostname": "new.example"})
    pinned = pin_restart_keys(running, loaded)
    assert {key: pinned.get(key) for key in RESTART_KEYS} == {
        key: running.get(key) for key in RESTART_KEYS}
    assert pinned.get("hostname") == "new.example"
    assert dataclasses.replace(pinned, system=loaded.system) == loaded  # nothing else changes
    with pytest.raises(TypeError):
        pinned.system["paths.spool"] = "/x"  # type: ignore[index]
    assert len(config_changes(running, loaded)) == len(RESTART_KEYS) + 1  # still reported


# --- builders ----------------------------------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    ("127.0.0.1:8025", ("127.0.0.1", 8025)),
    ("[::1]:8025", ("::1", 8025)),
    ("localhost:0", ("localhost", 0)),
])
def test_host_port(etc_dir: Path, text: str, expected: tuple[str, int]) -> None:
    config = load_config(etc_dir)
    config = dataclasses.replace(config, system={**config.system, "health.listen": text})
    assert host_port(config, "health.listen") == expected


@pytest.mark.parametrize("text", ["8025", ":8025", "host:", "host:http", "host:70000"])
def test_host_port_errors(etc_dir: Path, text: str) -> None:
    config = load_config(etc_dir)
    config = dataclasses.replace(config, system={**config.system, "health.listen": text})
    with pytest.raises(Exception, match="must look like host:port"):
        host_port(config, "health.listen")


def test_journal_only_when_stderr_is_the_journal_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JOURNAL_STREAM", "0:0")
    assert journal_wanted() is False
    monkeypatch.delenv("JOURNAL_STREAM")
    assert journal_wanted() is False
    st = os.fstat(sys.stderr.fileno())
    monkeypatch.setenv("JOURNAL_STREAM", f"{st.st_dev}:{st.st_ino}")
    assert journal_wanted() is True  # python3-systemd is a dependency


async def test_built_engine_scores_the_penalty_box(etc_dir: Path) -> None:
    config = load_config(etc_dir)
    config = dataclasses.replace(config, system={**config.system, "limits.net.concurrent": 1})
    state = StateController(MemoryStore(100, time.time), MemoryStore(100, time.time),
                            clock=time.time, on_change=lambda old, new, reason: None)
    errors: list[str] = []
    runtime = build_runtime(config, state, time.time, lambda name, exc: errors.append(name))
    client = ipaddress.ip_address("1.2.3.4")
    connections = ConnectionTracker()
    for _ in range(2):
        connections.acquire("1.2.3.4/32")
    info = SessionInfo(
        session_id="s", client_ip=client, net_key="1.2.3.4/32",
        listener=config.listeners[0], tls_version=None, auth_user=None, helo=None,
        trusted=False, exempt=False, messages=0, protocol_errors=0, invalid_recipients=0)
    ctx = CheckContext(session=info, txn=None, config=config,
                       default_policy=PolicyResolver(config).default_policy(),
                       sender_policy=None, state=state, clock=time.time,
                       connections=connections)
    decision = await runtime.engine.run_phase(Phase.CONNECT, ctx)
    assert decision.reply is not None and decision.reply.code == 421  # too many connections
    status = await runtime.penalty_box.status("1.2.3.4/32")
    assert status.score == 5  # checks.conn_limits.ip_score
    assert errors == []
    assert runtime.policies.default_policy().values["scoring.limit"] == 50


def test_alerts_log_state_changes(caplog: pytest.LogCaptureFixture) -> None:
    sent: list[object] = []

    def spawn(coro: Coroutine[Any, Any, object]) -> None:
        sent.append(coro)
        coro.close()

    caplog.set_level(logging.INFO, logger="asspng.service")
    Alerts(RecordingAlerter(), spawn).state_changed(StateMode.NORMAL, StateMode.DEGRADED, "x")
    assert "state mode NORMAL -> DEGRADED: x" in caplog.text
    assert len(sent) == 1
