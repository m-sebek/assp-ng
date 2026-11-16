# SPDX-License-Identifier: GPL-3.0-or-later
"""Pieces of the application that need no application state: background loops, alerts, the
memory watch, the alerting health counters, the control socket commands and the reload change
report."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, TypeVar

from asspng.config.model import ConfigSnapshot
from asspng.config.settings import REGISTRY
from asspng.log.debug import DebugRule, DebugRules, RuleKind
from asspng.service.alerts import Alerter
from asspng.service.control import Handler
from asspng.service.health import HealthState
from asspng.service.memory import MemoryGuard
from asspng.state.controller import StateController, StateMode

_log = logging.getLogger("asspng.service")
_T = TypeVar("_T")

BACKEND_ALERT_FAILURES = 3  # consecutive backend failures that raise an alert (spec 8.6)
CERT_WARN_DAYS = 14
DB_DOWN_ALERT_S = 300.0

# SYSTEM settings that are read only at start: a reload keeps their running values
# (``pin_restart_keys``) and logs that they need a restart.
RESTART_KEYS = frozenset({
    "instance", "redis.url", "redis.key_prefix", "redis.op_timeout_ms",
    "state.on_redis_failure", "state.failures_to_degrade", "state.unreachable_to_degrade_s",
    "state.probe_interval_s", "state.memory_max_entries", "database.url",
    "domains.refresh_interval_s", "paths.spool", "paths.cache", "paths.run", "paths.log_dir",
    "health.listen", "alerts.email", "alerts.webhook", "alerts.smtp_server",
    "alerts.min_interval", "log.level",
    "debug.max_size_mb", "debug.default_duration", "debug.max_duration",
    "debug.max_duration_all", "memory.soft_limit_mb", "memory.idle_trim_after_s",
    "memory.trim_interval_s", "buffer.memory_total", "timeouts.tls_handshake", "timeouts.ptr",
})


# --- tasks -------------------------------------------------------------------------------------


async def cancel_all(tasks: set[asyncio.Task[Any]]) -> None:
    """Cancel the tasks and wait until they are done."""
    pending = list(tasks)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def close_writer(writer: asyncio.StreamWriter, timeout_s: float) -> None:
    """Close a client connection; abort it when the close does not finish in time."""
    try:
        writer.close()
        async with asyncio.timeout(timeout_s):
            await writer.wait_closed()
    except Exception:
        writer.transport.abort()


async def run_every(name: str, interval_s: float, job: Callable[[], Awaitable[None]], *,
                    immediately: bool = False) -> None:
    """Run ``job`` every ``interval_s`` until cancelled. An exception is logged by its type
    and the loop goes on."""
    if not immediately:
        await asyncio.sleep(interval_s)
    while True:
        try:
            await job()
        except Exception as exc:
            _log.warning("%s failed: %s", name, type(exc).__name__)
        await asyncio.sleep(interval_s)


async def supervise(name: str, run: Callable[[], Awaitable[None]], retry_s: float = 5.0) -> None:
    """Await ``run()`` until it returns; after an exception (logged by its type) start it
    again after ``retry_s``."""
    while True:
        try:
            await run()
            return
        except Exception as exc:
            _log.warning("%s failed: %s; restarting in %.0f s", name, type(exc).__name__,
                         retry_s)
        await asyncio.sleep(retry_s)


# --- alerts ------------------------------------------------------------------------------------


class Alerts:
    """The proxy's alerts (spec 8.6). Each delivery runs as a task handed to ``spawn``, so no
    caller waits for email or webhook delivery."""

    def __init__(self, alerter: Alerter,
                 spawn: Callable[[Coroutine[Any, Any, object]], None]) -> None:
        self._alerter = alerter
        self._spawn = spawn

    def send(self, event: str, message: str) -> None:
        self._spawn(self._alerter.notify(event, message))

    def state_changed(self, old: StateMode, new: StateMode, reason: str) -> None:
        """``StateController``'s ``on_change``: entering or leaving DEGRADED, entering
        TEMPFAIL."""
        level = logging.INFO if new is StateMode.NORMAL else logging.WARNING
        _log.log(level, "state mode %s -> %s: %s", old.name, new.name, reason)
        if StateMode.DEGRADED in (old, new) or new is StateMode.TEMPFAIL:
            self.send(f"state-{new.value}",
                      f"state mode changed from {old.name} to {new.name}: {reason}")

    def backend_down(self, listener: str, failures: int) -> None:
        self.send(f"backend-down-{listener}",
                  f"the backend of listener {listener} failed {failures} times in a row")

    def database_down(self, down_s: float) -> None:
        if down_s >= DB_DOWN_ALERT_S:
            self.send("database-down", f"the database has been unreachable for {down_s:.0f} s")

    def certificates(self, days_left: Mapping[str, int]) -> None:
        soon = {name: days for name, days in sorted(days_left.items()) if days < CERT_WARN_DAYS}
        if soon:
            text = ", ".join(f"{name}: {days} days" for name, days in soon.items())
            _log.warning("TLS certificates expire soon (%s)", text)
            self.send("certificate-expiry",
                      f"TLS certificates expire in less than {CERT_WARN_DAYS} days: {text}")


class MemoryWatch:
    """One alert per crossing of the memory soft limit; while DEGRADED, being over it switches
    the state to TEMPFAIL (spec 6.2, 8.7). Sessions refuse new connections themselves."""

    def __init__(self, guard: MemoryGuard, limit_mb: int, state: StateController,
                 alerts: Alerts) -> None:
        self._guard = guard
        self._limit_mb = limit_mb
        self._state = state
        self._alerts = alerts
        self._over = False

    def check(self) -> None:
        over = self._guard.over_limit()
        if over and not self._over:
            message = f"memory soft limit of {self._limit_mb} MB reached: new connections " \
                      "are refused"
            _log.warning("%s", message)
            self._alerts.send("memory-limit", message)
        if over and self._state.mode is StateMode.DEGRADED:
            self._state.force_tempfail("memory soft limit reached while degraded")
        self._over = over


# --- health ------------------------------------------------------------------------------------


class AlertingHealth:
    """The sessions' ``HealthCounters``: ``HealthState`` plus a callback when a listener's
    backend fails ``BACKEND_ALERT_FAILURES`` times in a row."""

    def __init__(self, state: HealthState, on_backend_down: Callable[[str, int], None]) -> None:
        self._state = state
        self._on_backend_down = on_backend_down

    def record(self, event: str) -> None:
        self._state.record(event)

    def backend_result(self, listener: str, ok: bool) -> int:
        failures = self._state.backend_result(listener, ok)
        if failures == BACKEND_ALERT_FAILURES:
            self._on_backend_down(listener, failures)
        return failures


# --- control socket ----------------------------------------------------------------------------


def _rule_view(rule: DebugRule) -> dict[str, object]:
    return {"id": rule.id, "kind": rule.kind.value, "value": rule.value,
            "expires_at": rule.expires_at, "headers": rule.headers}


def _kind(args: Mapping[str, object]) -> RuleKind:
    kind = args.get("kind")
    try:
        return RuleKind(kind)
    except ValueError:
        names = ", ".join(k.value for k in RuleKind)
        raise ValueError(f"unknown rule kind {kind!r}; use one of {names}") from None


def _typed(args: Mapping[str, object], key: str, kind: type[_T], default: _T) -> _T:
    value = args.get(key, default)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise ValueError(f"{key} must be of type {kind.__name__}")
    return value


def control_handlers(rules: DebugRules, status: Callable[[], dict[str, object]]
                     ) -> dict[str, Handler]:
    """The control socket commands (spec 8.11): ``debug.on``, ``debug.off``, ``debug.list``
    and ``status``. They need neither Redis nor the database."""

    async def debug_on(args: dict[str, object]) -> object:
        kind = _kind(args)
        value = _typed(args, "value", str, "")
        duration = args.get("duration_s")
        if duration is not None:
            duration = _typed(args, "duration_s", int, 0)
        rule = rules.add(kind, value, duration, _typed(args, "headers", bool, False))
        _log.info("debug rule %s switched on (%s) until %.0f", rule.id, kind.value,
                  rule.expires_at)
        return _rule_view(rule)

    async def debug_off(args: dict[str, object]) -> object:
        if _typed(args, "all", bool, False):
            removed = rules.clear()
        elif "id" in args:
            removed = int(rules.remove(_typed(args, "id", str, "")))
        else:
            raise ValueError("give the rule id or all")
        _log.info("%d debug rules switched off", removed)
        return {"removed": removed}

    async def debug_list(args: dict[str, object]) -> object:
        return [_rule_view(rule) for rule in rules.active()]

    async def status_command(args: dict[str, object]) -> object:
        return status()

    return {"debug.on": debug_on, "debug.off": debug_off, "debug.list": debug_list,
            "status": status_command}


# --- reload ------------------------------------------------------------------------------------


def _layer_changes(old: Mapping[str, object], new: Mapping[str, object], path: Path
                   ) -> list[tuple[str, str]]:
    changed = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
    return [(f"{key} changed in {path} ({REGISTRY.get(key).level.value})",
             "restart required" if key in RESTART_KEYS else "") for key in changed]


def _layers(old: Mapping[str, Mapping[str, object]], new: Mapping[str, Mapping[str, object]],
            directory: Path) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for name in sorted(set(old) | set(new)):
        result += _layer_changes(old.get(name, {}), new.get(name, {}),
                                 directory / f"{name}.toml")
    return result


def pin_restart_keys(running: ConfigSnapshot, loaded: ConfigSnapshot) -> ConfigSnapshot:
    """``loaded`` with the running value of every ``RESTART_KEYS`` setting.

    The service applied them at start only, so new sessions must keep seeing those values
    until a restart: a changed ``paths.spool`` would otherwise make them spool into a
    directory the start never created (ruling C8).
    """
    system = {**loaded.system, **{key: running.system[key] for key in RESTART_KEYS}}
    return dataclasses.replace(loaded, system=MappingProxyType(system))


def config_changes(old: ConfigSnapshot, new: ConfigSnapshot) -> list[tuple[str, str]]:
    """What a reload changed: ``(description, note)`` per setting, with its file and level;
    the note is "restart required" for what only a restart applies. Values are not shown:
    some carry credentials."""
    etc = new.etc_dir
    system = etc / "assp-ng.toml"
    changes = _layer_changes(old.system, new.system, system)
    if old.listeners != new.listeners:
        changes.append((f"[[listener]] changed in {system} (system)", "restart required"))
    if old.certificates != new.certificates:
        changes.append((f"[[tls.certificate]] changed in {system} (system)", ""))
    changes += _layer_changes(old.default_layer, new.default_layer, etc / "default.toml")
    changes += _layers(old.domain_layers, new.domain_layers, etc / "domain.d")
    changes += _layers(old.user_layers, new.user_layers, etc / "user.d")
    return changes
