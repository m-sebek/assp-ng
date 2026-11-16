# SPDX-License-Identifier: GPL-3.0-or-later
"""The proxy service: wiring, lifecycle and the ``python3 -m asspng.proxy`` entry point.

``Application.start()`` validates the configuration, builds every component in a fixed order
and then reports READY to systemd (spec 8.2-8.4). Each accepted connection gets ``SessionDeps``
built from the configuration current at that moment: a reload (SIGHUP, spec 7.5) changes new
sessions only, and a session keeps the settings it started with. SIGTERM and SIGINT stop the
service gracefully (spec 8.3): listeners first, then the sessions get ``timeouts.shutdown`` to
finish, then the rest are stopped (an idle client hears 421) and the stores are closed.

No background loop dies on an exception: it is logged by its type and the loop goes on.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Coroutine
from functools import partial
from pathlib import Path
from typing import Any

from asspng.checks.limits import AuthLimitsCheck
from asspng.config.errors import ConfigError
from asspng.config.loader import load_config
from asspng.config.model import ConfigSnapshot, ListenerConfig
from asspng.log.debug import DebugLog, DebugRules
from asspng.log.maillog import log_maillog
from asspng.log.setup import configure_logging, shutdown_logging
from asspng.net.dns import DnsPtrResolver, PtrResolver
from asspng.proxy.backend import Backend
from asspng.proxy.buffer import BufferBudget
from asspng.proxy.connections import ConnectionTracker
from asspng.proxy.listener import ListenerManager
from asspng.proxy.session import Session, SessionDeps
from asspng.proxy.session_util import config_int, config_seconds, config_text
from asspng.service.app_build import (
    LocalDomains,
    Runtime,
    build_alerter,
    build_debug,
    build_runtime,
    build_state,
    host_port,
    journal_wanted,
    prepare_directories,
    smtp_backend,
)
from asspng.service.app_tasks import (
    AlertingHealth,
    Alerts,
    MemoryWatch,
    cancel_all,
    close_writer,
    config_changes,
    control_handlers,
    pin_restart_keys,
    run_every,
    supervise,
)
from asspng.service.control import ControlServer
from asspng.service.health import HealthServer, HealthState
from asspng.service.memory import Housekeeper, MemoryGuard, rss_mb
from asspng.service.systemd import notify
from asspng.state.controller import StateController
from asspng.state.redis_store import EventBus
from asspng.tls.store import CertificateStore

_log = logging.getLogger("asspng.service")

DEFAULT_CONFIG = Path("/etc/assp-ng/assp-ng.toml")
_WATCHDOG_S = 10.0
_HOUSEKEEPING_S = 10.0
_CERT_CHECK_S = 86400.0
_CLOSE_TIMEOUT_S = 1.0
_CANCEL_WAIT_S = 10.0  # for cancelled sessions to close their connections
_STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)


def _rss() -> float:
    try:
        return round(rss_mb(), 1)
    except (OSError, ValueError, IndexError):
        return -1.0


class Application:
    """The proxy service: ``start()``, serve until ``shutdown()`` (or SIGTERM / SIGINT);
    ``wait_closed()`` returns once it has stopped.

    ``backend_factory`` and ``resolver`` replace the SMTP backend and the PTR resolver (tests).
    ``clock`` returns wall-clock seconds.
    """

    # Set by start(); every method using them runs only once start() got that far.
    _alerts: Alerts
    _state: StateController
    _health: HealthState
    _health_counters: AlertingHealth
    _connections: ConnectionTracker
    _budget: BufferBudget
    _auth_limits: AuthLimitsCheck
    _memory: MemoryGuard
    _memory_watch: MemoryWatch
    _housekeeper: Housekeeper
    _resolver: PtrResolver
    _domains: LocalDomains
    _tls: CertificateStore
    _debug_rules: DebugRules
    _debug_log: DebugLog
    _listeners: ListenerManager
    _health_server: HealthServer

    def __init__(
        self,
        config_path: Path,
        *,
        backend_factory: Callable[[ListenerConfig], Backend] | None = None,
        resolver: PtrResolver | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config_path = config_path
        self._backend_factory = backend_factory
        self._resolver_override = resolver
        self._clock = clock
        self._runtime: Runtime | None = None
        self._stack = contextlib.AsyncExitStack()  # closes what start() opened, in reverse
        self._sessions: dict[asyncio.Task[None], Session | None] = {}  # strong references
        self._loops: set[asyncio.Task[None]] = set()
        self._jobs: set[asyncio.Task[Any]] = set()  # fire-and-forget (alerts, reloads)
        self._jobs_closed = False
        self._reload_lock = asyncio.Lock()
        self._shutdown_task: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()
        self._serving = False
        self._stopping = False
        self._start_task: asyncio.Task[Any] | None = None  # set while start() runs
        self._stop_requested = False  # a stop signal arrived during start()
        self._reload_pending = False  # a SIGHUP arrived during start()
        self._started_at = time.monotonic()

    # --- public interface -------------------------------------------------------------------

    @property
    def config(self) -> ConfigSnapshot:
        """The configuration new sessions get."""
        if self._runtime is None:
            raise RuntimeError("the application has not been started")
        return self._runtime.config

    def addresses(self) -> list[tuple[str, str, int]]:
        """``(listener, host, port)`` of every listening socket."""
        return self._listeners.addresses()

    @property
    def health_address(self) -> tuple[str, int]:
        return self._health_server.address

    async def start(self) -> None:
        """Start the service. An invalid configuration raises ``ConfigError`` with every error
        found. On any failure whatever was already started is stopped again.

        SIGTERM or SIGINT during the start cancels it: whatever was started is stopped and
        ``start()`` returns normally with the service closed. A SIGHUP during the start is
        applied (a reload) once the service serves.
        """
        if self._runtime is not None or self._stopping:
            raise RuntimeError("an application starts only once")
        task = asyncio.current_task()
        self._start_task = task
        try:
            await self._start()
        except BaseException as exc:
            stopped = (isinstance(exc, asyncio.CancelledError) and self._stop_requested
                       and task is not None and task.uncancel() == 0)
            if isinstance(exc, Exception) and not isinstance(exc, ConfigError):
                # The type only: a message may quote a URL with its password.
                _log.error("start failed: %s", type(exc).__name__)
            self._stopping = True
            try:
                await self._close()
            except Exception as close_exc:
                _log.error("stopping after the failed start failed: %s",
                           type(close_exc).__name__)
            if not stopped:
                raise
        finally:
            self._start_task = None

    async def reload(self) -> bool:
        """Reload the configuration (spec 7.5); never raises.

        Everything is loaded and validated first. On any error the running configuration
        stays, the errors are logged and alerted, and the result is False. Otherwise new
        sessions get the new configuration, certificates are re-read and the changed settings
        are logged with their file and level. Settings only a restart applies
        (``RESTART_KEYS``) keep their running values; their change is logged as "restart
        required".
        """
        if not self._serving or self._stopping:
            _log.warning("reload ignored: the service is not running")
            return False
        async with self._reload_lock:
            old = self.config
            try:
                loaded = await asyncio.to_thread(self._load)
                new = pin_restart_keys(old, loaded)
                if not new.certificates and self._tls.front_context() is not None:
                    raise ConfigError(f"{new.etc_dir / 'assp-ng.toml'}: removing every "
                                      "[[tls.certificate]] needs a restart")
                runtime = build_runtime(new, self._state, self._clock, self._on_check_error)
                self._tls.reload(new.certificates)
            except ConfigError as exc:
                self._reload_failed(exc.errors)
                return False
            except Exception as exc:
                self._reload_failed([f"unexpected {type(exc).__name__}"])
                return False
            self._runtime = runtime
        for change, note in config_changes(old, loaded):
            if note:
                _log.warning("%s: %s", change, note)
            else:
                _log.info("%s", change)
        _log.info("configuration reloaded (%d trusted and %d exempt networks)",
                  len(new.trusted), len(new.exempt))
        return True

    async def shutdown(self) -> None:
        """Stop gracefully (spec 8.3). Safe to call more than once, and after a failed start."""
        await asyncio.shield(self._begin_shutdown())

    async def wait_closed(self) -> None:
        await self._closed.wait()

    async def handle_connection(self, listener: ListenerConfig, reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter) -> None:
        """Serve one accepted connection (the listeners' handler). Never raises, except
        ``CancelledError``; a failure ends this connection only."""
        task = asyncio.current_task()
        if task is None or self._stopping:
            await close_writer(writer, _CLOSE_TIMEOUT_S)
            return
        self._sessions[task] = None
        try:
            try:
                peer = writer.get_extra_info("peername")
                session = Session(self._session_deps(listener), reader, writer,
                                  (str(peer[0]), int(peer[1])))
            except Exception as exc:
                self._session_failed(listener, "cannot set up a session", exc)
                await close_writer(writer, _CLOSE_TIMEOUT_S)
                return
            self._sessions[task] = session
            try:
                await session.run()
            except Exception as exc:  # run() handles its errors itself; a last guard
                self._session_failed(listener, "session failed", exc)
                await close_writer(writer, _CLOSE_TIMEOUT_S)
        finally:
            self._sessions.pop(task, None)

    # --- start-up ---------------------------------------------------------------------------

    async def _start(self) -> None:
        # First: a signal during the start must not kill the process half-started (C3).
        self._install_signal_handlers()
        config = self._load()
        self._start_logging(config)
        prepare_directories(config)
        self._build_state(config)
        self._runtime = build_runtime(config, self._state, self._clock, self._on_check_error)
        await self._start_domains(config)
        await self._start_serving(config)
        self._start_loops(config)
        self._serving = True
        notify("READY=1")
        self._loop("watchdog", _WATCHDOG_S, self._watchdog, immediately=True)
        _log.info("ASSP-NG %s started", config_text(config, "instance"))
        if self._reload_pending:
            self._reload_pending = False
            self._spawn(self.reload())

    def _load(self) -> ConfigSnapshot:
        if self._config_path.name != "assp-ng.toml":
            raise ConfigError(f"{self._config_path}: the system configuration file must be "
                              "named assp-ng.toml")
        return load_config(self._config_path.parent)

    def _start_logging(self, config: ConfigSnapshot) -> None:
        listener = configure_logging(config_text(config, "log.level"),
                                     Path(config_text(config, "paths.log_dir")),
                                     journal=journal_wanted())
        self._stack.callback(shutdown_logging, listener)
        self._stack.push_async_callback(self._cancel_jobs)

    def _build_state(self, config: ConfigSnapshot) -> None:
        number = partial(config_int, config)
        self._alerts = Alerts(build_alerter(config), self._spawn)
        redis, self._state = build_state(config, self._clock, self._alerts.state_changed)
        self._stack.push_async_callback(redis.close)
        self._health = HealthState()
        self._health_counters = AlertingHealth(self._health, self._alerts.backend_down)
        self._connections = ConnectionTracker()
        self._budget = BufferBudget(number("buffer.memory_total"))
        self._auth_limits = AuthLimitsCheck()
        self._memory = MemoryGuard(number("memory.soft_limit_mb"))
        self._memory_watch = MemoryWatch(self._memory, number("memory.soft_limit_mb"),
                                         self._state, self._alerts)
        self._resolver = self._resolver_override or DnsPtrResolver(
            config_seconds(config, "timeouts.ptr"))

    async def _start_domains(self, config: ConfigSnapshot) -> None:
        self._domains = LocalDomains(config, self._alerts)
        self._stack.callback(self._domains.close)
        await self._domains.start()
        refresher = self._domains.refresher
        if refresher is None:
            return
        self._loop("domain refresh", config_seconds(config, "domains.refresh_interval_s"),
                   refresher.refresh)
        bus = EventBus(config_text(config, "redis.url"), config_text(config, "redis.key_prefix"))
        self._spawn_loop(supervise(
            "event bus", partial(bus.run, refresher.on_event, on_subscribed=refresher.refresh)))

    async def _start_serving(self, config: ConfigSnapshot) -> None:
        health_host, health_port = host_port(config, "health.listen")
        self._tls = CertificateStore(config.certificates)
        loop = asyncio.get_running_loop()

        def debug_log_full() -> None:  # called on the debug log's writer thread
            loop.call_soon_threadsafe(self._debug_log_full)

        self._debug_rules, self._debug_log = build_debug(config, self._clock, debug_log_full)
        self._stack.callback(self._debug_log.close)
        self._listeners = ListenerManager(config.listeners, self.handle_connection, self._tls)
        self._stack.push_async_callback(self._listeners.close)
        await self._listeners.start()
        self._health_server = HealthServer(health_host, health_port, self._health_snapshot,
                                           status_code=self._health.status_code)
        await self._health_server.start()
        self._stack.push_async_callback(self._health_server.close)
        control = ControlServer(Path(config_text(config, "paths.run")) / "control.sock",
                                control_handlers(self._debug_rules, self._health_snapshot))
        await control.start()
        self._stack.push_async_callback(control.close)

    def _start_loops(self, config: ConfigSnapshot) -> None:
        self._housekeeper = Housekeeper(
            lambda: len(self._sessions), [], time.monotonic,
            config_int(config, "memory.idle_trim_after_s"),
            config_int(config, "memory.trim_interval_s"))
        self._loop("housekeeping", _HOUSEKEEPING_S, self._housekeeping, immediately=True)
        self._loop("state probe", config_seconds(config, "state.probe_interval_s"),
                   self._state.probe)
        self._loop("certificate check", _CERT_CHECK_S, self._check_certificates,
                   immediately=True)

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, self._on_reload_signal)
        for sig in _STOP_SIGNALS:
            loop.add_signal_handler(sig, self._on_stop_signal, sig)
        self._stack.callback(self._remove_signal_handlers, loop)

    @staticmethod
    def _remove_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
        for sig in (signal.SIGHUP, *_STOP_SIGNALS):
            loop.remove_signal_handler(sig)

    # --- sessions ---------------------------------------------------------------------------

    def _session_deps(self, listener: ListenerConfig) -> SessionDeps:
        """Built per connection from the current configuration; the session keeps it."""
        runtime = self._runtime
        assert runtime is not None
        return SessionDeps(
            config=runtime.config, policies=runtime.policies, listener=listener,
            backend_factory=self._backend_factory or partial(smtp_backend, runtime.config),
            engine=runtime.engine, state=self._state, penalty_box=runtime.penalty_box,
            auth_limits=self._auth_limits, domains=self._domains.holder, tls=self._tls,
            resolver=self._resolver, connections=self._connections, budget=self._budget,
            maillog=log_maillog, debug_rules=self._debug_rules, debug_log=self._debug_log,
            health=self._health_counters, memory_over_limit=self._memory.over_limit,
            clock=self._clock)

    def _session_failed(self, listener: ListenerConfig, what: str, exc: Exception) -> None:
        _log.error("%s on listener %s: %s", what, listener.name, type(exc).__name__)
        self._health.record("session_error")

    # --- events and periodic jobs -----------------------------------------------------------

    def _on_check_error(self, name: str, exc: BaseException) -> None:
        _log.warning("check %s failed: %s", name, type(exc).__name__)
        self._health.record("check_error")

    def _debug_log_full(self) -> None:
        removed = self._debug_rules.clear()
        _log.warning("debug.log reached debug.max_size_mb: %d debug rules switched off", removed)

    def _reload_failed(self, errors: list[str]) -> None:
        for error in errors:
            _log.error("configuration reload failed: %s", error)
        self._alerts.send("reload-failed", "The configuration reload failed; the running "
                          "configuration is kept.\n" + "\n".join(errors))

    async def _housekeeping(self) -> None:
        self._housekeeper.tick()
        self._memory_watch.check()

    async def _check_certificates(self) -> None:
        self._alerts.certificates(self._tls.days_left())

    async def _watchdog(self) -> None:
        notify("WATCHDOG=1")
        notify(f"STATUS=mode={self._state.mode.name} sessions={len(self._sessions)} "
               f"domains={self._domains.holder.origin}")

    def _health_snapshot(self) -> dict[str, object]:
        return self._health.snapshot(
            instance=config_text(self.config, "instance"), mode=self._state.mode,
            db_ok=self._domains.db_ok, domains_origin=self._domains.holder.origin,
            domains_count=len(self._domains.holder.index), sessions=len(self._sessions),
            rss_mb=_rss(), uptime_s=int(time.monotonic() - self._started_at),
            debug_rules=len(self._debug_rules.active()), cert_days=self._tls.days_left())

    def _on_reload_signal(self) -> None:
        if self._start_task is not None and not self._serving:
            _log.info("SIGHUP received during the start: reloading once started")
            self._reload_pending = True
            return
        _log.info("SIGHUP received: reloading the configuration")
        self._spawn(self.reload())

    def _on_stop_signal(self, sig: signal.Signals) -> None:
        _log.info("%s received", sig.name)
        if self._stopping:  # already stopping (or a failed start is cleaning up)
            return
        if self._start_task is not None and not self._serving:
            self._stop_requested = True  # start() stops what it started and returns
            self._start_task.cancel()
            return
        self._begin_shutdown()

    # --- tasks ------------------------------------------------------------------------------

    def _loop(self, name: str, interval_s: float, job: Callable[[], Awaitable[None]], *,
              immediately: bool = False) -> None:
        self._spawn_loop(run_every(name, interval_s, job, immediately=immediately))

    def _spawn_loop(self, coro: Coroutine[Any, Any, None]) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._loops.add(task)
        task.add_done_callback(self._loops.discard)

    def _spawn(self, coro: Coroutine[Any, Any, object]) -> None:
        """Fire and forget; the task is referenced until it is done."""
        if self._jobs_closed:
            coro.close()
            return
        task = asyncio.get_running_loop().create_task(coro)
        self._jobs.add(task)
        task.add_done_callback(self._jobs.discard)

    async def _cancel_jobs(self) -> None:
        self._jobs_closed = True
        await cancel_all(self._jobs)

    # --- shutdown ---------------------------------------------------------------------------

    def _begin_shutdown(self) -> asyncio.Task[None]:
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.get_running_loop().create_task(self._shutdown())
        return self._shutdown_task

    async def _shutdown(self) -> None:
        """Never raises: a failing step is logged and the remaining ones still run, so
        ``wait_closed()`` (and ``main()``) always return."""
        self._stopping = True
        try:
            if self._serving:
                notify("STOPPING=1")
                _log.info("shutting down")
                try:
                    await self._listeners.close()
                finally:
                    await self._drain_sessions()
        except Exception as exc:
            _log.error("stopping the listeners or sessions failed: %s", type(exc).__name__)
        try:
            await self._close()
        except Exception as exc:  # logging may be closed already: the last resort reports it
            _log.error("closing failed: %s", type(exc).__name__)

    async def _drain_sessions(self) -> None:
        """Give the sessions ``timeouts.shutdown`` to finish; then stop the rest (an idle
        client hears 421, see ``Session.notify_shutdown``)."""
        if self._sessions:
            grace = config_seconds(self.config, "timeouts.shutdown")
            _log.info("waiting up to %.0f s for %d sessions", grace, len(self._sessions))
            await asyncio.wait(set(self._sessions), timeout=grace)
        remaining = list(self._sessions.items())
        for task, session in remaining:
            if session is not None:
                session.notify_shutdown()
            task.cancel()
        if remaining:
            _log.info("stopping %d sessions", len(remaining))
            _, pending = await asyncio.wait([task for task, _ in remaining],
                                            timeout=_CANCEL_WAIT_S)
            if pending:
                _log.warning("%d sessions did not stop in time", len(pending))

    async def _close(self) -> None:
        """Stop the background loops, then close what start() opened (logging last). A
        raising closer does not stop the others, and the service counts as closed."""
        try:
            await cancel_all(self._loops)
            await self._stack.aclose()
        finally:
            self._closed.set()


# --- entry point -------------------------------------------------------------------------------


def _start_error(exc: Exception) -> str:
    """The type, and for an OSError its errno and strerror (they hold no secrets). Never the
    text of other exceptions: it may quote a URL with its password."""
    name = type(exc).__name__
    if isinstance(exc, OSError) and exc.errno is not None and exc.strerror:
        return f"{name}: [Errno {exc.errno}] {exc.strerror}"
    return name


async def _serve(config_path: Path) -> int:
    app = Application(config_path)
    try:
        await app.start()
    except ConfigError as exc:
        for error in exc.errors:
            print(f"assp-ng: {error}", file=sys.stderr)
        return 2
    except Exception as exc:  # e.g. a port in use; the type only, as in the log
        print(f"assp-ng: cannot start: {_start_error(exc)}", file=sys.stderr)
        return 1
    await app.wait_closed()
    return 0


def main(argv: list[str] | None = None) -> int:
    """``python3 -m asspng.proxy --config /etc/assp-ng/assp-ng.toml``. Returns 0 after a
    graceful stop, 2 when the configuration is invalid and 1 when the service cannot start
    for another reason."""
    parser = argparse.ArgumentParser(prog="python3 -m asspng.proxy",
                                     description="ASSP-NG SMTP proxy service")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, metavar="PATH",
                        help="system configuration file (default: %(default)s)")
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_serve(args.config))
    except KeyboardInterrupt:  # SIGINT before the signal handlers were installed
        return 130
