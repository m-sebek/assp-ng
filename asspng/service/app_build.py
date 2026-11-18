# SPDX-License-Identifier: GPL-3.0-or-later
"""Builders of the application's components from a configuration snapshot."""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from asspng.checks.base import CheckContext
from asspng.checks.engine import CheckEngine
from asspng.checks.penalty_box import PenaltyBox
from asspng.checks.registry import default_checks
from asspng.config.errors import ConfigError
from asspng.config.model import ConfigSnapshot, ListenerConfig
from asspng.config.policy import PolicyResolver
from asspng.db.migrate import HEAD_REVISION, current_revision
from asspng.db.repository import DatabaseDomainSource
from asspng.domains.index import DomainEntry, DomainIndex, load_snapshot
from asspng.domains.refresher import DomainHolder, DomainRefresher
from asspng.log.debug import DebugLog, DebugRules
from asspng.proxy.backend import Backend, SmtpBackend
from asspng.proxy.buffer import purge_spool
from asspng.proxy.session_util import config_int, config_seconds, config_text
from asspng.service.alerts import Alerter
from asspng.service.app_tasks import Alerts
from asspng.state.controller import StateController, StateMode
from asspng.state.memory_store import MemoryStore
from asspng.state.redis_store import RedisStore

_log = logging.getLogger("asspng.service")

SNAPSHOT_FILE = "local-domains.json"


@dataclass(frozen=True)
class Runtime:
    """What a reload replaces as a whole; each session keeps the one it started with."""

    config: ConfigSnapshot
    policies: PolicyResolver
    penalty_box: PenaltyBox
    engine: CheckEngine


def build_runtime(config: ConfigSnapshot, state: StateController, clock: Callable[[], float],
                  on_check_error: Callable[[str, BaseException], None]) -> Runtime:
    """Policies, penalty box and check engine of ``config``."""
    number = partial(config_int, config)
    box = PenaltyBox(
        state, threshold=number("penalty_box.threshold"),
        score_cap=number("penalty_box.score_cap"), score_ttl_s=number("penalty_box.score_ttl"),
        ladder_s=_durations(config, "penalty_box.ladder"),
        history_s=number("penalty_box.history"), clock=clock)

    async def add_ip_score(ctx: CheckContext, points: int, reason: str) -> None:
        await box.add_score(ctx.session.net_key, points, reason)

    return Runtime(config, PolicyResolver(config), box,
                   CheckEngine(default_checks(box), add_ip_score, on_check_error))


def build_state(config: ConfigSnapshot, clock: Callable[[], float],
                on_change: Callable[[StateMode, StateMode, str], None]
                ) -> tuple[RedisStore, StateController]:
    """The Redis store and the degraded-mode controller around it (spec 6)."""
    number = partial(config_int, config)
    redis = RedisStore(config_text(config, "redis.url"), config_text(config, "redis.key_prefix"),
                       number("redis.op_timeout_ms") / 1000)
    state = StateController(
        redis, MemoryStore(number("state.memory_max_entries"), clock),
        failures_to_degrade=number("state.failures_to_degrade"),
        unreachable_s=config_seconds(config, "state.unreachable_to_degrade_s"),
        strict=config_text(config, "state.on_redis_failure") == "tempfail",
        clock=clock, on_change=on_change)
    return redis, state


def build_alerter(config: ConfigSnapshot) -> Alerter:
    text = partial(config_text, config)
    return Alerter(email=text("alerts.email"), webhook=text("alerts.webhook"),
                   smtp_server=text("alerts.smtp_server"),
                   min_interval_s=config_int(config, "alerts.min_interval"), clock=time.time,
                   instance=text("instance"), sender=f"assp-ng@{text('hostname')}")


def build_debug(config: ConfigSnapshot, clock: Callable[[], float],
                on_full: Callable[[], None]) -> tuple[DebugRules, DebugLog]:
    """The debug rules (kept in ``paths.run``) and the debug log; ``on_full`` runs on the
    log's writer thread."""
    number = partial(config_int, config)
    rules = DebugRules(
        Path(config_text(config, "paths.run")) / "debug-rules.json", clock,
        default_s=number("debug.default_duration"), max_s=number("debug.max_duration"),
        max_all_s=number("debug.max_duration_all"))
    log = DebugLog(Path(config_text(config, "paths.log_dir")) / "debug.log",
                   number("debug.max_size_mb") * 1024 * 1024, on_full)
    return rules, log


def smtp_backend(config: ConfigSnapshot, listener: ListenerConfig) -> Backend:
    """The real backend connection to the listener's MTA."""
    return SmtpBackend(listener.backend_host, listener.backend_port,
                       connect_timeout_s=config_seconds(config, "timeouts.backend_connect"),
                       banner_timeout_s=config_seconds(config, "timeouts.backend_banner"))


def prepare_directories(config: ConfigSnapshot) -> None:
    """Create the spool (0700), cache and run directories; empty the spool (spec 9)."""
    spool = Path(config_text(config, "paths.spool"))
    spool.mkdir(mode=0o700, parents=True, exist_ok=True)
    for key in ("paths.cache", "paths.run"):
        Path(config_text(config, key)).mkdir(parents=True, exist_ok=True)
    purged = purge_spool(spool)
    if purged:
        _log.info("removed %d leftover spool files", purged)


def host_port(config: ConfigSnapshot, key: str) -> tuple[str, int]:
    """A ``host:port`` or ``[ipv6]:port`` setting; ``ConfigError`` when malformed."""
    text = config_text(config, key)
    host, sep, port = text.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not sep or not host or not port.isdigit() or int(port) > 65535:
        raise ConfigError(f"{key} {text!r} must look like host:port or [ipv6]:port")
    return host, int(port)


def journal_wanted() -> bool:
    """True when stderr is the journal stream systemd connected (``JOURNAL_STREAM``)."""
    try:
        st = os.fstat(sys.stderr.fileno())
        if os.environ.get("JOURNAL_STREAM") != f"{st.st_dev}:{st.st_ino}":
            return False
        return importlib.util.find_spec("systemd.journal") is not None
    except (OSError, ValueError, AttributeError, ImportError):
        return False


def _durations(config: ConfigSnapshot, key: str) -> tuple[int, ...]:
    value = config.get(key)
    if not isinstance(value, tuple) or not all(isinstance(v, int) for v in value):
        raise TypeError(f"setting {key} is not a list of durations")
    return value


class _SchemaMismatch(Exception):
    """The database has another schema revision; its domains are not used."""


class LocalDomains:
    """The local domains of the relay decision (spec 5.8): from the database, kept fresh by
    ``refresher``, or without a usable database from the snapshot; with neither they are
    unavailable. ``holder`` is what the sessions ask.

    The schema revision is checked at start. When the database is unreachable then, the check
    runs before the first load instead; a mismatch found there is handled as at start.
    """

    def __init__(self, config: ConfigSnapshot, alerts: Alerts) -> None:
        self.holder = DomainHolder()
        self.db_ok = True
        self.refresher: DomainRefresher | None = None
        self._config = config
        self._alerts = alerts
        self._source: DatabaseDomainSource | None = None
        self._url = ""
        self._schema_unchecked = False  # set by start, cleared by the loader thread
        self._mismatch: str | None = None  # the alert message, once a mismatch is found
        self._mismatch_alerted = False

    async def start(self) -> None:
        """Load the domains; ``refresher`` is set when the database is usable."""
        config = self._config
        snapshot = Path(config_text(config, "paths.cache")) / SNAPSHOT_FILE
        url = self._url = config_text(config, "database.url")
        if not url or not await self._schema_matches(url):
            self.db_ok = not url
            await self._load_snapshot(snapshot)
            return
        self._source = DatabaseDomainSource(url)
        self.refresher = DomainRefresher(
            partial(self._load, self._source), self.holder, snapshot,
            config_int(config, "domains.refresh_interval_s"), self._on_db_down)
        await self.refresher.refresh()

    def close(self) -> None:
        if self._source is not None:
            self._source.close()

    async def _schema_matches(self, url: str) -> bool:
        try:
            revision = await asyncio.to_thread(current_revision, url)
        except Exception as exc:  # unreachable: the refresher retries and uses the snapshot
            _log.warning("cannot read the database schema revision: %s; it is checked before "
                         "the first load", type(exc).__name__)
            self._schema_unchecked = True
            return True
        if revision == HEAD_REVISION:
            return True
        self._report_mismatch(_mismatch_message(revision))
        return False

    def _report_mismatch(self, message: str) -> None:
        _log.error("%s", message)
        self._alerts.send("schema-mismatch", message)

    async def _load_snapshot(self, path: Path) -> None:
        entries = await asyncio.to_thread(load_snapshot, path)
        if entries is None:
            _log.warning("no local domains (no database and no snapshot at %s): mail for "
                         "them is deferred", path)
            return
        self.holder.index = DomainIndex(entries)
        self.holder.origin = "snapshot"
        _log.info("local domains loaded from the snapshot (%d entries)", len(entries))

    def _load(self, source: DatabaseDomainSource) -> list[DomainEntry]:
        """The refresher's loader; runs in a worker thread. A schema mismatch fails every
        load, so the refresher keeps the snapshot, as when the mismatch is found at start."""
        if self._mismatch is not None:
            raise _SchemaMismatch
        if self._schema_unchecked:
            revision = current_revision(self._url)  # raises while still unreachable
            if revision != HEAD_REVISION:
                self._mismatch = _mismatch_message(revision)
                raise _SchemaMismatch
            self._schema_unchecked = False
        entries = source.load()
        self.db_ok = True
        return entries

    def _on_db_down(self, down_s: float) -> None:
        self.db_ok = False
        if self._mismatch is None:
            self._alerts.database_down(down_s)
        elif not self._mismatch_alerted:
            self._mismatch_alerted = True
            self._report_mismatch(self._mismatch)


def _mismatch_message(revision: str | None) -> str:
    return (f"database schema revision {revision or 'none'} does not match "
            f"{HEAD_REVISION}; local domains come from the snapshot until "
            "'assp-ng db upgrade' has run and the service is restarted")
