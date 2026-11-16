# SPDX-License-Identifier: GPL-3.0-or-later
"""Session test fixtures: an in-process proxy with a scripted backend and real collaborators."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from asspng.checks.base import Check, CheckContext
from asspng.checks.engine import CheckEngine
from asspng.checks.limits import AuthLimitsCheck
from asspng.checks.penalty_box import PenaltyBox
from asspng.checks.registry import default_checks
from asspng.config.loader import load_config
from asspng.config.model import CertificateConfig, ListenerConfig, ListenerKind
from asspng.config.policy import PolicyResolver
from asspng.domains.index import DomainIndex
from asspng.log.debug import DebugLog, DebugRules, RuleKind
from asspng.log.maillog import MaillogRecord
from asspng.net.dns import PtrResult
from asspng.net.ipnet import IPAddress
from asspng.proxy.backend import Backend
from asspng.proxy.buffer import BufferBudget
from asspng.proxy.connections import ConnectionTracker
from asspng.proxy.listener import start_server
from asspng.proxy.session import Session, SessionDeps
from asspng.smtp.datacodec import Stuffer
from asspng.smtp.replies import Reply
from asspng.state.controller import StateController
from asspng.state.memory_store import MemoryStore
from asspng.tls.store import CertificateStore
from tests.support.certs import make_cert
from tests.support.smtp_client import SmtpDialog, client_tls_context, smtp_dialog

HOSTNAME = "proxy.test"
PUBLIC_PEER = ("1.2.3.4", 40000)
PUBLIC_NET = "1.2.3.4/32"

EHLO_LINES = (
    "fake.mta",
    "PIPELINING",
    "SIZE 10240000",
    "VRFY",
    "ETRN",
    "STARTTLS",
    "AUTH PLAIN LOGIN",
    "ENHANCEDSTATUSCODES",
    "8BITMIME",
    "DSN",
    "SMTPUTF8",
    "XCLIENT NAME ADDR PORT",
    "CHUNKING",
)

BASE_CONFIG: dict[str, object] = {
    "hostname": HOSTNAME,
    "instance": "test",
    "banner.text": "",
    "timeouts.command": 5,
    "timeouts.backend_command": 2,
    "timeouts.ptr": 1,
}


class FakeBackend(Backend):
    """Scripted ``Backend``: canned replies, injected failures, recorded traffic.

    One instance serves every session of a proxy. ``received`` holds the command lines
    sent with ``command()`` (and ``DATA``); the proxy's own XCLIENT goes to ``xclient_calls``.
    ``data()`` answers ``replies["DATA"]`` instead of 354 when it is set; otherwise it encodes
    the chunks like ``SmtpBackend`` (``Stuffer``), appends them to ``messages``, raises
    ``errors[b"DATA"]`` if set (the final reply is lost) and returns ``final_reply``.
    """

    def __init__(
        self,
        *,
        banner: Reply = Reply.of(220, "fake.mta ESMTP"),
        replies: dict[str, Reply] | None = None,
        connect_error: BaseException | None = None,
        xclient_error: BaseException | None = None,
        errors: dict[bytes, BaseException] | None = None,
        connect_gate: asyncio.Event | None = None,
        xclient_gate: asyncio.Event | None = None,
        close_error: BaseException | None = None,
        final_reply: Reply = Reply.of(250, "2.0.0 Ok: queued as FAKE1"),
    ) -> None:
        self.banner = banner
        self.replies = {k.upper(): v for k, v in (replies or {}).items()}
        self.connect_error = connect_error
        self.xclient_error = xclient_error
        self.errors = dict(errors or {})
        self.connect_gate = connect_gate
        self.xclient_gate = xclient_gate
        self.close_error = close_error
        self.final_reply = final_reply
        self.received: list[bytes] = []
        self.messages: list[bytes] = []  # each message as sent on the wire (stuffed)
        self.events: list[str] = []
        self.xclient_calls: list[tuple[IPAddress, int, str, str]] = []
        self.connected = asyncio.Event()
        self.closes = 0

    @property
    def received_text(self) -> str:
        return "\n".join(line.decode("utf-8", "replace") for line in self.received)

    async def connect(self) -> Reply:
        self.events.append("connect")
        self.connected.set()
        if self.connect_gate is not None:
            await self.connect_gate.wait()
        if self.connect_error is not None:
            raise self.connect_error
        return self.banner

    async def xclient(self, addr: IPAddress, port: int, name: str, helo_name: str) -> Reply:
        self.events.append("xclient")
        if self.xclient_gate is not None:
            await self.xclient_gate.wait()
        if self.xclient_error is not None:
            raise self.xclient_error
        self.xclient_calls.append((addr, port, name, helo_name))
        return Reply.of(220, "fake.mta ESMTP")

    async def command(self, line: bytes, timeout_s: float) -> Reply:
        self.received.append(line)
        self.events.append("command")
        if line in self.errors:
            raise self.errors[line]
        verb = line.split(b" ", 1)[0].decode("ascii", "replace").upper()
        if verb in self.replies:
            return self.replies[verb]
        if verb == "EHLO":
            return Reply(250, EHLO_LINES)
        if verb == "HELO":
            return Reply.of(250, "fake.mta")
        if verb == "QUIT":
            return Reply.of(221, "2.0.0 Bye")
        return Reply.of(250, "2.0.0 Ok")

    async def data(
        self, chunks: Iterable[bytes], timeout_354_s: float, timeout_final_s: float
    ) -> Reply:
        self.received.append(b"DATA")
        self.events.append("data")
        if "DATA" in self.replies:
            return self.replies["DATA"]
        stuffer = Stuffer()
        wire = b"".join(stuffer.feed(chunk) for chunk in chunks)
        self.messages.append(wire + stuffer.finish())
        if b"DATA" in self.errors:
            raise self.errors[b"DATA"]
        return self.final_reply

    async def close(self) -> None:
        self.events.append("close")
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


class FakeResolver:
    """``PtrResolver`` returning ``name``; optionally waits for ``gate`` or raises."""

    def __init__(
        self,
        name: str | None = "client.example",
        *,
        error: BaseException | None = None,
        gate: asyncio.Event | None = None,
    ) -> None:
        self.name = name
        self.error = error
        self.gate = gate
        self.started = asyncio.Event()
        self.lookups: list[IPAddress] = []

    async def lookup(self, addr: IPAddress) -> PtrResult:
        self.lookups.append(addr)
        self.started.set()
        if self.gate is not None:
            await self.gate.wait()
        if self.error is not None:
            raise self.error
        return PtrResult(self.name, False)


class FakeHealth:
    """``HealthCounters`` that records events and counts consecutive backend failures."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.backend_results: list[tuple[str, bool]] = []
        self._failures: dict[str, int] = {}

    def record(self, event: str) -> None:
        self.events.append(event)

    def backend_result(self, listener: str, ok: bool) -> int:
        self.backend_results.append((listener, ok))
        self._failures[listener] = 0 if ok else self._failures.get(listener, 0) + 1
        return self._failures[listener]


@dataclass
class Proxy:
    host: str
    port: int
    deps: SessionDeps
    fake: Backend
    health: FakeHealth
    resolver: Any
    box: PenaltyBox
    maillog: list[MaillogRecord]
    check_errors: list[tuple[str, BaseException]]
    tasks: list[asyncio.Task[None]] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)
    client_ssl: ssl.SSLContext | None = None  # set for an implicit-TLS listener

    def dialog(self) -> contextlib.AbstractAsyncContextManager[SmtpDialog]:
        return smtp_dialog(self.host, self.port, self.client_ssl)

    async def wait_sessions(self, timeout: float = 2.0) -> None:
        """Wait until every session started so far has finished (cancelled ones included)."""
        async with asyncio.timeout(timeout):
            await asyncio.gather(*self.tasks, return_exceptions=True)


StartProxy = Callable[..., Awaitable[Proxy]]


@pytest.fixture
async def proxy_with(etc_dir: Path, tmp_path: Path) -> AsyncIterator[StartProxy]:
    """``await proxy_with(fake_backend, **overrides)`` starts a proxy on 127.0.0.1:0.

    ``paths.spool`` is the empty directory ``tmp_path / "spool"``.

    Keyword arguments: ``config`` (SYSTEM values over ``BASE_CONFIG``), ``peer`` (the
    client address the session sees instead of 127.0.0.1), ``listener`` (field overrides
    for the listener), ``checks`` (extra checks after the production list of
    ``default_checks``), ``implicit_tls`` (a ``submissions`` listener, whatever ``listener``
    says: the session starts TLS with the ``tls`` store's context) and
    any ``SessionDeps`` field (``resolver``, ``tls``, ``domains``, ``backend_factory``...).
    """
    servers: list[asyncio.Server] = []
    proxies: list[Proxy] = []
    logs: list[DebugLog] = []

    async def start(
        fake_backend: Backend,
        *,
        config: dict[str, object] | None = None,
        peer: tuple[str, int] | None = None,
        listener: dict[str, object] | None = None,
        checks: Sequence[Check] = (),
        implicit_tls: bool = False,
        **overrides: Any,
    ) -> Proxy:
        snap = load_config(etc_dir)
        spool = tmp_path / "spool"
        spool.mkdir(exist_ok=True)
        snap = dataclasses.replace(snap, system={
            **snap.system, **BASE_CONFIG, "paths.spool": str(spool), **(config or {})})
        if implicit_tls:  # production: implicit TLS is the submissions listener's
            listener = {**(listener or {}), "kind": ListenerKind.SUBMISSIONS}
        listener_cfg: ListenerConfig = dataclasses.replace(
            snap.listeners[0], **(listener or {}))
        store = StateController(
            MemoryStore(10000, time.time), MemoryStore(10000, time.time),
            clock=time.time, on_change=lambda old, new, reason: None)
        box = PenaltyBox(
            store, threshold=50, score_cap=100, score_ttl_s=86400,
            ladder_s=[86400, 604800], history_s=7776000, clock=time.time)
        check_errors: list[tuple[str, BaseException]] = []

        async def ip_score_sink(ctx: CheckContext, score: int, reason: str) -> None:
            await box.add_score(ctx.session.net_key, score, reason)

        engine = CheckEngine(
            [*default_checks(box), *checks],  # the production list and order (R63)
            ip_score_sink, lambda name, exc: check_errors.append((name, exc)))
        debug_dir = tmp_path / f"debug{len(logs)}"
        debug_dir.mkdir()
        debug_log = DebugLog(debug_dir / "debug.log", 10_000_000, lambda: None)
        logs.append(debug_log)
        records: list[MaillogRecord] = []
        health = FakeHealth()
        resolver = overrides.pop("resolver", None) or FakeResolver()
        values: dict[str, Any] = {
            "config": snap,
            "policies": PolicyResolver(snap),
            "listener": listener_cfg,
            "backend_factory": lambda _listener: fake_backend,
            "engine": engine,
            "state": store,
            "penalty_box": box,
            "auth_limits": AuthLimitsCheck(),
            "domains": lambda: DomainIndex([]),
            "tls": CertificateStore([]),
            "resolver": resolver,
            "connections": ConnectionTracker(),
            "budget": BufferBudget(10_000_000),
            "maillog": records.append,
            "debug_rules": DebugRules(
                debug_dir / "rules.json", time.time,
                default_s=1800, max_s=86400, max_all_s=3600),
            "debug_log": debug_log,
            "health": health,
            "memory_over_limit": lambda: False,
            "clock": time.time,
        }
        values.update(overrides)
        deps = SessionDeps(**values)
        proxy: Proxy

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            assert task is not None
            proxy.tasks.append(task)
            real_peer = writer.get_extra_info("peername")
            session = Session(deps, reader, writer, peer or (real_peer[0], real_peer[1]))
            proxy.sessions.append(session)
            await session.run()

        assert not implicit_tls or deps.tls.front_context(), "implicit TLS needs a certificate"
        # The production server: on an implicit-TLS listener the session starts TLS (R59).
        server = await start_server(handle, implicit_tls=implicit_tls, host="127.0.0.1", port=0)
        servers.append(server)
        host, port = server.sockets[0].getsockname()[:2]
        proxy = Proxy(host, port, deps, fake_backend, health, resolver, box, records,
                      check_errors, client_ssl=client_tls_context() if implicit_tls else None)
        proxies.append(proxy)
        return proxy

    try:
        yield start
    finally:
        for server in servers:
            server.close()
        for proxy in proxies:
            for task in proxy.tasks:
                task.cancel()
            with contextlib.suppress(TimeoutError):
                await proxy.wait_sessions()
        for server in servers:
            await server.wait_closed()
        for debug_log in logs:
            debug_log.close()


@pytest.fixture
def cert_store(tmp_path: Path) -> CertificateStore:
    """A certificate store with one self-signed certificate for ``HOSTNAME``."""
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    cert, key = make_cert(cert_dir, HOSTNAME)
    return CertificateStore([CertificateConfig("main", (HOSTNAME,), cert, key)])


def tap_spy(proxy: Proxy) -> list[str]:
    """Activate debug output for every session and record the text given to the debug log."""
    proxy.deps.debug_rules.add(RuleKind.ALL, "", 600, False)
    return record_debug_writes(proxy)


def record_debug_writes(proxy: Proxy) -> list[str]:
    """Record the text given to the debug log as ``"<direction> <text>"``."""
    texts: list[str] = []
    real_write = proxy.deps.debug_log.write

    def write(session_id: str, direction: str, text: str, *, ts: float | None = None) -> None:
        texts.append(f"{direction} {text}")
        real_write(session_id, direction, text, ts=ts)

    proxy.deps.debug_log.write = write  # type: ignore[method-assign]
    return texts


def debug_file_text(proxy: Proxy) -> str:
    """Flush and close the debug log and return what it wrote to disk."""
    proxy.deps.debug_log.close()
    return proxy.deps.debug_log._path.read_text()
