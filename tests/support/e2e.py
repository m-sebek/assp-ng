# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared end-to-end fixtures: the real ``Application`` on random ports, ``FakeMta`` backends,
a real Redis, a SQLite domain database and generated certificates (spec 10.2).

Registered as a pytest plugin by ``tests/conftest.py``, so integration and security tests use
the same ``env`` fixture."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import shutil
import socket
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from asspng.db.migrate import upgrade
from asspng.db.repository import DomainRepository
from asspng.net.dns import PtrResult
from asspng.net.ipnet import IPAddress
from asspng.service.app import Application
from asspng.smtp.replies import R_DATA_GO, Reply
from tests.support.certs import make_cert
from tests.support.fake_mta import FakeMta
from tests.support.redis_server import RedisServer
from tests.support.smtp_client import SmtpDialog, client_tls_context, smtp_dialog

HOSTNAME = "proxy.test"
LOCAL_DOMAIN = "example.com"
BODY = b"Subject: hello\r\n\r\nhello world\r\n"
AUTH_PLAIN = base64.b64encode(b"\0test\0secret").decode()  # FakeMta's valid credentials


class StaticResolver:
    """PTR lookups without DNS: every client is ``client.test``."""

    async def lookup(self, addr: IPAddress) -> PtrResult:
        return PtrResult("client.test", False)


def toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    return json.dumps(str(value))


def toml_text(values: dict[str, object], tables: list[tuple[str, dict[str, object]]]) -> str:
    """Dotted top-level keys, then ``[[table]]`` entries."""
    lines = [f"{key} = {toml_value(value)}" for key, value in values.items()]
    for name, entry in tables:
        lines.append(f"\n[[{name}]]")
        lines += [f"{key} = {toml_value(value)}" for key, value in entry.items()]
    return "\n".join(lines) + "\n"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


async def wait_until(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached in time"
        await asyncio.sleep(0.02)


@dataclass
class Env:
    """One test installation: configuration files, directories, backends and the app."""

    etc: Path
    run: Path
    logs: Path
    spool: Path
    cache: Path
    mta: FakeMta
    cert: Path
    key: Path
    system: dict[str, object]
    listeners: list[dict[str, object]]
    certificates: list[dict[str, object]] = field(default_factory=list)
    default_toml: str = ""
    app: Application | None = None

    def write(self) -> None:
        tables = [("listener", entry) for entry in self.listeners]
        tables += [("tls.certificate", entry) for entry in self.certificates]
        (self.etc / "assp-ng.toml").write_text(toml_text(self.system, tables), encoding="utf-8")
        (self.etc / "default.toml").write_text(self.default_toml, encoding="utf-8")

    def use_tls(self) -> None:
        self.certificates = [{"name": "main", "hostnames": [HOSTNAME], "cert": str(self.cert),
                              "key": str(self.key)}]

    def enable_alerts(self, port: int) -> None:
        self.system["alerts.email"] = "admin@example.com"
        self.system["alerts.smtp_server"] = f"127.0.0.1:{port}"

    async def start(self, write: bool = True) -> Application:
        if write:
            self.write()
        self.app = Application(self.etc / "assp-ng.toml", resolver=StaticResolver())
        await self.app.start()
        return self.app

    async def stop(self) -> None:
        if self.app is not None:
            await self.app.shutdown()

    def address(self, name: str | None = None) -> tuple[str, int]:
        assert self.app is not None
        found = [(host, port) for listener, host, port in self.app.addresses()
                 if name is None or listener == name]
        return found[0]

    def dialog(self, name: str | None = None, tls: bool = False
               ) -> contextlib.AbstractAsyncContextManager[SmtpDialog]:
        host, port = self.address(name)
        return smtp_dialog(host, port, client_tls_context() if tls else None)

    def log_text(self, name: str) -> str:
        path = self.logs / name
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def maillog(self) -> list[str]:
        return self.log_text("maillog.log").splitlines()


@pytest.fixture(scope="module")
def db_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A migrated SQLite database with the local domain ``example.com``."""
    path = tmp_path_factory.mktemp("db") / "template.sqlite"
    url = f"sqlite:///{path}"
    upgrade(url)
    repo = DomainRepository(url, "test")
    try:
        repo.add(LOCAL_DOMAIN, include_subdomains=False, note=None, actor="test")
    finally:
        repo.close()
    return path


@pytest.fixture
async def env(tmp_path: Path, redis_server: RedisServer, db_template: Path
              ) -> AsyncIterator[Env]:
    mta = FakeMta()
    _, mta_port = await mta.start()
    run = Path(tempfile.mkdtemp(dir="/tmp", prefix="asspe"))  # short: a Unix socket lives here
    for name in ("etc", "logs", "spool", "cache", "certs"):
        (tmp_path / name).mkdir()
    cert, key = make_cert(tmp_path / "certs", HOSTNAME)
    db = tmp_path / "domains.sqlite"
    shutil.copy(db_template, db)
    system: dict[str, object] = {
        "instance": "e2e",
        "hostname": HOSTNAME,
        "database.url": f"sqlite:///{db}",
        "redis.url": redis_server.url,
        "redis.key_prefix": f"e2e:{uuid.uuid4().hex}:",
        "redis.op_timeout_ms": 200,
        "state.probe_interval_s": 1,
        "paths.spool": str(tmp_path / "spool"),
        "paths.cache": str(tmp_path / "cache"),
        "paths.run": str(run),
        "paths.log_dir": str(tmp_path / "logs"),
        "health.listen": "127.0.0.1:0",
        "timeouts.command": 5,
        "timeouts.backend_connect": 2,
        "timeouts.backend_banner": 2,
        "timeouts.backend_command": 5,
        "timeouts.ptr": 1,
        "timeouts.shutdown": 1,
    }
    listener: dict[str, object] = {
        "name": "inbound", "kind": "smtp", "port": 0, "ipv4": True, "ipv6": False,
        "bind4": "127.0.0.1", "backend": f"127.0.0.1:{mta_port}"}
    environment = Env(etc=tmp_path / "etc", run=run, logs=tmp_path / "logs",
                      spool=tmp_path / "spool", cache=tmp_path / "cache", mta=mta,
                      cert=cert, key=key, system=system, listeners=[listener])
    try:
        yield environment
    finally:
        await environment.stop()
        await mta.stop()
        shutil.rmtree(run, ignore_errors=True)


async def envelope(c: SmtpDialog, rcpt: str = f"user@{LOCAL_DOMAIN}") -> Reply:
    """Banner, EHLO and MAIL; return the reply to RCPT."""
    await c.expect_banner()
    assert (await c.send("EHLO client.test")).code == 250
    assert (await c.send("MAIL FROM:<sender@remote.test>")).code == 250
    return await c.send(f"RCPT TO:<{rcpt}>")


async def send_data(c: SmtpDialog, body: bytes = BODY) -> Reply:
    assert await c.send("DATA") == R_DATA_GO
    await c.send_raw(body + b".\r\n")
    return await c.reply()


async def deliver(c: SmtpDialog, rcpt: str = f"user@{LOCAL_DOMAIN}") -> Reply:
    assert (await envelope(c, rcpt)).code == 250
    return await send_data(c)


async def authenticate(c: SmtpDialog) -> None:
    ehlo = await c.send("EHLO client.test")
    assert any(line.startswith("AUTH") for line in ehlo.lines), ehlo
    assert (await c.send(f"AUTH PLAIN {AUTH_PLAIN}")).code == 235


def result_of(line: str) -> str:
    return line.split(" result=", 1)[1].split(" ", 1)[0]


class PeerWriter:
    """A ``StreamWriter`` that reports another peer address: the checks spare loopback and
    private clients, so abuse tests present a public one."""

    def __init__(self, writer: asyncio.StreamWriter, peer: tuple[str, int]) -> None:
        self._writer = writer
        self._peer = peer

    def get_extra_info(self, name: str, default: object = None) -> object:
        if name == "peername":
            return self._peer
        return self._writer.get_extra_info(name, default)

    def __getattr__(self, name: str) -> object:
        return getattr(self._writer, name)


@contextlib.asynccontextmanager
async def serve_as(env: Env, peer_ip: str, listener: str | None = None
                   ) -> AsyncIterator[tuple[str, int]]:
    """Serve the application's listener on a second random port, as if every client
    connected from ``peer_ip``; yields the address to connect to."""
    app = env.app
    assert app is not None
    config = next(item for item in app.config.listeners if listener in (None, item.name))

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        port = writer.get_extra_info("peername")[1]
        await app.handle_connection(
            config, reader, PeerWriter(writer, (peer_ip, port)))  # type: ignore[arg-type]

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield "127.0.0.1", server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()
