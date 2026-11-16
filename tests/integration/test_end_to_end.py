# SPDX-License-Identifier: GPL-3.0-or-later
"""End to end: the real ``Application`` on random ports, ``FakeMta`` backends, a real Redis,
a SQLite domain database and generated certificates (spec 10.2, integration layer)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import warnings
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
import redis

from asspng.checks.penalty_box import PenaltyBox
from asspng.config.errors import ConfigError
from asspng.db.migrate import HEAD_REVISION
from asspng.db.repository import DomainRepository
from asspng.domains.index import DomainEntry, save_snapshot
from asspng.domains.refresher import EVENT_DOMAINS_CHANGED
from asspng.service import app as app_module
from asspng.service import app_build
from asspng.service.app import Application, main
from asspng.service.control import control_request
from asspng.smtp.replies import (
    R_BACKEND_DOWN,
    R_DATA_GO,
    R_RELAY_DENIED,
    R_SCORE,
    R_TEMPFAIL,
    R_TRY_LATER,
)
from asspng.state.redis_store import RedisStore
from tests.support.certs import make_cert
from tests.support.fake_mta import FakeMta
from tests.support.redis_server import RedisServer
from tests.support.e2e import (
    AUTH_PLAIN,
    BODY,
    HOSTNAME,
    LOCAL_DOMAIN,
    Env,
    StaticResolver,
    authenticate,
    deliver,
    envelope,
    free_port,
    result_of,
    send_data,
    toml_text,
    wait_until,
)
from tests.support.smtp_client import client_tls_context, smtp_dialog


@pytest.fixture
async def alert_mta() -> AsyncIterator[tuple[FakeMta, int]]:
    """An MTA that receives the alert email."""
    mta = FakeMta()
    _, port = await mta.start()
    try:
        yield mta, port
    finally:
        await mta.stop()


@pytest.fixture
def private_redis(tmp_path: Path) -> Iterator[RedisServer]:
    """A Redis of this test only: it may be stopped and started again."""
    workdir = tmp_path / "redis"
    workdir.mkdir()
    server = RedisServer(workdir)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def alert_subjects(mta: FakeMta) -> list[str]:
    subjects = []
    for _, _, body in mta.messages:
        for line in body.decode("utf-8", "replace").splitlines():
            if line.startswith("Subject: "):
                subjects.append(line[len("Subject: "):])
    return subjects


async def health(app: Application) -> tuple[int, dict[str, object]]:
    host, port = app.health_address
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(b"GET /health HTTP/1.0\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5)
    finally:
        writer.close()
    head, _, body = data.partition(b"\r\n\r\n")
    snapshot: dict[str, object] = json.loads(body)
    return int(head.split()[1]), snapshot


# --- delivery ---------------------------------------------------------------------------------


async def test_inbound_delivery_ipv4(env: Env) -> None:
    await env.start()
    async with env.dialog() as c:
        assert (await deliver(c)).code == 250
        assert (await c.send("QUIT")).code == 221
    [(mail_from, rcpts, body)] = env.mta.messages
    assert (mail_from, rcpts) == ("sender@remote.test", [f"user@{LOCAL_DOMAIN}"])
    assert body.startswith(b"X-ASSP-NG-ID: e2e-")
    assert body.endswith(BODY)
    assert env.mta.xclient_attrs[0]["ADDR"] == "127.0.0.1"
    assert env.mta.xclient_attrs[0]["NAME"] == "client.test"
    await env.stop()
    [line] = env.maillog()
    assert " l=inbound ip=127.0.0.1 ptr=client.test " in line
    assert result_of(line) == "accepted"


def ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


@pytest.mark.skipif(not ipv6_loopback(), reason="no IPv6 loopback")
async def test_inbound_delivery_ipv6_loopback(env: Env) -> None:
    env.listeners[0].update(ipv4=False, ipv6=True, bind6="::1")
    app = await env.start()
    [(name, host, port)] = app.addresses()
    assert (name, host) == ("inbound", "::1")
    async with smtp_dialog("::1", port) as c:
        assert (await deliver(c)).code == 250
    assert len(env.mta.messages) == 1
    assert env.mta.xclient_attrs[0]["ADDR"] == "IPV6:::1"
    await env.stop()
    [line] = env.maillog()
    assert " ip=::1 " in line and result_of(line) == "accepted"


async def test_mapped_ipv4_keyed_as_ipv4(env: Env, redis_server: RedisServer) -> None:
    app = await env.start()
    prefix = str(env.system["redis.key_prefix"])
    # Another instance (or the CLI) blocks the IPv4 network in the shared Redis.
    store = RedisStore(redis_server.url, prefix, 2.0)
    box = PenaltyBox(store, threshold=50, score_cap=100, score_ttl_s=3600, ladder_s=[3600],
                     history_s=3600, clock=time.time)
    await box.block("127.0.0.1/32", 3600, "test")
    await store.close()
    # A dual-stack socket reports the IPv4 client as ::ffff:127.0.0.1.
    dual = socket.create_server(("::", 0), family=socket.AF_INET6, dualstack_ipv6=True)
    peers: list[str] = []
    listener = app.config.listeners[0]

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peers.append(writer.get_extra_info("peername")[0])
        await app.handle_connection(listener, reader, writer)

    server = await asyncio.start_server(handle, sock=dual)
    try:
        async with smtp_dialog("127.0.0.1", dual.getsockname()[1]) as c:
            assert await c.reply() == R_TRY_LATER  # the penalty box knows 127.0.0.1/32
            await c.expect_closed()
    finally:
        server.close()
        await server.wait_closed()
    assert peers == ["::ffff:127.0.0.1"]
    client = redis.Redis.from_url(redis_server.url)
    try:
        # The penalty box refuses first: a blocked network does not use the rate counter.
        assert client.exists(f"{prefix}rl:conn:127.0.0.1/32") == 0
    finally:
        client.close()
    assert env.mta.lines == []  # refused before the MTA was contacted
    await env.stop()
    [line] = env.maillog()
    assert " ip=127.0.0.1 " in line and result_of(line) == "rejected"


async def test_submission_starttls_auth_relay(env: Env) -> None:
    env.use_tls()
    env.listeners[0].update(name="submission", kind="submission")
    await env.start()
    async with env.dialog() as c:
        await c.expect_banner()
        ehlo = await c.send("EHLO client.test")
        assert "STARTTLS" in ehlo.lines
        assert not any(line.startswith("AUTH") for line in ehlo.lines)  # no AUTH before TLS
        assert (await c.send("STARTTLS")).code == 220
        await c.starttls(client_tls_context(), server_hostname=HOSTNAME)
        await authenticate(c)
        assert (await c.send("MAIL FROM:<test@example.com>")).code == 250
        assert (await c.send("RCPT TO:<friend@remote.test>")).code == 250  # relay after AUTH
        assert (await send_data(c)).code == 250
    assert env.mta.auth_attempts == [("PLAIN", "test", True)]
    [(_, rcpts, _)] = env.mta.messages
    assert rcpts == ["friend@remote.test"]
    await env.stop()
    [line] = env.maillog()
    assert " auth=test " in line and " tls=TLSv1.3 " in line and result_of(line) == "accepted"
    for name in ("maillog.log", "assp-ng.log", "debug.log"):
        assert AUTH_PLAIN not in env.log_text(name)


async def test_submissions_implicit_tls(env: Env) -> None:
    env.use_tls()
    env.listeners[0].update(name="submissions", kind="submissions")
    await env.start()
    async with env.dialog(tls=True) as c:
        await c.expect_banner()
        await authenticate(c)
        assert (await c.send("MAIL FROM:<test@example.com>")).code == 250
        assert (await c.send("RCPT TO:<friend@remote.test>")).code == 250
        assert (await send_data(c)).code == 250
    assert len(env.mta.messages) == 1
    await env.stop()
    [line] = env.maillog()
    assert " l=submissions " in line and " tls=TLSv1.3 " in line


# --- state, backends and alerts -----------------------------------------------------------------


async def test_redis_stopped_degraded_then_recovers(
    env: Env, private_redis: RedisServer, alert_mta: tuple[FakeMta, int]
) -> None:
    env.system["redis.url"] = private_redis.url
    env.enable_alerts(alert_mta[1])
    app = await env.start()
    assert (await health(app))[1]["status"] == "ok"
    private_redis.stop()
    async with env.dialog() as c:
        assert (await deliver(c)).code == 250  # mail still flows
    code, snapshot = await health(app)
    assert (code, snapshot["status"], snapshot["mode"], snapshot["redis"]) == (
        200, "degraded", "DEGRADED", "down")
    await wait_until(lambda: "[ASSP-NG e2e] state-degraded" in alert_subjects(alert_mta[0]))
    private_redis.start()

    async def mode() -> object:
        return (await health(app))[1]["mode"]

    deadline = time.monotonic() + 5
    while await mode() != "NORMAL":  # the probe loop runs every second
        assert time.monotonic() < deadline
        await asyncio.sleep(0.1)
    assert (await health(app))[1]["status"] == "ok"
    async with env.dialog() as c:
        assert (await deliver(c)).code == 250
    assert len(env.mta.messages) == 2
    await wait_until(lambda: "[ASSP-NG e2e] state-normal" in alert_subjects(alert_mta[0]))


async def test_strict_redis_failure_goes_to_tempfail(
    env: Env, private_redis: RedisServer, alert_mta: tuple[FakeMta, int]
) -> None:
    env.system["redis.url"] = private_redis.url
    env.system["state.on_redis_failure"] = "tempfail"
    env.enable_alerts(alert_mta[1])
    app = await env.start()
    private_redis.stop()
    async with env.dialog() as c:  # admitted while NORMAL; its checks hit the outage
        await c.expect_banner()
    await wait_until(lambda: "[ASSP-NG e2e] state-tempfail" in alert_subjects(alert_mta[0]))
    async with env.dialog() as c:
        assert await c.reply() == R_TEMPFAIL  # refused at the greeting
        await c.expect_closed()
    code, snapshot = await health(app)
    counters = snapshot["counters"]
    assert (code, snapshot["mode"]) == (503, "TEMPFAIL")
    assert isinstance(counters, dict) and counters["check_error"] >= 1


async def test_domains_changed_event_refreshes(
    env: Env, redis_server: RedisServer, tmp_path: Path
) -> None:
    app = await env.start()
    channel = f"{env.system['redis.key_prefix']}events"
    client = redis.Redis.from_url(redis_server.url)
    try:
        await wait_until(lambda: dict(client.pubsub_numsub(channel))[channel.encode()] == 1)
        repo = DomainRepository(str(env.system["database.url"]), "test")
        try:
            repo.add("new.test", include_subdomains=False, note=None, actor="test")
        finally:
            repo.close()
        client.publish(channel, EVENT_DOMAINS_CHANGED)
    finally:
        client.close()

    async def count() -> object:
        domains = (await health(app))[1]["domains"]
        assert isinstance(domains, dict)
        return domains["count"]

    deadline = time.monotonic() + 5
    while await count() != 2:
        assert time.monotonic() < deadline
        await asyncio.sleep(0.05)
    async with env.dialog() as c:
        assert (await envelope(c, "user@new.test")).code == 250
    snapshot = json.loads((env.cache / "local-domains.json").read_text())
    assert [e["domain"] for e in snapshot["entries"]] == [LOCAL_DOMAIN, "new.test"]


async def test_backend_down_421(env: Env, alert_mta: tuple[FakeMta, int]) -> None:
    env.listeners[0]["backend"] = f"127.0.0.1:{free_port()}"  # nothing listens there
    env.enable_alerts(alert_mta[1])
    app = await env.start()
    for _ in range(3):
        async with env.dialog() as c:
            assert await c.reply() == R_BACKEND_DOWN
            await c.expect_closed()
    code, snapshot = await health(app)
    assert (code, snapshot["status"], snapshot["backends"]) == (503, "failing",
                                                                {"inbound": "down"})
    await wait_until(
        lambda: "[ASSP-NG e2e] backend-down-inbound" in alert_subjects(alert_mta[0]))
    await env.stop()
    assert [result_of(line) for line in env.maillog()] == ["tempfailed"] * 3


async def test_certificate_expiry_alert(env: Env, alert_mta: tuple[FakeMta, int]) -> None:
    env.cert, env.key = make_cert(env.cert.parent, "short.test", days=10)
    env.use_tls()
    env.enable_alerts(alert_mta[1])
    app = await env.start()
    assert (await health(app))[1]["certificates"] == {"main": {"days_left": 9}}
    await wait_until(
        lambda: "[ASSP-NG e2e] certificate-expiry" in alert_subjects(alert_mta[0]))


async def test_memory_soft_limit_refuses_and_alerts(
    env: Env, alert_mta: tuple[FakeMta, int]
) -> None:
    env.system["memory.soft_limit_mb"] = 1  # always exceeded
    env.enable_alerts(alert_mta[1])
    await env.start()
    await wait_until(lambda: "[ASSP-NG e2e] memory-limit" in alert_subjects(alert_mta[0]))
    async with env.dialog() as c:
        assert await c.reply() == R_TEMPFAIL
        await c.expect_closed()
    assert env.mta.lines == []


# --- reload -----------------------------------------------------------------------------------


@pytest.mark.parametrize("broken", ["default.toml", "user.d", "tls.certificate"])
async def test_invalid_reload_keeps_config(env: Env, broken: str) -> None:
    env.default_toml = "[scoring]\nlimit = 40\nwarn = 30\n"
    env.use_tls()
    app = await env.start()
    if broken == "default.toml":
        (env.etc / "default.toml").write_text("[scoring]\nlimit = -5\n", encoding="utf-8")
    elif broken == "tls.certificate":
        env.certificates = []  # STARTTLS is offered: the certificates cannot all go
        env.default_toml = "[scoring]\nlimit = 45\nwarn = 30\n"
        env.write()
    else:
        (env.etc / "user.d").mkdir()
        (env.etc / "user.d" / "jano@example.com.toml").write_text("testmode = 'maybe'\n",
                                                                  encoding="utf-8")
    assert await app.reload() is False
    assert app.config.default_layer["scoring.limit"] == 40
    assert app.config.user_layers == {}
    async with env.dialog() as c:  # still serving with the old configuration
        assert (await deliver(c)).code == 250
    await env.stop()
    log = env.log_text("assp-ng.log")
    assert "configuration reload failed" in log
    assert broken in log


async def test_reload_during_transaction_keeps_policy(env: Env) -> None:
    # Every message scores 0 >= limit 0: only test mode lets it through, tagged.
    env.default_toml = "testmode = true\n[scoring]\nlimit = 0\nwarn = 0\n"
    app = await env.start()
    async with env.dialog() as old:
        assert (await envelope(old)).code == 250
        (env.etc / "domain.d").mkdir()
        (env.etc / "domain.d" / f"{LOCAL_DOMAIN}.toml").write_text("testmode = false\n",
                                                                   encoding="utf-8")
        assert await app.reload() is True
        assert app.config.domain_layers[LOCAL_DOMAIN]["testmode"] is False
        async with env.dialog() as new:
            assert await envelope(new) == R_SCORE  # a new session has the new policy
        assert (await send_data(old)).code == 250  # the open transaction keeps the old one
    [(_, _, body)] = env.mta.messages
    assert b"X-ASSP-NG-Test: would reject: score: 0 >= 0" in body
    await env.stop()
    assert "accepted-test" in [result_of(line) for line in env.maillog()]
    assert "testmode changed in" in env.log_text("assp-ng.log")


async def test_reload_keeps_restart_keys_new_sessions_spool_as_before(
    env: Env, tmp_path: Path
) -> None:
    """C8: settings read only at start keep their running values until a restart, so a new
    session never spools into a directory the start did not create."""
    env.system["buffer.memory_total"] = 4096  # every message overflows to the spool
    app = await env.start()
    running = {key: app.config.get(key) for key in ("paths.spool", "instance", "timeouts.ptr")}
    moved = tmp_path / "spool-moved"  # only a start creates the spool directory
    env.system.update({"paths.spool": str(moved), "instance": "renamed", "timeouts.ptr": 2})
    env.write()
    assert await app.reload() is True
    assert {key: app.config.get(key) for key in running} == running
    body = b"Subject: big\r\n\r\n" + (b"y" * 998 + b"\r\n") * 30
    async with env.dialog() as c:  # a session that started after the reload
        assert (await envelope(c)).code == 250
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(body)
        await wait_until(lambda: any(env.spool.iterdir()))  # the running spool directory
        await c.send_raw(b".\r\n")
        assert (await c.reply()).code == 250
    assert not moved.exists()
    await env.stop()
    [line] = env.maillog()
    assert " e2e s=" in line and result_of(line) == "accepted"
    log = env.log_text("assp-ng.log")
    for key in running:
        assert f"{key} changed in {env.etc / 'assp-ng.toml'} (system): restart required" in log


async def test_sighup_reloads_and_sigterm_stops(env: Env) -> None:
    app = await env.start()
    address = env.address()
    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        assert signal.getsignal(sig) not in (signal.SIG_DFL, signal.SIG_IGN, None)
    env.system["log.level"] = "debug"  # read at start only
    env.default_toml = "[scoring]\nlimit = 42\n"
    env.write()
    os.kill(os.getpid(), signal.SIGHUP)
    await wait_until(lambda: app.config.default_layer.get("scoring.limit") == 42)
    os.kill(os.getpid(), signal.SIGTERM)
    await asyncio.wait_for(app.wait_closed(), 10)
    assert await app.reload() is False  # stopped
    log = env.log_text("assp-ng.log")
    assert "log.level changed in" in log and "(system): restart required" in log
    assert "SIGTERM received" in log
    assert signal.getsignal(signal.SIGHUP) is signal.SIG_DFL
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    with pytest.raises(OSError):
        await asyncio.open_connection(*address)


async def test_raising_closer_still_closes(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    """C2: a closer that raises must not leave wait_closed() (and so main()) hanging."""
    app = await env.start()
    address = env.address()

    def broken() -> None:
        raise RuntimeError("closer broke")
    app._stack.callback(broken)
    await asyncio.wait_for(app.shutdown(), 10)
    await asyncio.wait_for(app.wait_closed(), 1)
    with pytest.raises(OSError):
        await asyncio.open_connection(*address)
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL  # the other closers ran


async def test_failing_session_drain_still_closes(env: Env,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    app = await env.start()

    async def broken_drain() -> None:
        raise RuntimeError("drain broke")
    monkeypatch.setattr(app, "_drain_sessions", broken_drain)
    await asyncio.wait_for(app.shutdown(), 10)
    await asyncio.wait_for(app.wait_closed(), 1)
    assert not (env.run / "control.sock").exists()


class SlowStart:
    """Holds ``LocalDomains.start`` (the middle of ``Application.start``) until released."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.reached = asyncio.Event()
        self.release = asyncio.Event()
        original = app_build.LocalDomains.start

        async def start(domains: app_build.LocalDomains) -> None:
            self.reached.set()
            await self.release.wait()
            await original(domains)
        monkeypatch.setattr(app_build.LocalDomains, "start", start)


async def test_sigterm_during_start_stops_cleanly(env: Env,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    """C3: the handlers are installed first; a stop signal cancels the start."""
    slow = SlowStart(monkeypatch)
    env.write()
    app = Application(env.etc / "assp-ng.toml", resolver=StaticResolver())
    env.app = app
    starting = asyncio.create_task(app.start())
    await asyncio.wait_for(slow.reached.wait(), 5)
    assert signal.getsignal(signal.SIGTERM) not in (signal.SIG_DFL, signal.SIG_IGN, None)
    app._on_stop_signal(signal.SIGTERM)
    await asyncio.wait_for(starting, 5)  # returns: a requested stop is not a failure
    await asyncio.wait_for(app.wait_closed(), 1)
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    assert "start failed" not in env.log_text("assp-ng.log")
    assert "SIGTERM received" in env.log_text("assp-ng.log")


async def test_sighup_during_start_reloads_once_serving(env: Env,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    slow = SlowStart(monkeypatch)
    env.write()
    app = Application(env.etc / "assp-ng.toml", resolver=StaticResolver())
    env.app = app
    starting = asyncio.create_task(app.start())
    await asyncio.wait_for(slow.reached.wait(), 5)
    app._on_reload_signal()
    env.default_toml = "[scoring]\nlimit = 42\n"
    env.write()
    slow.release.set()
    await asyncio.wait_for(starting, 5)
    await wait_until(lambda: app.config.default_layer.get("scoring.limit") == 42)
    assert "reload ignored" not in env.log_text("assp-ng.log")


# --- start-up ---------------------------------------------------------------------------------


async def test_missing_default_toml_refuses_start(env: Env) -> None:
    env.write()
    (env.etc / "default.toml").unlink()
    app = Application(env.etc / "assp-ng.toml", resolver=StaticResolver())
    with pytest.raises(ConfigError) as info:
        await app.start()
    assert any("default.toml" in error and "assp-ng config init" in error
               for error in info.value.errors)
    assert not (env.run / "control.sock").exists()
    assert not (env.logs / "assp-ng.log").exists()
    await app.shutdown()  # harmless after a refused start


async def test_start_guards(env: Env) -> None:
    env.write()
    wrong_name = env.etc / "proxy.toml"
    (env.etc / "assp-ng.toml").rename(wrong_name)
    app = Application(wrong_name)
    with pytest.raises(RuntimeError, match="not been started"):
        app.config
    assert await app.reload() is False  # nothing to reload yet
    with pytest.raises(ConfigError, match="must be named assp-ng.toml"):
        await app.start()
    with pytest.raises(RuntimeError, match="starts only once"):
        await app.start()


def write_minimal(tmp_path: Path, redis_url: str, run: Path, **extra: object) -> Path:
    etc = tmp_path / "etc"
    etc.mkdir()
    system: dict[str, object] = {
        "hostname": HOSTNAME, "redis.url": redis_url,
        "redis.key_prefix": f"e2e:{uuid.uuid4().hex}:",
        "paths.spool": str(tmp_path / "spool"), "paths.cache": str(tmp_path / "cache"),
        "paths.run": str(run), "paths.log_dir": str(tmp_path / "logs"),
        "health.listen": "127.0.0.1:0", **extra}
    listener: dict[str, object] = {"name": "inbound", "kind": "smtp", "port": 0, "ipv6": False,
                                   "bind4": "127.0.0.1", "backend": f"127.0.0.1:{free_port()}"}
    (etc / "assp-ng.toml").write_text(toml_text(system, [("listener", listener)]),
                                      encoding="utf-8")
    (etc / "default.toml").write_text("", encoding="utf-8")
    return etc / "assp-ng.toml"


@pytest.fixture
def idle_loop_closed() -> None:
    """``main()`` runs its own loop with ``asyncio.run()``, which replaces the idle loop that
    pytest-asyncio leaves set after an async test; close that one so it does not leak."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            idle = asyncio.get_event_loop_policy().get_event_loop()
        except RuntimeError:
            return
    if not idle.is_running():
        idle.close()


@pytest.mark.usefixtures("idle_loop_closed")
def test_main_invalid_config_exits_2_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = write_minimal(tmp_path, "redis://127.0.0.1:1/0", tmp_path / "run",
                           **{"timeouts.command": 0, "log.level": "loud"})
    assert main(["--config", str(config)]) == 2
    err = capsys.readouterr().err
    assert "timeouts.command" in err and "log.level" in err
    assert "Traceback" not in err


@pytest.mark.usefixtures("idle_loop_closed")
def test_main_start_failure_exits_1_and_cleans_up(
    tmp_path: Path, redis_server: RedisServer, capsys: pytest.CaptureFixture[str]
) -> None:
    run = Path(tempfile.mkdtemp(dir="/tmp", prefix="asspm"))
    try:
        with socket.create_server(("127.0.0.1", 0)) as busy:
            config = write_minimal(tmp_path, redis_server.url, run,
                                   **{"health.listen": f"127.0.0.1:{busy.getsockname()[1]}"})
            assert main(["--config", str(config)]) == 1
        # C4: an OSError says why, secret-free: its errno and strerror
        assert "cannot start: OSError: [Errno 98] " in capsys.readouterr().err
        assert "start failed: OSError" in (tmp_path / "logs" / "assp-ng.log").read_text()
        assert not (run / "control.sock").exists()
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    finally:
        shutil.rmtree(run, ignore_errors=True)


PASSWORD = "S3cretPW"


class RecordingJournal(logging.Handler):
    """Stands in for ``systemd.journal.JournalHandler``: keeps what would reach journald."""

    lines: list[str] = []

    def __init__(self, **kwargs: object) -> None:
        super().__init__()

    def emit(self, record: logging.LogRecord) -> None:
        RecordingJournal.lines.append(self.format(record))


@pytest.fixture
def journal(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Log to a recording journal handler as if running under systemd."""
    import systemd.journal

    RecordingJournal.lines = []
    monkeypatch.setattr(systemd.journal, "JournalHandler", RecordingJournal)
    monkeypatch.setattr(app_module, "journal_wanted", lambda: True)
    return RecordingJournal.lines


def assert_no_password(tmp_path: Path, journal: list[str], caplog: pytest.LogCaptureFixture,
                       *outputs: str) -> None:
    log = tmp_path / "logs" / "assp-ng.log"
    texts = [*outputs, caplog.text, *journal, log.read_text() if log.exists() else ""]
    assert all(PASSWORD not in text for text in texts)


@pytest.mark.usefixtures("idle_loop_closed")
def test_malformed_database_url_never_leaks(
    tmp_path: Path, journal: list[str], caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str]
) -> None:
    config = write_minimal(tmp_path, "redis://127.0.0.1:1/0", tmp_path / "run",
                           **{"database.url": f"mysql+pymysql:/assp:{PASSWORD}@db/assp"})
    assert main(["--config", str(config)]) == 2
    out, err = capsys.readouterr()
    assert "database.url" in err and "Traceback" not in err
    assert_no_password(tmp_path, journal, caplog, out, err)


class DatabaseBroke(Exception):
    pass


@pytest.mark.usefixtures("idle_loop_closed")
def test_start_failure_never_leaks_database_url(
    tmp_path: Path, redis_server: RedisServer, journal: list[str],
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"mysql+pymysql://assp:{PASSWORD}@db.invalid/assp?ssl_ca=/etc/ssl/certs/ca.pem"

    def broken_source(database_url: str) -> object:
        raise DatabaseBroke(f"cannot use {database_url}")

    monkeypatch.setattr(app_build, "current_revision", lambda database_url: HEAD_REVISION)
    monkeypatch.setattr(app_build, "DatabaseDomainSource", broken_source)
    run = Path(tempfile.mkdtemp(dir="/tmp", prefix="asspm"))
    try:
        config = write_minimal(tmp_path, redis_server.url, run, **{"database.url": url})
        assert main(["--config", str(config)]) == 1
    finally:
        shutil.rmtree(run, ignore_errors=True)
    out, err = capsys.readouterr()
    assert "cannot start: DatabaseBroke" in err and "Traceback" not in err
    assert "start failed: DatabaseBroke" in (tmp_path / "logs" / "assp-ng.log").read_text()
    assert any("start failed: DatabaseBroke" in line for line in journal)
    assert_no_password(tmp_path, journal, caplog, out, err)


@pytest.mark.parametrize("listen", ["0.0.0.0:0", "[2001:db8::1]:0"])
async def test_health_listen_must_be_loopback_at_start(env: Env, listen: str) -> None:
    env.system["health.listen"] = listen
    with pytest.raises(ConfigError) as info:
        await env.start()
    assert any("health.listen" in error for error in info.value.errors)


@pytest.mark.parametrize("listen", ["0.0.0.0:0", "[2001:db8::1]:0"])
async def test_health_listen_must_be_loopback_at_reload(env: Env, listen: str) -> None:
    app = await env.start()
    env.system["health.listen"] = listen
    env.write()
    assert await app.reload() is False
    assert app.config.get("health.listen") == "127.0.0.1:0"
    await env.stop()
    assert "health.listen" in env.log_text("assp-ng.log")


def test_module_entry_point_exits_2(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "asspng.proxy", "--config", str(tmp_path / "assp-ng.toml")],
        cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=60)
    assert result.returncode == 2
    assert "assp-ng.toml: file is missing" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.usefixtures("idle_loop_closed")
def test_main_returns_0_after_sigterm(tmp_path: Path, redis_server: RedisServer) -> None:
    run = Path(tempfile.mkdtemp(dir="/tmp", prefix="asspm"))
    try:
        config = write_minimal(tmp_path, redis_server.url, run)
        original = signal.getsignal(signal.SIGTERM)

        def stop_when_ready() -> None:
            deadline = time.monotonic() + 20
            while signal.getsignal(signal.SIGTERM) is original:  # not installed yet
                if time.monotonic() > deadline:
                    return
                time.sleep(0.01)
            os.kill(os.getpid(), signal.SIGTERM)

        stopper = threading.Thread(target=stop_when_ready)
        stopper.start()
        try:
            assert main(["--config", str(config)]) == 0
        finally:
            stopper.join()
        assert "shutting down" in (tmp_path / "logs" / "assp-ng.log").read_text()
    finally:
        shutil.rmtree(run, ignore_errors=True)


async def test_spool_overflow_to_disk(env: Env) -> None:
    env.system["buffer.memory_total"] = 4096  # the in-memory budget overflows at once
    leftover = env.spool / "tmpleftover"
    leftover.write_bytes(b"from a crash")
    await env.start()
    assert not leftover.exists()  # purged at start
    body = b"Subject: big\r\n\r\n" + b"x" * 998 + b"\r\n"
    body += (b"y" * 998 + b"\r\n") * 30
    async with env.dialog() as c:
        assert (await envelope(c)).code == 250
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(body)
        await wait_until(lambda: any(env.spool.iterdir()))
        [spooled] = list(env.spool.iterdir())
        assert stat.S_IMODE(spooled.stat().st_mode) == 0o600
        await c.send_raw(b".\r\n")
        assert (await c.reply()).code == 250
    [(_, _, delivered)] = env.mta.messages
    assert delivered.endswith(body)
    await wait_until(lambda: not any(env.spool.iterdir()))


@pytest.mark.parametrize("database", ["unreachable", "schema-mismatch", "none"])
async def test_domain_snapshot_fallback(
    env: Env, tmp_path: Path, alert_mta: tuple[FakeMta, int], database: str
) -> None:
    save_snapshot(env.cache / "local-domains.json", [DomainEntry("snapshot.test", False)])
    if database == "unreachable":
        env.system["database.url"] = f"sqlite:///{tmp_path / 'missing' / 'db.sqlite'}"
    elif database == "schema-mismatch":
        env.system["database.url"] = f"sqlite:///{tmp_path / 'empty.sqlite'}"
    else:
        env.system["database.url"] = ""
    env.enable_alerts(alert_mta[1])
    app = await env.start()
    async with env.dialog() as c:
        assert (await envelope(c, "user@snapshot.test")).code == 250
        assert await c.send(f"RCPT TO:<user@{LOCAL_DOMAIN}>") == R_RELAY_DENIED
    _, snapshot = await health(app)
    assert snapshot["domains"] == {"source": "snapshot", "count": 1}
    assert snapshot["status"] == "degraded"
    if database == "schema-mismatch":
        await wait_until(
            lambda: "[ASSP-NG e2e] schema-mismatch" in alert_subjects(alert_mta[0]))


async def test_debug_via_control_socket_during_redis_outage(
    env: Env, private_redis: RedisServer
) -> None:
    env.system["redis.url"] = private_redis.url
    await env.start()
    private_redis.stop()
    sock = env.run / "control.sock"
    assert stat.S_IMODE(os.stat(sock).st_mode) == 0o660
    rule = await control_request(sock, "debug.on", {"kind": "ip", "value": "127.0.0.1",
                                                    "duration_s": 600, "headers": False})
    assert isinstance(rule, dict)
    assert (rule["kind"], rule["value"], rule["headers"]) == ("ip", "127.0.0.1/32", False)
    assert await control_request(sock, "debug.list", {}) == [rule]
    with pytest.raises(RuntimeError, match="unknown rule kind"):
        await control_request(sock, "debug.on", {"kind": "planet", "value": "x"})
    async with env.dialog() as c:
        assert (await deliver(c)).code == 250
    status = await control_request(sock, "status", {})
    assert isinstance(status, dict)
    assert (status["mode"], status["debug_rules"]) == ("DEGRADED", 1)
    assert await control_request(sock, "debug.off", {"id": rule["id"]}) == {"removed": 1}
    assert await control_request(sock, "debug.list", {}) == []
    await env.stop()
    debug = env.log_text("debug.log")
    assert "C>P EHLO client.test" in debug and "P>M MAIL FROM:<sender@remote.test>" in debug
    assert "hello world" not in debug  # message bodies are never logged


async def test_debug_log_full_switches_rules_off(env: Env) -> None:
    (env.logs / "debug.log").write_bytes(b"x" * 1024 * 1024)  # debug.max_size_mb = 1 reached
    env.system["debug.max_size_mb"] = 1
    await env.start()
    sock = env.run / "control.sock"
    await control_request(sock, "debug.on", {"kind": "listener", "value": "inbound"})
    async with env.dialog() as c:
        await c.expect_banner()
    await wait_until(lambda: (env.run / "debug-rules.json").read_text() == "[]")
    assert await control_request(sock, "debug.list", {}) == []
    await env.stop()
    assert "debug rules switched off" in env.log_text("assp-ng.log")
    assert (env.logs / "debug.log").stat().st_size == 1024 * 1024


# --- lifecycle --------------------------------------------------------------------------------


async def test_shutdown_answers_idle_sessions_only(env: Env) -> None:
    app = await env.start()
    host, port = env.address()
    # A connection accepted just before the listeners closed reaches the handler late.
    late = await asyncio.start_server(
        lambda r, w: app.handle_connection(app.config.listeners[0], r, w), "127.0.0.1", 0)
    async with env.dialog() as idle, env.dialog() as busy, env.dialog() as leaving:
        await idle.expect_banner()
        assert (await idle.send("EHLO client.test")).code == 250
        assert (await envelope(busy)).code == 250
        assert await busy.send("DATA") == R_DATA_GO
        await busy.send_raw(b"Subject: unfinished\r\n\r\n")
        await leaving.expect_banner()
        assert env.app is not None
        stopping = asyncio.create_task(env.app.shutdown())
        await asyncio.sleep(0.1)
        with pytest.raises(OSError):  # the listeners are closed first
            await asyncio.open_connection(host, port)
        assert (await leaving.send("QUIT")).code == 221  # served within the grace period
        async with smtp_dialog(*late.sockets[0].getsockname()[:2]) as refused:
            await refused.expect_closed()
        assert await idle.reply(timeout=5) == R_TEMPFAIL
        await idle.expect_closed()
        await busy.expect_closed(timeout=5)  # nothing written in the middle of DATA
        await asyncio.wait_for(stopping, 10)
    late.close()
    await late.wait_closed()
    assert env.mta.messages == []
    assert sorted(result_of(line) for line in env.maillog()) == ["quit", "shutdown", "shutdown"]


async def test_session_setup_failure_keeps_serving(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = await env.start()
    real_session = app_module.Session
    calls: list[int] = []

    class BrokenRun:
        async def run(self) -> None:
            raise ValueError("secret run detail")

    def flaky_session(*args: object, **kwargs: object) -> object:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("secret setup detail")
        if len(calls) == 2:
            return BrokenRun()
        return real_session(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(app_module, "Session", flaky_session)
    for _ in range(2):
        async with env.dialog() as c:
            await c.expect_closed()  # closed without a word
    async with env.dialog() as c:
        assert (await deliver(c)).code == 250
    _, snapshot = await health(app)
    counters = snapshot["counters"]
    assert isinstance(counters, dict) and counters["session_error"] == 2
    await env.stop()
    log = env.log_text("assp-ng.log")
    assert "cannot set up a session on listener inbound: RuntimeError" in log
    assert "session failed on listener inbound: ValueError" in log
    assert "secret setup detail" not in log and "secret run detail" not in log
