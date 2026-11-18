# SPDX-License-Identifier: GPL-3.0-or-later
"""ListenerManager: one server per enabled family, IPv6-only sockets, implicit TLS (R59)."""

from __future__ import annotations

import asyncio
import dataclasses
import socket
import ssl
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from asspng.config.errors import ConfigError
from asspng.config.model import CertificateConfig, ListenerConfig, ListenerKind
from asspng.proxy.listener import READ_LIMIT, ListenerManager
from asspng.tls.store import CertificateStore
from tests.support.certs import make_cert
from tests.support.smtp_client import client_tls_context

LISTENER = ListenerConfig(
    name="inbound", kind=ListenerKind.SMTP, port=0, ipv4=True, ipv6=True,
    bind4="127.0.0.1", bind6="::1", backend_host="127.0.0.1", backend_port=1, xclient=False,
    auth=False)


def ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


needs_ipv6 = pytest.mark.skipif(not ipv6_loopback(), reason="no IPv6 loopback")


class Recorder:
    """Connection handler that greets, records what it got and closes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, bool]] = []

    async def __call__(self, listener: ListenerConfig, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
        tls = writer.get_extra_info("ssl_object") is not None
        self.calls.append((listener.name, reader._limit, tls))  # type: ignore[attr-defined]
        writer.write(b"hello\r\n")
        await writer.drain()
        writer.close()


@pytest.fixture
async def managers() -> AsyncIterator[list[ListenerManager]]:
    started: list[ListenerManager] = []
    yield started
    for manager in started:
        await manager.close()


async def start(managers: list[ListenerManager], listener: ListenerConfig, handler: Recorder,
                tls: CertificateStore | None = None) -> ListenerManager:
    manager = ListenerManager([listener], handler, tls or CertificateStore([]))
    managers.append(manager)
    await manager.start()
    return manager


async def greeting(host: str, port: int, **kwargs: object) -> bytes:
    reader, writer = await asyncio.open_connection(host, port, **kwargs)  # type: ignore[arg-type]
    try:
        return await asyncio.wait_for(reader.readline(), 2)
    finally:
        writer.close()


@needs_ipv6
async def test_one_server_per_enabled_family(managers: list[ListenerManager]) -> None:
    handler = Recorder()
    manager = await start(managers, LISTENER, handler)
    addresses = manager.addresses()
    assert [(name, host) for name, host, _ in addresses] == [("inbound", "127.0.0.1"),
                                                             ("inbound", "::1")]
    for _, host, port in addresses:
        assert port != 0
        assert await greeting(host, port) == b"hello\r\n"
    assert handler.calls == [("inbound", READ_LIMIT, False)] * 2
    assert READ_LIMIT == 64 * 1024


async def test_disabled_family_is_not_bound(managers: list[ListenerManager]) -> None:
    manager = await start(managers, dataclasses.replace(LISTENER, ipv6=False), Recorder())
    assert [host for _, host, _ in manager.addresses()] == ["127.0.0.1"]


@needs_ipv6
async def test_ipv6_socket_does_not_accept_ipv4(managers: list[ListenerManager]) -> None:
    listener = dataclasses.replace(LISTENER, ipv4=False, bind6="::")
    manager = await start(managers, listener, Recorder())
    [(_, host, port)] = manager.addresses()
    assert host == "::"
    assert await greeting("::1", port) == b"hello\r\n"
    with pytest.raises(OSError):  # IPV6_V6ONLY: IPv4 clients never show up as ::ffff:a.b.c.d
        await greeting("127.0.0.1", port)


async def test_close_stops_accepting(managers: list[ListenerManager]) -> None:
    manager = await start(managers, dataclasses.replace(LISTENER, ipv6=False), Recorder())
    [(_, host, port)] = manager.addresses()
    await manager.close()
    assert manager.addresses() == []
    with pytest.raises(OSError):
        await greeting(host, port)
    await manager.close()  # idempotent


async def test_port_in_use_fails_start(managers: list[ListenerManager]) -> None:
    with socket.create_server(("127.0.0.1", 0)) as busy:
        port = busy.getsockname()[1]
        listener = dataclasses.replace(LISTENER, ipv6=False, port=port)
        with pytest.raises(OSError):
            await start(managers, listener, Recorder())


def accept_queue_limit(sock: socket.socket) -> int:
    """The accept-queue limit the kernel applies to a listening socket. For a socket in the
    LISTEN state Linux reports it in ``tcpi_sacked`` of ``TCP_INFO`` (offset 28)."""
    info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    return int.from_bytes(info[28:32], sys.byteorder)


async def test_listen_backlog_absorbs_connection_bursts(
        managers: list[ListenerManager]) -> None:
    # With asyncio's default backlog of 100, a burst of 500 connections overflowed the accept
    # queue: the kernel answered with SYN cookies and dropped what it could not queue, while
    # the clients saw open connections and waited for a greeting that never came.
    somaxconn = int(Path("/proc/sys/net/core/somaxconn").read_text())
    if somaxconn <= 100:
        pytest.skip(f"net.core.somaxconn is {somaxconn}")
    manager = await start(managers, dataclasses.replace(LISTENER, ipv6=False), Recorder())
    [(_, server)] = manager._servers
    [sock] = server.sockets
    assert accept_queue_limit(sock) == min(socket.SOMAXCONN, somaxconn)


@pytest.fixture
def cert_store(tmp_path: Path) -> CertificateStore:
    cert, key = make_cert(tmp_path, "proxy.test")
    return CertificateStore([CertificateConfig("main", ("proxy.test",), cert, key)])


SUBMISSIONS = dataclasses.replace(LISTENER, name="submissions", kind=ListenerKind.SUBMISSIONS,
                                  ipv6=False, auth=True)


class TlsRecorder(Recorder):
    """Handler that, like a session, starts TLS itself after a CONNECT phase of ``delay_s``."""

    def __init__(self, context: ssl.SSLContext, delay_s: float) -> None:
        super().__init__()
        self.context = context
        self.delay_s = delay_s
        self.buffered = -1

    async def __call__(self, listener: ListenerConfig, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
        tls = writer.get_extra_info("ssl_object") is not None
        self.calls.append((listener.name, reader._limit, tls))  # type: ignore[attr-defined]
        await asyncio.sleep(self.delay_s)  # the client's ClientHello arrives meanwhile
        self.buffered = len(reader._buffer)  # type: ignore[attr-defined]
        await writer.start_tls(self.context, ssl_handshake_timeout=2)
        writer.write(b"hello\r\n")
        await writer.drain()
        writer.close()


async def test_submissions_hands_over_plain_tcp_and_the_handler_starts_tls(
    managers: list[ListenerManager], cert_store: CertificateStore
) -> None:
    context = cert_store.front_context()
    assert context is not None
    handler = TlsRecorder(context, delay_s=0.2)
    manager = await start(managers, SUBMISSIONS, handler, cert_store)
    [(_, host, port)] = manager.addresses()
    assert await greeting(host, port, ssl=client_tls_context()) == b"hello\r\n"
    assert handler.calls == [("submissions", READ_LIMIT, False)]
    assert handler.buffered == 0  # the ClientHello was left to the TLS layer


async def test_submissions_handler_runs_before_any_handshake(
    managers: list[ListenerManager], cert_store: CertificateStore
) -> None:
    """The session's limits decide before a handshake starts (ruling R59)."""
    handler = Recorder()
    manager = await start(managers, SUBMISSIONS, handler, cert_store)
    [(_, host, port)] = manager.addresses()
    assert await greeting(host, port) == b"hello\r\n"  # a client that never says ClientHello
    assert handler.calls == [("submissions", READ_LIMIT, False)]


async def test_submissions_without_certificate_refuses_to_start(
    managers: list[ListenerManager]
) -> None:
    with pytest.raises(ConfigError, match="submissions"):
        await start(managers, SUBMISSIONS, Recorder())
