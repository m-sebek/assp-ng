# SPDX-License-Identifier: GPL-3.0-or-later
"""Implicit TLS (``submissions``, spec 4.2): the session starts TLS after its limits admitted
the client, so the limits also bound the pending handshakes (ruling R59)."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from asspng.checks.base import NEUTRAL, CheckContext, CheckResult, Phase
from asspng.config.model import ListenerKind
from asspng.smtp.replies import R_BYE
from asspng.tls.store import CertificateStore
from tests.session.conftest import PUBLIC_PEER, FakeBackend, StartProxy

LONG_HANDSHAKE = {"timeouts.tls_handshake": 30}


async def read_until_closed(host: str, port: int, *, send: bytes = b"", eof: bool = False
                            ) -> tuple[bytes, float]:
    """Connect without TLS, optionally send ``send`` (and EOF), and read until the server
    closes; return what was read and how long that took."""
    started = time.monotonic()
    reader, writer = await asyncio.open_connection(host, port)
    try:
        if send:
            writer.write(send)
            await writer.drain()
        if eof:
            writer.write_eof()
        try:
            data = await asyncio.wait_for(reader.read(), 5)
        except ConnectionResetError:
            data = b""
    finally:
        writer.close()
    return data, time.monotonic() - started


@pytest.mark.parametrize("limit", ["memory", "instance", "network"])
async def test_limits_apply_before_the_handshake(
    proxy_with: StartProxy, cert_store: CertificateStore, limit: str
) -> None:
    """A refused client never gets a handshake: the connection closes at once, without a
    plaintext reply the TLS client could not read anyway."""
    fake = FakeBackend()
    kwargs: dict[str, Any] = {
        "memory": {"memory_over_limit": lambda: True},
        "instance": {"config": {**LONG_HANDSHAKE, "limits.instance.concurrent": 0}},
        "network": {"config": {**LONG_HANDSHAKE, "limits.net.concurrent": 0},
                    "peer": PUBLIC_PEER},
    }[limit]
    kwargs.setdefault("config", LONG_HANDSHAKE)
    proxy = await proxy_with(fake, tls=cert_store, implicit_tls=True, **kwargs)
    data, elapsed = await read_until_closed(proxy.host, proxy.port)  # never says ClientHello
    await proxy.wait_sessions()
    assert data == b""
    assert elapsed < 3
    assert fake.events == []
    assert proxy.deps.connections.total == 0
    [record] = proxy.maillog
    assert record.result in ("tempfailed", "rejected")
    assert record.tls == ""


@pytest.mark.parametrize("client", ["silence", "garbage", "close"])
async def test_handshake_failure_or_timeout_disconnects(
    proxy_with: StartProxy, cert_store: CertificateStore, client: str
) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, tls=cert_store, implicit_tls=True,
                             config={"timeouts.tls_handshake": 0.3})
    data, elapsed = await read_until_closed(
        proxy.host, proxy.port, send=b"EHLO not.tls.example\r\n" * 4 if client == "garbage"
        else b"", eof=client == "close")
    await proxy.wait_sessions()
    assert b"220" not in data  # at most a TLS alert, never a plaintext banner
    assert elapsed < 3
    assert fake.events == []  # the backend is contacted only after the handshake
    assert proxy.deps.connections.total == 0
    assert [r.result for r in proxy.maillog] == ["disconnected"]


class SlowConnect:
    """A CONNECT-phase check that takes a while (it borrows the conn_limits settings)."""

    name = "conn_limits"
    phases = frozenset({Phase.CONNECT})
    exempt: frozenset[str] = frozenset()

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        await asyncio.sleep(0.3)
        return NEUTRAL


async def test_client_hello_during_the_connect_phase_reaches_tls(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    """The client's ClientHello arrives while the CONNECT checks run: it must reach the TLS
    layer, not the plaintext reader."""
    fake = FakeBackend()
    proxy = await proxy_with(fake, tls=cert_store, implicit_tls=True, checks=[SlowConnect()],
                             config={"timeouts.tls_handshake": 2})
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert (await c.send("EHLO client.example")).code == 250
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    [record] = proxy.maillog
    assert (record.result, record.tls.startswith("TLSv1.")) == ("quit", True)
    assert proxy.deps.listener.kind is ListenerKind.SUBMISSIONS
