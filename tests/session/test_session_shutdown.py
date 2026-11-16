# SPDX-License-Identifier: GPL-3.0-or-later
"""Session behaviour when the service stops: ``notify_shutdown`` and then a cancellation."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

import pytest

from asspng.domains.index import DomainEntry, DomainIndex
from asspng.proxy import session as session_module
from asspng.proxy.session import Session
from asspng.smtp.replies import R_DATA_GO, R_TEMPFAIL
from tests.session.conftest import PUBLIC_PEER, FakeBackend, Proxy, StartProxy

LOCAL = DomainIndex([DomainEntry("example.com", False)])


async def wait_until(condition: Callable[[], bool], timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached in time"
        await asyncio.sleep(0.005)


async def stop_session(proxy: Proxy, index: int = 0) -> None:
    """What the application does to a session left over at shutdown."""
    session, task = proxy.sessions[index], proxy.tasks[index]
    session.notify_shutdown()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_idle_session_hears_421_on_shutdown(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert (await c.send("EHLO client.example")).code == 250
        await wait_until(lambda: proxy.sessions[0].idle)
        await stop_session(proxy)
        assert await c.reply() == R_TEMPFAIL
        await c.expect_closed()
    assert proxy.deps.connections.total == 0
    assert fake.closes == 1
    assert [r.result for r in proxy.maillog] == ["shutdown"]


async def test_idle_again_after_each_reply(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend())
    async with proxy.dialog() as c:
        await c.expect_banner()
        session = proxy.sessions[0]
        for command in ("EHLO client.example", "NOOP", "MAIL FROM:<a@example.org>", "RSET"):
            await wait_until(lambda: session.idle)
            assert (await c.send(command)).code == 250
        await wait_until(lambda: session.idle)


async def test_session_in_data_is_closed_without_reply(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, domains=lambda: LOCAL)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send("EHLO client.example")
        await c.send("MAIL FROM:<a@example.org>")
        assert (await c.send("RCPT TO:<b@example.com>")).code == 250
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(b"Subject: half\r\n\r\npart of the body\r\n")
        await asyncio.sleep(0.05)
        assert not proxy.sessions[0].idle
        await stop_session(proxy)
        await c.expect_closed()  # nothing written mid-DATA: it would corrupt the protocol
    assert fake.messages == []
    assert [r.result for r in proxy.maillog] == ["shutdown"]


async def test_session_before_banner_gets_no_421(proxy_with: StartProxy) -> None:
    gate = asyncio.Event()
    fake = FakeBackend(connect_gate=gate)
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await fake.connected.wait()
        await stop_session(proxy)
        await c.expect_closed()
    assert [r.result for r in proxy.maillog] == ["shutdown"]


async def test_cancel_without_shutdown_notice_writes_nothing(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend())
    async with proxy.dialog() as c:
        await c.expect_banner()
        await wait_until(lambda: proxy.sessions[0].idle)
        proxy.tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await proxy.tasks[0]
        await c.expect_closed()
    assert [r.result for r in proxy.maillog] == ["disconnected"]


async def test_notified_session_that_ends_normally_keeps_its_result(
    proxy_with: StartProxy
) -> None:
    proxy = await proxy_with(FakeBackend())
    async with proxy.dialog() as c:
        await c.expect_banner()
        proxy.sessions[0].notify_shutdown()
        assert (await c.send("QUIT")).code == 221
        await c.expect_closed()
    await proxy.wait_sessions()
    assert [r.result for r in proxy.maillog] == ["quit"]


class StallingWriter:
    """A StreamWriter stand-in whose client stops reading once ``stall`` is set."""

    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.stall = False
        self.aborted = False
        self.transport = self

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        if self.stall:
            await asyncio.Event().wait()

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        await asyncio.Event().wait()

    def abort(self) -> None:
        self.aborted = True


async def test_shutdown_reply_is_bounded(
    proxy_with: StartProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "_SHUTDOWN_REPLY_TIMEOUT_S", 0.05)
    proxy = await proxy_with(FakeBackend())
    writer = StallingWriter()
    session = Session(proxy.deps, asyncio.StreamReader(), writer,  # type: ignore[arg-type]
                      PUBLIC_PEER)
    task = asyncio.create_task(session.run())
    await wait_until(lambda: session.idle)
    writer.stall = True
    session.notify_shutdown()
    task.cancel()
    started = time.monotonic()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - started < 1.0
    assert writer.written[-1] == R_TEMPFAIL.encode()
    assert writer.aborted  # the client did not take the reply: the connection is aborted
    assert [r.result for r in proxy.maillog] == ["shutdown"]
