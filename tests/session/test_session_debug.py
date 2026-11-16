# SPDX-License-Identifier: GPL-3.0-or-later
"""The session's debug events besides the SMTP dialogue (spec 8.11, ruling R68): connect, TLS,
DNS, check decisions (CHK) and the state mode (STATE)."""

from __future__ import annotations

import re

from asspng.smtp.replies import R_BYE, R_TLS_READY, R_TRY_LATER
from asspng.tls.store import CertificateStore
from tests.session.conftest import (
    PUBLIC_NET,
    PUBLIC_PEER,
    FakeBackend,
    FakeResolver,
    StartProxy,
    debug_file_text,
    tap_spy,
)
from tests.support.smtp_client import client_tls_context

MS = r"ms=\d+\.\d"


def index(texts: list[str], pattern: str) -> int:
    """Position of the first line matching ``pattern`` (a full match)."""
    for position, text in enumerate(texts):
        if re.fullmatch(pattern, text):
            return position
    raise AssertionError(f"no line matches {pattern!r} in {texts!r}")


async def test_session_events_in_order(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend())
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send("EHLO client.example")
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    positions = [
        index(texts, r"STATE mode=NORMAL"),
        index(texts, rf"CHK phase=CONNECT check=conn_limits outcome=pass score=0 ip_score=0 "
                     rf"{MS}"),
        index(texts, rf"DNS PTR 127\.0\.0\.1 name=client\.example {MS}"),
        index(texts, r"SES connect ip=127\.0\.0\.1 port=\d+ ptr=client\.example "
                     r"listener=inbound"),
        index(texts, r"P>C 220 proxy\.test ESMTP"),
    ]
    assert positions == sorted(positions)
    assert positions[0] == 0
    assert not any(t.startswith("SES TLS") for t in texts)  # no TLS in this session
    written = debug_file_text(proxy)
    assert " STATE mode=NORMAL\n" in written and " SES connect ip=127.0.0.1 " in written


async def test_refused_client_connect_line_without_ptr(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER)
    await proxy.box.block(PUBLIC_NET, 3600, "test block")
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        assert await c.reply() == R_TRY_LATER
    await proxy.wait_sessions()
    index(texts, rf"CHK phase=CONNECT check=penalty_box outcome=tempfail score=\d+ "
                 rf"ip_score=\d+ {MS} reason=.+")
    index(texts, r"SES connect ip=1\.2\.3\.4 port=40000 ptr=- listener=inbound")
    assert not any(t.startswith("DNS ") for t in texts)  # a refused client costs no lookup


async def test_ptr_failure_line(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend(), resolver=FakeResolver(error=OSError("no dns")))
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await c.expect_banner()
    await proxy.wait_sessions()
    index(texts, rf"DNS PTR 127\.0\.0\.1 failed: OSError {MS}")
    index(texts, r"SES connect ip=127\.0\.0\.1 port=\d+ ptr=\[TEMPUNAVAIL\] listener=inbound")


async def test_tls_line_after_starttls(proxy_with: StartProxy, cert_store: CertificateStore
                                       ) -> None:
    proxy = await proxy_with(FakeBackend(), tls=cert_store)
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send("EHLO client.example")
        assert await c.send("STARTTLS") == R_TLS_READY
        await c.starttls(client_tls_context())
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    tls = index(texts, r"SES TLS TLSv1\.[23] cipher=\S+")
    assert tls > index(texts, r"P>C 220 2\.0\.0 Ready to start TLS")


async def test_tls_line_after_the_implicit_handshake(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    proxy = await proxy_with(FakeBackend(), tls=cert_store, implicit_tls=True)
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await c.expect_banner()
    await proxy.wait_sessions()
    positions = [
        index(texts, r"CHK phase=CONNECT check=conn_limits outcome=pass .+"),
        index(texts, r"SES TLS TLSv1\.[23] cipher=\S+"),
        index(texts, r"DNS PTR .+"),
        index(texts, r"SES connect ip=127\.0\.0\.1 port=\d+ ptr=client\.example "
                     r"listener=inbound"),
    ]
    assert positions == sorted(positions)


async def test_state_mode_changes_while_tapped(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend())
    texts = tap_spy(proxy)
    state = proxy.deps.state
    async with proxy.dialog() as c:
        await c.expect_banner()
        state.force_tempfail("test outage")
        assert (await c.send("NOOP")).code == 250
    await proxy.wait_sessions()
    index(texts, r"STATE mode=TEMPFAIL \(was NORMAL\): test outage")
    count = len(texts)
    await state.probe()  # back to NORMAL after the session ended: nobody listens any more
    assert len(texts) == count
