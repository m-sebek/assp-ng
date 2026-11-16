# SPDX-License-Identifier: GPL-3.0-or-later
"""Session part 1: connection setup, basic commands, errors, logging and cleanup."""

from __future__ import annotations

import asyncio
import base64
import logging
from ipaddress import ip_address

import pytest

from asspng.checks.base import CheckContext, CheckResult, Phase
from asspng.log.debug import RuleKind
from asspng.proxy import session as session_module
from asspng.proxy.backend import BackendClosed, BackendError, XclientUnsupported
from asspng.proxy.session import Session
from asspng.smtp.replies import (
    R_BACKEND_DOWN,
    R_BACKEND_LOST,
    R_BAD_ARG,
    R_BYE,
    R_HELP,
    R_IDLE,
    R_INTERNAL,
    R_LINE_TOO_LONG,
    R_NOT_IMPL,
    R_SYNTAX,
    R_TEMPFAIL,
    R_TOO_MANY_CONN,
    R_TOO_MANY_ERRORS,
    R_TRY_LATER,
    R_VRFY,
    ReadTimeout,
    Reply,
)
from tests.session.conftest import (
    PUBLIC_NET,
    PUBLIC_PEER,
    FakeBackend,
    FakeHealth,
    FakeResolver,
    StartProxy,
    debug_file_text,
    record_debug_writes,
    tap_spy,
)

SECRET = "Sup3r-S3cret!pw"
SECRET_B64 = base64.b64encode(f"\0test\0{SECRET}".encode()).decode()


class HeloStub:
    """A HELO-phase check (it borrows the session_limits settings)."""

    name = "session_limits"
    phases = frozenset({Phase.HELO})
    exempt: frozenset[str] = frozenset()

    def __init__(self, result: CheckResult) -> None:
        self.result = result

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        return self.result if ctx.session.helo == "bad.example" else CheckResult(False)


# --- connection setup --------------------------------------------------------------------


async def test_banner_own_hostname(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend(), config={"banner.text": "ready"})
    async with proxy.dialog() as c:
        banner = await c.expect_banner()
    assert banner == Reply.of(220, "proxy.test ESMTP ready")


async def test_banner_without_text(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend())
    async with proxy.dialog() as c:
        assert await c.expect_banner() == Reply.of(220, "proxy.test ESMTP")


async def test_connect_reject_never_contacts_backend(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER)
    await proxy.box.block(PUBLIC_NET, 3600, "test block")
    async with proxy.dialog() as c:
        assert await c.reply() == R_TRY_LATER
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.events == []
    assert proxy.resolver.lookups == []
    assert [r.result for r in proxy.maillog] == ["rejected"]
    assert proxy.deps.connections.total == 0


async def test_conn_limit_counts_this_connection(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, config={"limits.net.concurrent": 1})
    async with proxy.dialog() as first:
        await first.expect_banner()
        async with proxy.dialog() as second:
            assert await second.reply() == R_TOO_MANY_CONN
            await second.expect_closed()
        await asyncio.wait_for(proxy.tasks[1], 2)
        assert fake.events.count("connect") == 1
        assert proxy.deps.connections.count(PUBLIC_NET) == 1


async def test_tempfail_mode_421_430(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    proxy.deps.state.force_tempfail("test")
    async with proxy.dialog() as c:
        assert await c.reply() == R_TEMPFAIL
        assert R_TEMPFAIL.encode() == b"421 4.3.0 Service temporarily unavailable\r\n"
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.events == []
    assert proxy.deps.connections.total == 0
    record = proxy.maillog[0]
    assert (record.result, record.mta) == ("tempfailed", "-")


async def test_memory_over_limit_421_430(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, memory_over_limit=lambda: True)
    async with proxy.dialog() as c:
        assert await c.reply() == R_TEMPFAIL
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.events == []
    assert [r.result for r in proxy.maillog] == ["tempfailed"]


async def test_instance_limit_421_432(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, config={"limits.instance.concurrent": 1})
    async with proxy.dialog() as first:
        await first.expect_banner()
        async with proxy.dialog() as second:
            assert await second.reply() == R_BACKEND_DOWN
            await second.expect_closed()
        await asyncio.wait_for(proxy.tasks[1], 2)
        assert fake.events.count("connect") == 1
        assert proxy.deps.connections.total == 1  # the refused session released nothing
        assert proxy.maillog[0].result == "tempfailed"


async def test_backend_down_421_432(proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
                                    ) -> None:
    fake = FakeBackend(connect_error=BackendError("connect failed: ConnectionRefusedError"))
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        reply = await c.reply()
        await c.expect_closed()
    assert reply == R_BACKEND_DOWN
    assert reply.encode() == b"421 4.3.2 Service temporarily unavailable\r\n"
    await proxy.wait_sessions()
    assert proxy.health.backend_results == [("inbound", False)]
    assert fake.closes == 1
    assert [r.result for r in proxy.maillog] == ["tempfailed"]
    assert "ConnectionRefusedError" in caplog.text


async def test_backend_banner_not_220_is_down(proxy_with: StartProxy) -> None:
    fake = FakeBackend(banner=Reply.of(554, "5.3.2 not now"))
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        assert await c.reply() == R_BACKEND_DOWN
        await c.expect_closed()
    await proxy.wait_sessions()
    assert "xclient" not in fake.events
    assert proxy.health.backend_results == [("inbound", False)]


async def test_xclient_sent_before_banner(proxy_with: StartProxy) -> None:
    gate = asyncio.Event()
    fake = FakeBackend(xclient_gate=gate)
    proxy = await proxy_with(fake, peer=PUBLIC_PEER)
    async with proxy.dialog() as c:
        with pytest.raises(ReadTimeout):
            await c.reply(timeout=0.2)  # no banner while XCLIENT is pending
        gate.set()
        await c.expect_banner()
    assert fake.events[:2] == ["connect", "xclient"]
    assert fake.xclient_calls == [
        (ip_address("1.2.3.4"), 40000, "client.example", "proxy.test")
    ]
    assert proxy.health.backend_results == [("inbound", True)]


async def test_xclient_unsupported_fails_closed(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend(xclient_error=XclientUnsupported("backend does not advertise XCLIENT"))
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        assert await c.reply() == R_BACKEND_DOWN
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.received == []
    assert fake.closes == 1
    assert proxy.health.backend_results == [("inbound", False)]
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors and "XCLIENT" in errors[0].getMessage()
    assert [r.result for r in proxy.maillog] == ["tempfailed"]


async def test_xclient_rejected_fails_closed(proxy_with: StartProxy) -> None:
    fake = FakeBackend(xclient_error=BackendError("XCLIENT rejected with 550"))
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        assert await c.reply() == R_BACKEND_DOWN
        await c.expect_closed()
    await proxy.wait_sessions()
    assert proxy.health.backend_results == [("inbound", False)]


async def test_xclient_disabled_not_sent(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, listener={"xclient": False})
    async with proxy.dialog() as c:
        await c.expect_banner()
    assert fake.events[:1] == ["connect"]
    assert "xclient" not in fake.events
    assert proxy.health.backend_results == [("inbound", True)]


async def test_ptr_failure_not_fatal(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, resolver=FakeResolver(error=RuntimeError("dns broke")))
    async with proxy.dialog() as c:
        await c.expect_banner()
    assert fake.xclient_calls[0][2] == "[TEMPUNAVAIL]"


async def test_ptr_lookup_runs_concurrently_with_backend_connect(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    resolver = FakeResolver("client.example", gate=fake.connected)
    fake.connect_gate = resolver.started  # each side waits until the other one has started
    proxy = await proxy_with(fake, resolver=resolver, config={"timeouts.ptr": 2})
    async with proxy.dialog() as c:
        await c.expect_banner(timeout=1.0)
    assert fake.xclient_calls[0][2] == "client.example"


# --- commands ----------------------------------------------------------------------------


async def test_ehlo_filtered(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        reply = await c.send("EHLO client.example")
    assert reply == Reply(250, (
        "proxy.test", "SIZE 10240000", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN", "SMTPUTF8"))
    assert fake.received == [b"EHLO client.example"]


async def test_helo_plain_250(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("HELO client.example") == Reply.of(250, "proxy.test")
    assert fake.received == [b"HELO client.example"]


async def test_helo_mta_error_relayed(proxy_with: StartProxy) -> None:
    fake = FakeBackend(replies={"HELO": Reply.of(550, "5.7.1 go away")})
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("HELO client.example") == Reply.of(550, "5.7.1 go away")


async def test_ehlo_without_argument_501(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("EHLO") == R_BAD_ARG
    assert fake.received == []


@pytest.mark.parametrize("outcome", ["reject", "tempfail"])
async def test_helo_rejected_not_forwarded_session_open(
    proxy_with: StartProxy, outcome: str
) -> None:
    bad = Reply.of(550, "5.7.1 Bad HELO") if outcome == "reject" else Reply.of(
        450, "4.7.1 Try HELO later")
    check = HeloStub(CheckResult(True, reason="bad helo", reply=bad,
                                 temporary=outcome == "tempfail"))
    fake = FakeBackend()
    proxy = await proxy_with(fake, checks=[check])
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("EHLO bad.example") == bad
        assert fake.received == []
        assert (await c.send("NOOP")).code == 250
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    assert [r.result for r in proxy.maillog] == ["rejected"]


async def test_helo_check_421_ends_the_session(proxy_with: StartProxy) -> None:
    gone = Reply.of(421, "4.7.0 Go away")
    check = HeloStub(CheckResult(True, reason="bad helo", reply=gone, temporary=True))
    fake = FakeBackend()
    proxy = await proxy_with(fake, checks=[check])
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("EHLO bad.example") == gone
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.received == []
    assert [r.result for r in proxy.maillog] == ["rejected"]


async def test_helo_accepted_after_rejection_clears_rejected(proxy_with: StartProxy) -> None:
    check = HeloStub(CheckResult(True, reason="bad helo", reply=Reply.of(550, "5.7.1 Bad")))
    proxy = await proxy_with(FakeBackend(), checks=[check])
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert (await c.send("EHLO bad.example")).code == 550
        assert (await c.send("EHLO good.example")).code == 250
        await c.send("QUIT")
    await proxy.wait_sessions()
    assert [r.result for r in proxy.maillog] == ["quit"]


async def test_vrfy_252_not_forwarded(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("VRFY bob") == R_VRFY
        assert await c.send("EXPN staff") == R_VRFY
        assert await c.send("HELP") == R_HELP
    assert fake.received == []


async def test_rset_and_noop_forwarded(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("RSET") == Reply.of(250, "2.0.0 Ok")
        assert await c.send("NOOP") == Reply.of(250, "2.0.0 Ok")
    assert fake.received == [b"RSET", b"NOOP"]


async def test_client_xclient_never_forwarded(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send("EHLO client.example")
        assert await c.send("XCLIENT ADDR=192.0.2.1 NAME=spoofed.example") == R_NOT_IMPL
        assert await c.send("xclient ADDR=192.0.2.1") == R_NOT_IMPL
    assert "XCLIENT" not in fake.received_text.upper()


@pytest.mark.parametrize("line", [
    "XFORWARD NAME=spoofed.example",
    "ETRN example.com",
    "TURN",
    "ATRN example.com",
    "BDAT 10 LAST",
    f"AUTH PLAIN {SECRET_B64}",  # the smtp listener does not allow AUTH
])
async def test_unhandled_verbs_502_not_forwarded(proxy_with: StartProxy, line: str) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send(line) == R_NOT_IMPL
    assert fake.received == []


async def test_unknown_command_502(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        reply = await c.send("FOO bar")
    assert reply == R_NOT_IMPL
    assert reply.encode() == b"502 5.5.1 Command not implemented\r\n"
    assert fake.received == []


@pytest.mark.parametrize("line", [b"!!!", b"", b"\xff\xfe NOOP", b"NO\x00OP"])
async def test_syntax_error_500(proxy_with: StartProxy, line: bytes) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send(line) == R_SYNTAX
    assert fake.received == []


async def test_too_many_errors_421_and_ip_score(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, config={
        "limits.session.protocol_errors": 3, "abuse.protocol_error_ip_score": 7})
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("FOO") == R_NOT_IMPL
        assert await c.send("!!!") == R_SYNTAX
        assert await c.send("BAR") == R_TOO_MANY_ERRORS
        await c.expect_closed()
    await proxy.wait_sessions()
    assert (await proxy.box.status(PUBLIC_NET)).score == 7
    assert [r.result for r in proxy.maillog] == ["rejected"]
    assert proxy.deps.connections.total == 0


async def test_too_many_errors_private_ip_not_scored(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend(), config={"limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("FOO") == R_TOO_MANY_ERRORS
        await c.expect_closed()
    await proxy.wait_sessions()
    assert (await proxy.box.status("127.0.0.1/32")).score == 0


async def test_over_long_line_never_logged(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    texts = tap_spy(proxy)
    line = b"NOOP " + b"X" * 3000 + b"OVERLONG-MARKER"
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send(line) == R_LINE_TOO_LONG
        assert await c.send("NOOP") == Reply.of(250, "2.0.0 Ok")
    await proxy.wait_sessions()
    assert f"C>P <line too long: {len(line)} bytes>" in texts
    assert fake.received == [b"NOOP"]
    assert not any("OVERLONG-MARKER" in t or "XXXX" in t for t in texts)
    assert "OVERLONG-MARKER" not in debug_file_text(proxy)
    assert "OVERLONG-MARKER" not in caplog.text


# --- relaying, redaction and the debug tap ------------------------------------------------


async def test_backend_reply_control_chars_relayed_without_them(proxy_with: StartProxy) -> None:
    fake = FakeBackend(replies={"NOOP": Reply.of(250, "2.0.0 Ok\rinjected\n250 fake\x00\x7fend")})
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send_raw(b"NOOP\r\n")
        assert await c.raw_line() == b"250 2.0.0 Ok injected 250 fake  end\r\n"
        assert await c.send("QUIT") == R_BYE  # nothing else was queued


async def test_ehlo_capability_control_chars_removed(proxy_with: StartProxy) -> None:
    fake = FakeBackend(replies={"EHLO": Reply(250, ("fake.mta", "DSN\rX", "8BITMIME\n"))})
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("EHLO client.example") == Reply(
            250, ("proxy.test", "DSN X", "8BITMIME "))


async def test_auth_secret_never_in_tap_or_logs(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    proxy = await proxy_with(FakeBackend())
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send(f"AUTH PLAIN {SECRET_B64}") == R_NOT_IMPL
        assert await c.send(f"auth login {SECRET_B64}") == R_NOT_IMPL
        await c.send("QUIT")
    await proxy.wait_sessions()
    assert "C>P AUTH PLAIN <redacted>" in texts
    assert "C>P auth login <redacted>" in texts
    debug_text = debug_file_text(proxy)
    for secret in (SECRET, SECRET_B64):
        assert not any(secret in t for t in texts)
        assert secret not in debug_text
        assert secret not in caplog.text


async def test_tap_records_all_directions(proxy_with: StartProxy) -> None:
    proxy = await proxy_with(FakeBackend())
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send("EHLO client.example")
        await c.send("QUIT")
    await proxy.wait_sessions()
    for expected in (
        "M>P 220 fake.mta ESMTP",
        "P>M EHLO proxy.test",
        "P>M XCLIENT ADDR=127.0.0.1 PORT=",
        "P>C 220 proxy.test ESMTP",
        "C>P EHLO client.example",
        "P>M EHLO client.example",
        "M>P 250-fake.mta",
        "P>C 250-proxy.test",
        "P>C 250 SMTPUTF8",
        "C>P QUIT",
        "M>P 221 2.0.0 Bye",
        "P>C 221 2.0.0 Bye",
    ):
        assert any(t.startswith(expected) for t in texts), expected


@pytest.mark.parametrize("peer,config", [
    (("1.2.3.4", 40000), {"network.ipv4_prefix": 24}),
    (("2001:db8:1:2::5", 40000), {"network.ipv6_prefix": 48}),
], ids=["ipv4", "ipv6"])
async def test_debug_ip_rule_matches_client_not_state_network(
    proxy_with: StartProxy, peer: tuple[str, int], config: dict[str, object]
) -> None:
    proxy = await proxy_with(FakeBackend(), peer=peer, config=config)
    proxy.deps.debug_rules.add(RuleKind.IP, peer[0], 600, False)
    texts = record_debug_writes(proxy)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send("NOOP")
    await proxy.wait_sessions()
    assert "C>P NOOP" in texts


# --- session end, errors and cleanup -------------------------------------------------------


async def test_idle_timeout(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, config={"timeouts.command": 0.2})
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.reply(timeout=2) == R_IDLE
        await c.expect_closed()
    await proxy.wait_sessions()
    assert [r.result for r in proxy.maillog] == ["timeout"]
    assert fake.closes == 1


async def test_quit(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER)
    async with proxy.dialog() as c:
        await c.expect_banner()
        await c.send("EHLO client.example")
        assert await c.send("QUIT") == R_BYE
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.received == [b"EHLO client.example", b"QUIT"]
    assert fake.closes == 1
    [record] = proxy.maillog
    assert len(record.session) == 8 and int(record.session, 16) >= 0
    assert (record.txn, record.size, record.score) == (None, None, None)
    assert (record.listener, record.ip, record.ptr, record.helo) == (
        "inbound", "1.2.3.4", "client.example", "client.example")
    assert (record.mail_from, record.rcpts, record.auth, record.tls) == ("", [], "", "")
    assert (record.result, record.mta, record.instance) == ("quit", "221 2.0.0 Bye", "test")
    assert record.duration_s >= 0


async def test_backend_lost_421_442(proxy_with: StartProxy) -> None:
    fake = FakeBackend(errors={b"NOOP": BackendClosed("backend closed the connection")})
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("NOOP") == R_BACKEND_LOST
        await c.expect_closed()
    await proxy.wait_sessions()
    assert proxy.health.events == ["backend_lost"]
    assert [r.result for r in proxy.maillog] == ["tempfailed"]
    assert fake.closes == 1


async def test_quit_with_lost_backend_still_says_bye(proxy_with: StartProxy) -> None:
    fake = FakeBackend(errors={b"QUIT": BackendClosed("backend closed the connection")})
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("QUIT") == R_BYE
        await c.expect_closed()
    await proxy.wait_sessions()
    assert [r.result for r in proxy.maillog] == ["quit"]


async def test_session_exception_421_others_unaffected(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend(errors={b"EHLO boom.example": RuntimeError("boom")})
    proxy = await proxy_with(fake)
    async with proxy.dialog() as healthy:
        await healthy.expect_banner()
        assert (await healthy.send("EHLO ok.example")).code == 250
        async with proxy.dialog() as broken:
            await broken.expect_banner()
            assert await broken.send("EHLO boom.example") == R_INTERNAL
            await broken.expect_closed()
        await asyncio.wait_for(proxy.tasks[1], 2)
        assert await healthy.send("NOOP") == Reply.of(250, "2.0.0 Ok")
        assert proxy.deps.connections.total == 1
    assert proxy.health.events == ["session_error"]
    assert [r.result for r in proxy.maillog] == ["error"]
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors and errors[0].exc_info is not None


@pytest.mark.parametrize("scenario,result", [
    ("quit", "quit"),
    ("disconnect", "disconnected"),
    ("timeout", "timeout"),
    ("exception", "error"),
    ("backend_lost", "tempfailed"),
    ("too_many_errors", "rejected"),
])
async def test_slot_released_and_session_record_on_exit(
    proxy_with: StartProxy, scenario: str, result: str
) -> None:
    errors: dict[bytes, BaseException] = {
        b"NOOP": RuntimeError("boom") if scenario == "exception" else BackendClosed("gone")}
    fake = FakeBackend(errors=errors if scenario in ("exception", "backend_lost") else None)
    proxy = await proxy_with(fake, config={
        "timeouts.command": 0.3 if scenario == "timeout" else 5,
        "limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert proxy.deps.connections.total == 1
        if scenario == "quit":
            assert await c.send("QUIT") == R_BYE
        elif scenario == "timeout":
            assert await c.reply() == R_IDLE
        elif scenario == "exception":
            assert await c.send("NOOP") == R_INTERNAL
        elif scenario == "backend_lost":
            assert await c.send("NOOP") == R_BACKEND_LOST
        elif scenario == "too_many_errors":
            assert await c.send("FOO") == R_TOO_MANY_ERRORS
        if scenario != "disconnect":
            await c.expect_closed()
    await proxy.wait_sessions()
    assert proxy.deps.connections.total == 0
    assert fake.closes == 1
    assert [r.result for r in proxy.maillog] == [result]


async def test_slot_released_on_cancel(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        task = proxy.tasks[0]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()
        await c.expect_closed()
    assert proxy.deps.connections.total == 0
    assert fake.closes == 1
    assert [r.result for r in proxy.maillog] == ["disconnected"]


# --- failure paths of the session itself ----------------------------------------------------


class GoneWriter:
    """A StreamWriter stand-in whose client is gone: drain fails and close never finishes."""

    def __init__(self, tls_version: str | None = None) -> None:
        self.written: list[bytes] = []
        self.aborted = False
        self.transport = self
        self._tls_version = tls_version

    def get_extra_info(self, name: str, default: object = None) -> object:
        if name == "ssl_object" and self._tls_version is not None:
            return self
        return default

    def version(self) -> str | None:
        return self._tls_version

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        raise ConnectionResetError("connection reset by peer")

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        await asyncio.Event().wait()

    def abort(self) -> None:
        self.aborted = True


async def test_client_gone_while_writing_is_disconnected(
    proxy_with: StartProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "_CLOSE_TIMEOUT_S", 0.05)
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    reader = asyncio.StreamReader()
    reader.feed_eof()
    writer = GoneWriter(tls_version="TLSv1.3")
    await Session(proxy.deps, reader, writer, PUBLIC_PEER).run()  # type: ignore[arg-type]
    assert writer.written == [b"220 proxy.test ESMTP\r\n"]
    assert writer.aborted  # the bounded close timed out
    assert proxy.deps.connections.total == 0
    assert fake.closes == 1
    [record] = proxy.maillog
    assert (record.result, record.tls) == ("disconnected", "TLSv1.3")


async def test_backend_connect_bug_is_internal_error(proxy_with: StartProxy) -> None:
    fake = FakeBackend(connect_error=RuntimeError("bug"))
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        assert await c.reply() == R_INTERNAL
        await c.expect_closed()
    await proxy.wait_sessions()
    assert proxy.health.events == ["session_error"]
    assert proxy.health.backend_results == []
    assert [r.result for r in proxy.maillog] == ["error"]
    assert fake.closes == 1


async def test_too_many_errors_state_unavailable_still_closes(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    proxy = await proxy_with(FakeBackend(), peer=PUBLIC_PEER,
                             config={"limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        await c.expect_banner()
        proxy.deps.state.force_tempfail("test")
        assert await c.send("FOO") == R_TOO_MANY_ERRORS
        await c.expect_closed()
    await proxy.wait_sessions()
    assert "cannot add IP score: StateError" in caplog.text
    assert [r.result for r in proxy.maillog] == ["rejected"]


class FailingHealth(FakeHealth):
    def record(self, event: str) -> None:
        raise RuntimeError("health broke")


def failing_maillog(record: object) -> None:
    raise RuntimeError("maillog broke")


async def test_cleanup_survives_failing_collaborators(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend(errors={b"NOOP": RuntimeError("boom")},
                       close_error=RuntimeError("close broke"))
    proxy = await proxy_with(fake, health=FailingHealth(), maillog=failing_maillog)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("NOOP") == R_INTERNAL
        await c.expect_closed()
    await proxy.wait_sessions()
    assert proxy.deps.connections.total == 0
    assert all(task.exception() is None for task in proxy.tasks)
    for message in ("cannot count the error", "cannot write the session record",
                    "closing the backend failed"):
        assert message in caplog.text
