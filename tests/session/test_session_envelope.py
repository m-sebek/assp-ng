# SPDX-License-Identifier: GPL-3.0-or-later
"""Session part 2: STARTTLS, AUTH passthrough, MAIL, RCPT, relay decision, policy grouping."""

from __future__ import annotations

import base64
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from asspng.checks.base import CheckContext, CheckResult, Phase
from asspng.checks.limits import AuthLimitsCheck
from asspng.config.model import ListenerKind
from asspng.domains.index import DomainEntry, DomainIndex
from asspng.log.debug import RuleKind
from asspng.proxy.backend import BackendClosed
from asspng.smtp.replies import (
    R_AUTH_REQUIRED,
    R_AUTH_TEMPFAIL,
    R_BACKEND_LOST,
    R_BAD_ARG,
    R_BAD_SEQUENCE,
    R_BYE,
    R_DOMAINS_UNAVAILABLE,
    R_ENCRYPTION_REQUIRED,
    R_LINE_TOO_LONG,
    R_NOT_IMPL,
    R_POLICY_SPLIT,
    R_RELAY_DENIED,
    R_SIZE,
    R_SYNTAX,
    R_TEMPFAIL_CMD,
    R_TLS_ACTIVE,
    R_TLS_READY,
    R_TLS_UNAVAILABLE,
    R_TOO_MANY_ERRORS,
    R_TOO_MANY_RCPT,
    Reply,
)
from asspng.tls.store import CertificateStore
from tests.session.conftest import (
    HOSTNAME,
    PUBLIC_NET,
    PUBLIC_PEER,
    FakeBackend,
    Proxy,
    StartProxy,
    debug_file_text,
    record_debug_writes,
    tap_spy,
)
from tests.support.smtp_client import SmtpDialog, client_tls_context

USER = "alice@example.org"
SECRET = "Sup3r-S3cret!pw"
OK = Reply.of(250, "2.0.0 Ok")
EHLO = b"EHLO client.example"
OK_235 = Reply.of(235, "2.7.0 Authentication successful")
FAILED_535 = Reply.of(535, "5.7.8 Error: authentication failed")
ABORTED_501 = Reply.of(501, "5.7.0 Authentication aborted")
EMPTY_334 = Reply.of(334, "")
USERNAME_334 = Reply.of(334, "VXNlcm5hbWU6")
PASSWORD_334 = Reply.of(334, "UGFzc3dvcmQ6")
SUBMISSION: dict[str, object] = {"kind": ListenerKind.SUBMISSION, "auth": True}
SUBMISSIONS: dict[str, object] = {"kind": ListenerKind.SUBMISSIONS, "auth": True}


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def plain(password: str = SECRET) -> str:
    """An AUTH PLAIN response for ``USER``."""
    return b64(f"\0{USER}\0{password}")


def local(*domains: str) -> Callable[[], DomainIndex]:
    index = DomainIndex([DomainEntry(domain, False) for domain in domains])
    return lambda: index


def write_layer(etc_dir: Path, sub: str, name: str, text: str) -> None:
    (etc_dir / sub).mkdir(exist_ok=True)
    (etc_dir / sub / f"{name}.toml").write_text(text, encoding="utf-8")


def rcpt_lines(fake: FakeBackend) -> list[bytes]:
    return [line for line in fake.received if line.startswith(b"RCPT")]


class AuthBackend(FakeBackend):
    """``FakeBackend`` with a Postfix-like AUTH PLAIN/LOGIN dialogue for ``USER``/``SECRET``.

    ``auth_result`` replaces the final reply of every complete exchange (e.g. a 4xx).
    """

    def __init__(self, *, auth_result: Reply | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.auth_result = auth_result
        self._step: str | None = None
        self._login_user = b""

    async def command(self, line: bytes, timeout_s: float) -> Reply:
        if self._step is None and not line.upper().startswith(b"AUTH "):
            return await super().command(line, timeout_s)
        self.received.append(line)
        if line in self.errors:
            raise self.errors[line]
        return self._auth(line)

    def _auth(self, line: bytes) -> Reply:
        step, self._step = self._step, None
        if line == b"*":
            return ABORTED_501
        if step is None:
            _, mechanism, *initial = line.split()
            if mechanism.upper() == b"PLAIN":
                if initial:
                    return self._verify_plain(initial[0])
                self._step = "plain"
                return EMPTY_334
            if initial:
                self._login_user = initial[0]
                self._step = "password"
                return PASSWORD_334
            self._step = "username"
            return USERNAME_334
        if step == "plain":
            return self._verify_plain(line)
        if step == "username":
            self._login_user = line
            self._step = "password"
            return PASSWORD_334
        return self._verify(base64.b64decode(self._login_user), base64.b64decode(line))

    def _verify_plain(self, response: bytes) -> Reply:
        _, user, password = base64.b64decode(response).split(b"\0")
        return self._verify(user, password)

    def _verify(self, user: bytes, password: bytes) -> Reply:
        if self.auth_result is not None:
            return self.auth_result
        ok = (user, password) == (USER.encode(), SECRET.encode())
        return OK_235 if ok else FAILED_535


class UnreadableAuthLimits(AuthLimitsCheck):
    @staticmethod
    async def user_blocked(state: object, username: str, limit: int) -> bool:
        raise RuntimeError("state store unavailable")


class UnwritableAuthLimits(AuthLimitsCheck):
    @staticmethod
    async def record_failure(state: object, net: str, username: str | None, window_s: int
                             ) -> None:
        raise RuntimeError("state store unavailable")


@dataclass(frozen=True)
class Seen:
    phase: Phase
    mail_from: str
    rcpt: str
    messages_per_hour: object
    testmode: object


class Spy:
    """A MAIL/RCPT-phase check recording what checks see; rejects with ``reject[phase]``.

    It borrows the session_limits settings, like the HELO stub of the basic tests.
    """

    name = "session_limits"
    phases = frozenset({Phase.MAIL, Phase.RCPT})
    exempt: frozenset[str] = frozenset()

    def __init__(self, reject: dict[Phase, Reply] | None = None) -> None:
        self.reject = reject or {}
        self.seen: list[Seen] = []

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        txn = ctx.txn
        assert txn is not None
        self.seen.append(Seen(phase, str(txn.mail_from), str(txn.current_rcpt),
                              ctx.setting("limits.user.messages_per_hour"),
                              ctx.setting("testmode")))
        reply = self.reject.get(phase)
        return CheckResult(reply is not None, reason="spy", reply=reply)


async def greet(c: SmtpDialog) -> Reply:
    await c.expect_banner()
    reply = await c.send("EHLO client.example")
    assert reply.code == 250
    return reply


async def start_submissions(
    proxy_with: StartProxy, cert_store: CertificateStore, fake: FakeBackend, **kwargs: Any
) -> Proxy:
    """A submissions listener: implicit TLS, AUTH allowed."""
    return await proxy_with(fake, tls=cert_store, implicit_tls=True, listener=SUBMISSIONS,
                            **kwargs)


# --- STARTTLS ------------------------------------------------------------------------------


async def test_starttls_then_ehlo_again(proxy_with: StartProxy, cert_store: CertificateStore
                                        ) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, tls=cert_store)
    async with proxy.dialog() as c:
        assert "STARTTLS" in (await greet(c)).lines
        assert await c.send("STARTTLS") == R_TLS_READY
        await c.starttls(client_tls_context())
        assert await c.send("MAIL FROM:<a@remote.example>") == R_BAD_SEQUENCE  # HELO reset
        reply = await c.send("EHLO client.example")
        assert reply.lines[0] == HOSTNAME
        assert "STARTTLS" not in reply.lines
        assert await c.send("STARTTLS") == R_TLS_ACTIVE
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    assert fake.received == [EHLO, EHLO, b"MAIL FROM:<a@remote.example>", b"QUIT"]
    [record] = proxy.maillog
    assert record.tls.startswith("TLSv1.")
    assert record.helo == "client.example"


async def test_starttls_pipelined_plaintext_discarded(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, tls=cert_store, config={"limits.session.protocol_errors": 2})
    async with proxy.dialog() as c:
        await greet(c)
        await c.send_raw(b"STARTTLS\r\nRSET\r\n")
        assert await c.reply() == R_TLS_READY
        await c.starttls(client_tls_context())
        # The first reply over TLS answers EHLO: nothing answered the injected RSET.
        assert (await c.send("EHLO client.example")).lines[0] == HOSTNAME
        assert await c.send("FOO") == R_TOO_MANY_ERRORS  # the injection was error number one
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.received == [EHLO, EHLO]
    assert "discarded 6 bytes" in caplog.text
    assert "RSET" not in caplog.text


async def test_starttls_without_certificate_454(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, config={"limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        assert "STARTTLS" not in (await greet(c)).lines
        assert await c.send("STARTTLS") == R_TLS_UNAVAILABLE  # not a protocol error
        assert await c.send("NOOP") == OK
    assert fake.received == [EHLO, b"NOOP"]


async def test_starttls_with_argument_or_in_transaction_refused(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, tls=cert_store)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("STARTTLS now") == R_BAD_ARG
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("STARTTLS") == R_BAD_SEQUENCE
        assert await c.send("NOOP") == OK  # still the plaintext connection
    assert fake.received == [EHLO, b"MAIL FROM:<a@remote.example>", b"NOOP"]


@pytest.mark.parametrize("client", ["garbage", "silence", "close"])
async def test_starttls_handshake_failure_disconnects(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture,
    client: str,
) -> None:
    caplog.set_level(logging.INFO)
    fake = FakeBackend()
    proxy = await proxy_with(fake, tls=cert_store, config={"timeouts.tls_handshake": 0.3})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("STARTTLS") == R_TLS_READY
        if client == "garbage":
            await c.send_raw(b"EHLO not.tls.example\r\n" * 4)
        elif client == "close":
            c.writer.write_eof()
        await c.expect_closed()
    await proxy.wait_sessions(timeout=2.0)  # the broken connection is aborted, not awaited
    assert [r.result for r in proxy.maillog] == ["disconnected"]
    assert fake.closes == 1
    assert "TLS handshake failed" in caplog.text


async def test_implicit_tls_hides_starttls(proxy_with: StartProxy, cert_store: CertificateStore
                                           ) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake)
    async with proxy.dialog() as c:
        lines = (await greet(c)).lines
        assert "STARTTLS" not in lines
        assert "AUTH PLAIN LOGIN" in lines
        assert await c.send("STARTTLS") == R_TLS_ACTIVE
    await proxy.wait_sessions()
    assert fake.received == [EHLO]
    assert proxy.maillog[0].tls.startswith("TLSv1.")


# --- AUTH ----------------------------------------------------------------------------------


async def test_auth_before_tls_538(proxy_with: StartProxy, cert_store: CertificateStore) -> None:
    fake = AuthBackend()
    proxy = await proxy_with(fake, tls=cert_store, listener=SUBMISSION,
                             config={"limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        lines = (await greet(c)).lines
        assert "STARTTLS" in lines
        assert not any(line.startswith("AUTH") for line in lines)
        assert await c.send(f"AUTH PLAIN {plain()}") == R_ENCRYPTION_REQUIRED
        assert await c.send("NOOP") == OK  # not a protocol error
    assert fake.received == [EHLO, b"NOOP"]


async def test_auth_on_listener_without_auth_502(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    fake = AuthBackend()
    proxy = await proxy_with(fake, tls=cert_store, implicit_tls=True)  # smtp: auth = false
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain()}") == R_NOT_IMPL
    assert fake.received == [EHLO]


async def test_auth_plain_success_sets_user_and_allows_relay(
    proxy_with: StartProxy, cert_store: CertificateStore, etc_dir: Path
) -> None:
    write_layer(etc_dir, "user.d", USER, "limits.user.messages_per_hour = 7\n")
    spy = Spy()
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake, peer=PUBLIC_PEER,
                                    checks=[spy], domains=local("example.com"))
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain()}") == OK_235
        assert await c.send(f"AUTH PLAIN {plain()}") == R_BAD_SEQUENCE  # once per session
        assert await c.send(f"MAIL FROM:<{USER}>") == OK
        assert await c.send("RCPT TO:<bob@remote.example>") == OK
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    assert fake.received == [EHLO, f"AUTH PLAIN {plain()}".encode(), f"MAIL FROM:<{USER}>".encode(),
                             b"RCPT TO:<bob@remote.example>", b"QUIT"]
    assert [s.messages_per_hour for s in spy.seen] == [7, 7]  # the sender policy is loaded
    assert proxy.maillog[0].auth == USER
    assert (await proxy.box.status(PUBLIC_NET)).score == 0


async def test_auth_failure_counts(proxy_with: StartProxy, cert_store: CertificateStore) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake, peer=PUBLIC_PEER,
                                    config={"limits.auth.failures_per_user": 2})
    async with proxy.dialog() as c:
        await greet(c)
        for _ in range(2):
            assert await c.send(f"AUTH PLAIN {plain('wrong')}") == FAILED_535
        assert await c.send(f"AUTH PLAIN {plain()}") == R_AUTH_TEMPFAIL  # the user is blocked
    state = proxy.deps.state
    for key in (f"rl:authfail:net:{PUBLIC_NET}", f"rl:authfail:user:{USER}"):
        assert await state.get(key) == "2"
        ttl = await state.ttl(key)
        assert ttl is not None and 0 < ttl <= 900  # limits.auth.window, in seconds
    assert sum(line.startswith(b"AUTH") for line in fake.received) == 2


async def test_second_auth_after_tempfail_421_and_ip_score(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake, peer=PUBLIC_PEER, config={
        "limits.auth.failures_per_net": 1, "abuse.auth_failure_ip_score": 9,
        "checks.auth_limits.ip_score": 0})
    await proxy.deps.state.incr_window(f"rl:authfail:net:{PUBLIC_NET}", 900)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain()}") == R_AUTH_TEMPFAIL  # the AUTH phase
        assert await c.send(f"AUTH PLAIN {plain()}") == R_TOO_MANY_ERRORS
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.received == [EHLO]
    assert (await proxy.box.status(PUBLIC_NET)).score == 9
    assert [r.result for r in proxy.maillog] == ["rejected"]


async def test_auth_blocked_user_never_forwarded(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake,
                                    config={"limits.auth.failures_per_user": 1})
    await proxy.deps.state.incr_window(f"rl:authfail:user:{USER}", 900)
    async with proxy.dialog() as c:  # PLAIN with an initial response: nothing is forwarded
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain()}") == R_AUTH_TEMPFAIL
    async with proxy.dialog() as c:  # LOGIN: the open exchange is cancelled instead
        await greet(c)
        assert await c.send("AUTH LOGIN") == USERNAME_334
        assert await c.send(b64(USER)) == R_AUTH_TEMPFAIL
        assert await c.send("NOOP") == OK
    assert fake.received == [EHLO, EHLO, b"AUTH LOGIN", b"*", b"NOOP"]


async def test_auth_cancelled_with_star(proxy_with: StartProxy, cert_store: CertificateStore
                                        ) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake, peer=PUBLIC_PEER)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("AUTH LOGIN") == USERNAME_334
        assert await c.send("*") == ABORTED_501
        assert await c.send(f"AUTH PLAIN {plain()}") == OK_235
    assert fake.received == [EHLO, b"AUTH LOGIN", b"*", f"AUTH PLAIN {plain()}".encode()]
    assert await proxy.deps.state.get(f"rl:authfail:net:{PUBLIC_NET}") is None


async def test_auth_bad_base64_mid_exchange_cancels_backend(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake)
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("AUTH PLAIN") == EMPTY_334
        assert await c.send(f"not-base64:{SECRET}") == R_BAD_ARG
        assert await c.send("NOOP") == OK
    await proxy.wait_sessions()
    assert fake.received == [EHLO, b"AUTH PLAIN", b"*", b"NOOP"]
    assert "C>P <redacted>" in texts
    assert not any(SECRET in t for t in texts)
    assert SECRET not in caplog.text


@pytest.mark.parametrize("raw", [SECRET.encode() + b"\rX", b"\x1b" + SECRET.encode(),
                                 SECRET.encode() + b"\x00", SECRET.encode() + b"\x7f"],
                         ids=["cr", "esc", "nul", "del"])  # never the password in an id
async def test_auth_response_with_control_characters_501_locally(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture,
    raw: bytes
) -> None:
    """C1: a response the MTA must not get ends the exchange here (cancelled with "*")."""
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake)
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("AUTH LOGIN") == USERNAME_334
        assert await c.send(b64(USER)) == PASSWORD_334
        await c.send_raw(raw + b"\r\n")
        assert await c.reply() == R_BAD_ARG
        assert await c.send("NOOP") == OK
    await proxy.wait_sessions()
    assert fake.received == [EHLO, b"AUTH LOGIN", b64(USER).encode(), b"*", b"NOOP"]
    assert proxy.health.events == []  # no session_error
    assert not any(SECRET in t for t in texts)
    assert SECRET not in caplog.text


@pytest.mark.parametrize("line", [
    "AUTH CRAM-MD5", "AUTH PLAIN !!!", "AUTH LOGIN =", "AUTH", "AUTH PLAIN a b"])
async def test_auth_bad_mechanism_or_initial_response_501(
    proxy_with: StartProxy, cert_store: CertificateStore, line: str
) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(line) == R_BAD_ARG
    assert fake.received == [EHLO]


async def test_auth_mta_4xx_relayed_not_counted(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    busy = Reply.of(454, "4.3.0 Try again later")
    fake = AuthBackend(auth_result=busy)
    proxy = await start_submissions(proxy_with, cert_store, fake, peer=PUBLIC_PEER)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain()}") == busy
        assert await c.send(f"AUTH PLAIN {plain()}") == busy  # no R_TOO_MANY_ERRORS
    assert await proxy.deps.state.get(f"rl:authfail:net:{PUBLIC_NET}") is None


async def test_auth_backend_lost_during_exchange(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    fake = AuthBackend(errors={plain().encode(): BackendClosed("backend closed the connection")})
    proxy = await start_submissions(proxy_with, cert_store, fake)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("AUTH PLAIN") == EMPTY_334
        assert await c.send(plain()) == R_BACKEND_LOST
        await c.expect_closed()
    await proxy.wait_sessions()
    assert proxy.health.events == ["backend_lost"]
    assert [r.result for r in proxy.maillog] == ["tempfailed"]


async def test_auth_limit_state_failures(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture
) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake,
                                    auth_limits=UnwritableAuthLimits())
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain('wrong')}") == FAILED_535  # still relayed
    assert "cannot count the authentication failure: RuntimeError" in caplog.text
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake,
                                    auth_limits=UnreadableAuthLimits())
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain()}") == R_AUTH_TEMPFAIL  # fails closed
        assert await c.send(f"AUTH PLAIN {plain()}") == R_AUTH_TEMPFAIL  # no 421 (R32)
    assert fake.received == [EHLO]
    assert "cannot read the authentication failures: RuntimeError" in caplog.text


async def test_blocked_user_never_escalates_but_network_limit_does(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake, peer=PUBLIC_PEER, config={
        "limits.auth.failures_per_user": 1, "limits.auth.failures_per_net": 1,
        "abuse.auth_failure_ip_score": 9, "checks.auth_limits.ip_score": 0})
    state = proxy.deps.state
    await state.incr_window(f"rl:authfail:user:{USER}", 900)
    async with proxy.dialog() as c:  # someone elsewhere locked the account: no 421, no score
        await greet(c)
        for _ in range(2):
            assert await c.send(f"AUTH PLAIN {plain()}") == R_AUTH_TEMPFAIL
        assert await c.send("NOOP") == OK
    assert (await proxy.box.status(PUBLIC_NET)).score == 0
    await state.incr_window(f"rl:authfail:net:{PUBLIC_NET}", 900)
    async with proxy.dialog() as c:  # this network is over its limit: it escalates
        await greet(c)
        assert await c.send(f"AUTH PLAIN {plain()}") == R_AUTH_TEMPFAIL
        assert await c.send(f"AUTH PLAIN {plain()}") == R_TOO_MANY_ERRORS
        await c.expect_closed()
    await proxy.wait_sessions()
    assert (await proxy.box.status(PUBLIC_NET)).score == 9


async def test_pipelined_login_after_blocked_user_never_tapped(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake,
                                    config={"limits.auth.failures_per_user": 1})
    await proxy.deps.state.incr_window(f"rl:authfail:user:{USER}", 900)
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await greet(c)
        await c.send_raw(f"AUTH LOGIN\r\n{b64(USER)}\r\n{b64(SECRET)}\r\n".encode())
        assert await c.reply() == USERNAME_334
        assert await c.reply() == R_AUTH_TEMPFAIL
        assert await c.send("NOOP") == OK  # the pipelined password was dropped unanswered
    await proxy.wait_sessions()
    assert fake.received == [EHLO, b"AUTH LOGIN", b"*", b"NOOP"]
    debug_text = debug_file_text(proxy)
    for secret in (SECRET, b64(SECRET)):
        assert not any(secret in t for t in texts)
        assert secret not in debug_text
        assert secret not in caplog.text


async def test_pipelined_plain_after_auth_phase_refusal_never_logged(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = AuthBackend()
    # An smtp listener with AUTH (MAIL needs no AUTH there), TLS by STARTTLS.
    proxy = await proxy_with(fake, tls=cert_store, listener={"auth": True},
                             peer=PUBLIC_PEER, config={"limits.auth.failures_per_net": 1})
    await proxy.deps.state.incr_window(f"rl:authfail:net:{PUBLIC_NET}", 900)
    # No ALL rule: a FROM rule flushes the ring buffer at MAIL.
    proxy.deps.debug_rules.add(RuleKind.FROM, "x@remote.example", 600, False)
    texts = record_debug_writes(proxy)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("STARTTLS") == R_TLS_READY
        await c.starttls(client_tls_context())
        await c.send("EHLO client.example")
        await c.send_raw(f"AUTH PLAIN\r\n{plain()}\r\n".encode())
        assert await c.reply() == R_AUTH_TEMPFAIL
        assert await c.send("MAIL FROM:<x@remote.example>") == OK
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    assert "C>P MAIL FROM:<x@remote.example>" in texts  # the ring was flushed
    debug_text = debug_file_text(proxy)
    for secret in (SECRET, plain()):
        assert not any(secret in t for t in texts)
        assert secret not in debug_text
        assert secret not in caplog.text


@pytest.mark.parametrize("payload", [b64(SECRET), b64("AAAAAA")],
                         ids=["syntax-error", "unknown-verb"])
async def test_later_auth_payload_after_refusal_never_tapped(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture,
    payload: str,
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake,
                                    config={"limits.auth.failures_per_net": 1})
    await proxy.deps.state.incr_window("rl:authfail:net:127.0.0.1/32", 900)
    texts = tap_spy(proxy)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("AUTH PLAIN") == R_AUTH_TEMPFAIL
        assert (await c.send(payload)).code in (500, 502)  # a later segment: read as a command
        assert await c.send("NOOP") == OK
    await proxy.wait_sessions()
    assert f"C>P <unknown command: {len(payload)} bytes>" in texts
    debug_text = debug_file_text(proxy)
    assert not any(payload in t for t in texts)
    assert payload not in debug_text
    assert payload not in caplog.text


async def test_auth_over_long_line_cancels_exchange(
    proxy_with: StartProxy, cert_store: CertificateStore
) -> None:
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("AUTH LOGIN") == USERNAME_334
        assert await c.send(b"QUFB" * 1000) == R_LINE_TOO_LONG
        assert await c.send("NOOP") == OK
    assert fake.received == [EHLO, b"AUTH LOGIN", b"*", b"NOOP"]


async def test_password_never_in_debug_log(
    proxy_with: StartProxy, cert_store: CertificateStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = AuthBackend()
    proxy = await start_submissions(proxy_with, cert_store, fake)
    proxy.deps.debug_rules.add(RuleKind.ALL, "", 600, False)  # the real DebugLog writes all
    flows = [
        [(f"AUTH PLAIN {plain()}", OK_235)],
        [("AUTH PLAIN", EMPTY_334), (plain(), OK_235)],
        [("AUTH LOGIN", USERNAME_334), (b64(USER), PASSWORD_334), (b64(SECRET), OK_235)],
        [(f"AUTH LOGIN {b64(USER)}", PASSWORD_334), (b64(SECRET), OK_235)],
    ]
    for flow in flows:
        async with proxy.dialog() as c:
            await greet(c)
            for line, expected in flow:
                assert await c.send(line) == expected
            assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    assert [r.auth for r in proxy.maillog] == [USER] * len(flows)
    debug_text = debug_file_text(proxy)
    for logged in ("C>P AUTH PLAIN <redacted>", "P>M AUTH PLAIN <redacted>", "C>P <redacted>",
                   "P>M <redacted>", "C>P AUTH LOGIN <redacted>", "M>P 235"):
        assert logged in debug_text
    records = repr(proxy.maillog)
    for secret in (SECRET, b64(SECRET), plain()):
        assert secret not in debug_text
        assert secret not in caplog.text
        assert secret not in records


# --- MAIL ----------------------------------------------------------------------------------


@pytest.mark.parametrize("listener", [SUBMISSION, SUBMISSIONS], ids=["587", "465"])
async def test_submission_mail_without_auth_530(
    proxy_with: StartProxy, cert_store: CertificateStore, listener: dict[str, object]
) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, listener=listener, config={"limits.session.protocol_errors": 1},
                             tls=cert_store,
                             implicit_tls=listener["kind"] is ListenerKind.SUBMISSIONS)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@example.org>") == R_AUTH_REQUIRED
        assert await c.send("NOOP") == OK
    assert fake.received == [EHLO, b"NOOP"]


async def test_size_param_552(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, config={"max_message_size": 1000,
                                           "limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example> SIZE=1001") == R_SIZE
        assert await c.send("MAIL FROM:<a@remote.example> SIZE=1000 BODY=8BITMIME") == OK
    assert fake.received == [EHLO, b"MAIL FROM:<a@remote.example> SIZE=1000 BODY=8BITMIME"]


async def test_mail_auth_param_dropped(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await greet(c)
        line = "MAIL FROM:<a@remote.example> AUTH=<> size=10 SMTPUTF8 RET=HDRS ENVID=QQ314"
        assert await c.send(line) == OK
    assert fake.received == [
        EHLO, b"MAIL FROM:<a@remote.example> SIZE=10 SMTPUTF8 RET=HDRS ENVID=QQ314"]


@pytest.mark.parametrize("params", ["XFOO=1", "SIZE=abc", "SIZE", "SMTPUTF8=yes", "BODY"])
async def test_mail_unknown_or_malformed_param_rejected(proxy_with: StartProxy, params: str
                                                        ) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send(f"MAIL FROM:<a@remote.example> {params}") == R_BAD_ARG
    assert fake.received == [EHLO]


async def test_mail_sequence_and_syntax_errors(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert await c.send("MAIL FROM:<a@remote.example>") == R_BAD_SEQUENCE  # before EHLO
        assert (await c.send("EHLO client.example")).code == 250
        assert await c.send("RCPT TO:<b@example.com>") == R_BAD_SEQUENCE  # before MAIL
        assert await c.send("MAIL FROM:a b c<") == R_SYNTAX
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("MAIL FROM:<a@remote.example>") == R_BAD_SEQUENCE  # nested
    assert fake.received == [EHLO, b"MAIL FROM:<a@remote.example>"]


async def test_mail_rejected_by_mta_or_check_opens_no_transaction(proxy_with: StartProxy
                                                                  ) -> None:
    refused = Reply.of(550, "5.7.1 Sender refused")
    blocked = Reply.of(550, "5.7.1 Blocked by a check")
    fake = FakeBackend(replies={"MAIL": refused})
    spy = Spy(reject={Phase.MAIL: blocked})
    proxy = await proxy_with(fake, checks=[spy])
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<spam@remote.example>") == blocked
        spy.reject.clear()
        assert await c.send("MAIL FROM:<a@remote.example>") == refused
        assert await c.send("RCPT TO:<b@example.com>") == R_BAD_SEQUENCE
    assert fake.received == [EHLO, b"MAIL FROM:<a@remote.example>"]
    assert [s.mail_from for s in spy.seen] == ["spam@remote.example", "a@remote.example"]


async def test_mail_in_tempfail_mode_451_not_forwarded(proxy_with: StartProxy) -> None:
    """Spec 6.2: a session in progress gets 451 4.3.0 at its next MAIL in TEMPFAIL."""
    fake = FakeBackend()
    proxy = await proxy_with(fake)
    async with proxy.dialog() as c:
        await greet(c)
        proxy.deps.state.force_tempfail("test")
        assert await c.send("MAIL FROM:<a@remote.example>") == R_TEMPFAIL_CMD
        assert R_TEMPFAIL_CMD.encode() == b"451 4.3.0 Service temporarily unavailable\r\n"
        assert await c.send("RCPT TO:<b@example.com>") == R_TEMPFAIL_CMD
    assert fake.received == [EHLO]


# --- RCPT ----------------------------------------------------------------------------------


async def test_relay_denied_554_and_not_forwarded(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, domains=local("example.com"), config={
        "abuse.relay_denied_ip_score": 4, "abuse.protocol_error_ip_score": 10,
        "limits.session.protocol_errors": 2})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("RCPT TO:<bob@remote.example>") == R_RELAY_DENIED
        assert (await proxy.box.status(PUBLIC_NET)).score == 4
        assert await c.send("RCPT TO:<eve@remote.example>") == R_TOO_MANY_ERRORS  # error #2
        await c.expect_closed()
    await proxy.wait_sessions()
    assert rcpt_lines(fake) == []
    assert (await proxy.box.status(PUBLIC_NET)).score == 4 + 4 + 10


async def test_rcpt_in_tempfail_mode_451_not_forwarded(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, domains=local("example.com"))
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        proxy.deps.state.force_tempfail("test")
        assert await c.send("RCPT TO:<bob@example.com>") == R_TEMPFAIL_CMD
    assert rcpt_lines(fake) == []


async def test_local_domain_accepted_case_insensitive(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER,
                             domains=local("example.com", "xn--bcher-kva.example"))
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("RCPT TO:<Bob@EXAMPLE.Com>") == OK
        assert await c.send("RCPT TO:<anna@Bücher.Example.>") == OK
    assert rcpt_lines(fake) == [  # forwarded as the client sent them
        b"RCPT TO:<Bob@EXAMPLE.Com>", "RCPT TO:<anna@Bücher.Example.>".encode()]


async def test_trusted_network_may_relay(proxy_with: StartProxy, etc_dir: Path) -> None:
    (etc_dir / "trusted-networks.txt").write_text("1.2.3.0/24\n", encoding="utf-8")
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, domains=local("example.com"))
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@example.com>") == OK
        assert await c.send("RCPT TO:<bob@remote.example>") == OK
    assert rcpt_lines(fake) == [b"RCPT TO:<bob@remote.example>"]


async def test_domains_unavailable_451(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, domains=DomainIndex.unavailable,
                             config={"limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("RCPT TO:<bob@example.com>") == R_DOMAINS_UNAVAILABLE
        assert await c.send("RCPT TO:<postmaster>") == OK  # always local
    assert rcpt_lines(fake) == [b"RCPT TO:<postmaster>"]
    assert (await proxy.box.status(PUBLIC_NET)).score == 0


async def test_policy_split_452_not_forwarded(proxy_with: StartProxy, etc_dir: Path) -> None:
    write_layer(etc_dir, "domain.d", "b.example", "testmode = true\n")
    spy = Spy()
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, domains=local("a.example", "b.example"),
                             checks=[spy], config={"limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<x@remote.example>") == OK
        assert await c.send("RCPT TO:<ann@a.example>") == OK
        assert await c.send("RCPT TO:<bob@b.example>") == R_POLICY_SPLIT
        assert await c.send("RSET") == OK
        assert await c.send("MAIL FROM:<x@remote.example>") == OK
        assert await c.send("RCPT TO:<bob@b.example>") == OK  # its own transaction
    assert rcpt_lines(fake) == [b"RCPT TO:<ann@a.example>", b"RCPT TO:<bob@b.example>"]
    rcpt_checks = [(s.rcpt, s.testmode) for s in spy.seen if s.phase is Phase.RCPT]
    assert rcpt_checks == [("ann@a.example", False), ("bob@b.example", True)]


async def test_same_policy_stays_together(proxy_with: StartProxy, etc_dir: Path) -> None:
    write_layer(etc_dir, "domain.d", "c.example", "scoring.limit = 50\n")  # the default value
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, domains=local("a.example", "c.example"))
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<x@remote.example>") == OK
        for rcpt in ("ann@a.example", "al@a.example", "cy@c.example"):
            assert await c.send(f"RCPT TO:<{rcpt}>") == OK
    assert len(rcpt_lines(fake)) == 3


@pytest.mark.parametrize("refused_by", ["check", "mta"])
async def test_refused_recipient_does_not_fix_the_policy(
    proxy_with: StartProxy, etc_dir: Path, refused_by: str
) -> None:
    write_layer(etc_dir, "domain.d", "b.example", "testmode = true\n")
    refused = Reply.of(550, "5.1.1 User unknown")
    spy = Spy()
    fake = FakeBackend()
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, domains=local("a.example", "b.example"),
                             checks=[spy])
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<x@remote.example>") == OK
        if refused_by == "check":
            spy.reject[Phase.RCPT] = refused
        else:
            fake.replies["RCPT"] = refused
        assert await c.send("RCPT TO:<bob@a.example>") == refused  # the default policy
        spy.reject.clear()
        fake.replies.pop("RCPT", None)
        assert await c.send("RCPT TO:<ann@b.example>") == OK  # the first accepted one: no 452
    assert rcpt_lines(fake)[-1] == b"RCPT TO:<ann@b.example>"


@pytest.mark.parametrize("code", [550, 551, 553])
async def test_invalid_recipients_limit(proxy_with: StartProxy, code: int) -> None:
    unknown = Reply.of(code, "5.1.1 User unknown")
    fake = FakeBackend(replies={"RCPT": unknown})
    proxy = await proxy_with(fake, peer=PUBLIC_PEER, domains=local("example.com"), config={
        "limits.session.invalid_recipients": 2, "abuse.invalid_recipient_ip_score": 6})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("RCPT TO:<nobody@example.com>") == unknown
        assert await c.send("RCPT TO:<noone@example.com>") == R_TOO_MANY_ERRORS
        await c.expect_closed()
    await proxy.wait_sessions()
    assert (await proxy.box.status(PUBLIC_NET)).score == 6
    assert [r.result for r in proxy.maillog] == ["rejected"]


async def test_temporary_rcpt_failure_is_not_invalid(proxy_with: StartProxy) -> None:
    busy = Reply.of(450, "4.2.0 Mailbox busy")
    fake = FakeBackend(replies={"RCPT": busy})
    proxy = await proxy_with(fake, domains=local("example.com"),
                             config={"limits.session.invalid_recipients": 1})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        for rcpt in ("a@example.com", "b@example.com"):
            assert await c.send(f"RCPT TO:<{rcpt}>") == busy
        assert await c.send("NOOP") == OK


async def test_rcpt_limit_452_not_protocol_error(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, domains=local("example.com"), config={
        "limits.message.recipients": 2, "limits.session.protocol_errors": 1})
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        for rcpt in ("a", "b"):
            assert await c.send(f"RCPT TO:<{rcpt}@example.com>") == OK
        for rcpt in ("c", "d"):
            assert await c.send(f"RCPT TO:<{rcpt}@example.com>") == R_TOO_MANY_RCPT
        assert await c.send("NOOP") == OK
    assert len(rcpt_lines(fake)) == 2


async def test_rcpt_params_allow_list_and_syntax(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, domains=local("example.com"))
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        line = "RCPT TO:<a@example.com> notify=SUCCESS,FAILURE ORCPT=rfc822;a@example.com"
        assert await c.send(line) == OK
        assert await c.send("RCPT TO:<b@example.com> XFOO=1") == R_BAD_ARG
        assert await c.send("RCPT TO:<b@example.com") == R_SYNTAX
    assert rcpt_lines(fake) == [
        b"RCPT TO:<a@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a@example.com"]


async def test_rcpt_check_421_ends_the_session(proxy_with: StartProxy) -> None:
    gone = Reply.of(421, "4.7.0 Go away")
    fake = FakeBackend()
    spy = Spy(reject={Phase.RCPT: gone})
    proxy = await proxy_with(fake, checks=[spy], domains=local("example.com"))
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("RCPT TO:<bob@example.com>") == gone
        await c.expect_closed()
    await proxy.wait_sessions()
    assert rcpt_lines(fake) == []
    assert [r.result for r in proxy.maillog] == ["rejected"]


async def test_mail_check_421_ends_the_session(proxy_with: StartProxy) -> None:
    gone = Reply.of(421, "4.7.0 Go away")
    fake = FakeBackend()
    proxy = await proxy_with(fake, checks=[Spy(reject={Phase.MAIL: gone})])
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == gone
        await c.expect_closed()
    assert fake.received == [EHLO]


async def test_rcpt_rejected_by_check_not_forwarded(proxy_with: StartProxy) -> None:
    blocked = Reply.of(550, "5.7.1 Blocked by a check")
    fake = FakeBackend()
    spy = Spy(reject={Phase.RCPT: blocked})
    proxy = await proxy_with(fake, domains=local("example.com"), checks=[spy])
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("RCPT TO:<b@example.com>") == blocked
    assert rcpt_lines(fake) == []


async def test_envelope_debug_rules_activate_the_tap(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await proxy_with(fake, domains=local("example.com"))
    texts = record_debug_writes(proxy)
    rules = proxy.deps.debug_rules
    rule = rules.add(RuleKind.FROM, "a@remote.example", 600, False)
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<A@remote.example>") == OK
    await proxy.wait_sessions()
    assert "C>P EHLO client.example" in texts  # the ring was flushed
    rules.remove(rule.id)
    rules.add(RuleKind.RCPT, "bob@example.com", 600, False)
    texts.clear()
    async with proxy.dialog() as c:
        await greet(c)
        assert await c.send("MAIL FROM:<a@remote.example>") == OK
        assert await c.send("RCPT TO:<ann@example.com>") == OK
        assert texts == []
        assert await c.send("RCPT TO:<Bob@example.com>") == OK
        assert "C>P RCPT TO:<ann@example.com>" in texts
