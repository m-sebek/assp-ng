# SPDX-License-Identifier: GPL-3.0-or-later
"""Session part 3: DATA with buffering, checks, header fields, delivery and cleanup."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
import struct
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

from asspng.checks.base import CheckContext, CheckResult, Phase
from asspng.checks.engine import R_REJECT
from asspng.checks.engine import R_TEMPFAIL as R_CHECK_TEMPFAIL
from asspng.domains.index import DomainEntry, DomainIndex
from asspng.log.debug import RuleKind
from asspng.log.maillog import format_maillog
from asspng.proxy import session_data
from asspng.proxy.backend import BackendClosed
from asspng.proxy.buffer import MessageBuffer
from asspng.smtp.replies import (
    R_BACKEND_LOST,
    R_BAD_ARG,
    R_BAD_SEQUENCE,
    R_BYE,
    R_DATA_GO,
    R_IDLE,
    R_NO_RCPT,
    R_SIZE,
    R_TEMPFAIL,
    R_TEMPFAIL_CMD,
    R_TOO_MANY_ERRORS,
    R_TOO_MANY_MSG,
    Reply,
)
from tests.session.conftest import (
    PUBLIC_NET,
    PUBLIC_PEER,
    FakeBackend,
    FakeHealth,
    Proxy,
    StartProxy,
    debug_file_text,
    record_debug_writes,
)
from tests.support.smtp_client import SmtpDialog

OK = Reply.of(250, "2.0.0 Ok")
QUEUED = Reply.of(250, "2.0.0 Ok: queued as FAKE1")
SENDER = "alice@remote.example"
HEADER = b"From: alice@remote.example\r\nTo: bob@example.com\r\nSubject: Hello\r\n"
BODY = b"Hello Bob,\r\n\r\nsee you.\r\n"
MESSAGE = HEADER + b"\r\n" + BODY
SCORE_MODE = {"checks.session_limits.mode": "score"}
_ID_FIELD = re.compile(rb"X-ASSP-NG-ID: test-([0-9a-f]{8})-(\d+)\r\n")


class ContentCheck:
    """A HEADER/BODY-phase check that records the buffered message it sees and hits with
    ``result`` in ``phase``. It borrows the session_limits settings."""

    name = "session_limits"
    phases = frozenset({Phase.HEADER, Phase.BODY})
    exempt: frozenset[str] = frozenset()

    def __init__(self, result: CheckResult | None = None, phase: Phase = Phase.HEADER) -> None:
        self.result = result
        self.phase = phase
        self.seen: list[tuple[Phase, bytes]] = []

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult:
        assert ctx.txn is not None and ctx.txn.message is not None
        self.seen.append((phase, ctx.txn.message.read_head(1 << 20)))
        if self.result is None or phase is not self.phase:
            return CheckResult(False)
        return self.result


class SpoolWatchingBackend(FakeBackend):
    """Records the spool directory's files at the moment the message is delivered."""

    def __init__(self, spool: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.spool = spool
        self.spooled: list[Path] = []

    async def data(
        self, chunks: Iterable[bytes], timeout_354_s: float, timeout_final_s: float
    ) -> Reply:
        self.spooled = list(self.spool.iterdir())
        return await super().data(chunks, timeout_354_s, timeout_final_s)


def local_domains() -> Callable[[], DomainIndex]:
    index = DomainIndex([DomainEntry("example.com", False)])
    return lambda: index


async def start(proxy_with: StartProxy, fake: FakeBackend, **kwargs: Any) -> Proxy:
    """A proxy for which example.com is local."""
    return await proxy_with(fake, domains=local_domains(), **kwargs)


async def open_transaction(
    c: SmtpDialog, *rcpts: str, sender: str = SENDER, greet: bool = True
) -> None:
    if greet:
        await c.expect_banner()
        assert (await c.send("EHLO client.example")).code == 250
    assert await c.send(f"MAIL FROM:<{sender}>") == OK
    for rcpt in rcpts or ("bob@example.com",):
        assert await c.send(f"RCPT TO:<{rcpt}>") == OK


async def send_message(c: SmtpDialog, wire: bytes = MESSAGE) -> Reply:
    """DATA, then ``wire`` (dot-stuffed, ending with CRLF) and the end of data."""
    assert await c.send("DATA") == R_DATA_GO
    await c.send_raw(wire + b".\r\n")
    return await c.reply()


def split_id(message: bytes) -> tuple[str, int, bytes]:
    """The session id and transaction number of the leading ID field, and the rest."""
    match = _ID_FIELD.match(message)
    assert match is not None, message[:200]
    return match.group(1).decode(), int(match.group(2)), message[match.end():]


def spool_files(proxy: Proxy) -> list[Path]:
    return list(Path(str(proxy.deps.config.get("paths.spool"))).iterdir())


def write_default(etc_dir: Path, text: str) -> None:
    (etc_dir / "default.toml").write_text(text, encoding="utf-8")


def lines(count: int, width: int = 98) -> bytes:
    return (b"x" * width + b"\r\n") * count


def padded_header(length: int) -> bytes:
    """Header fields of exactly ``length`` bytes."""
    full, rest = divmod(length, 1000)
    assert rest >= 9, "the last field needs room for its name"
    field = b"X-Pad: " + b"a" * 991 + b"\r\n"
    return field * full + b"X-Pad: " + b"a" * (rest - 9) + b"\r\n"


async def wait_until(condition: Callable[[], bool], timeout: float = 2.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


# --- delivery ------------------------------------------------------------------------------


async def test_message_delivered_with_id_header(proxy_with: StartProxy) -> None:
    check = ContentCheck()
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check])
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, MESSAGE + b"..leading dot\r\n") == QUEUED
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    [message] = fake.messages
    session_id, number, rest = split_id(message)
    assert (session_id, number) == (proxy.maillog[0].session, 1)
    assert rest == MESSAGE + b"..leading dot\r\n.\r\n"  # stuffed again for the MTA
    assert fake.received[-2:] == [b"DATA", b"QUIT"]
    # The checks see the decoded message in both phases.
    assert [phase for phase, _ in check.seen] == [Phase.HEADER, Phase.BODY]
    assert {seen for _, seen in check.seen} == {MESSAGE + b".leading dot\r\n"}
    assert proxy.health.events == ["accepted"]


async def test_incoming_assp_headers_stripped(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    spoofed = (b"X-ASSP-NG-Score: -100 (whitelist=-100)\r\n"
               b"From: alice@remote.example\r\n"
               b"x-assp-ng-id: forged\r\n"
               b"X-Assp-Ng-Test: would reject:\r\n\tfolded continuation\r\n"
               b"Subject: Hello\r\n"
               b"\r\n"
               b"X-ASSP-NG-Score: a body line stays\r\n")
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, spoofed) == QUEUED
    [message] = fake.messages
    assert split_id(message)[2] == (b"From: alice@remote.example\r\nSubject: Hello\r\n\r\n"
                                    b"X-ASSP-NG-Score: a body line stays\r\n.\r\n")


@pytest.mark.parametrize("score", [0, 10])
async def test_leading_continuations_never_fold_onto_own_fields(proxy_with: StartProxy,
                                                                score: int) -> None:
    result = CheckResult(True, msg_score=score, reason="suspicious") if score else None
    check = ContentCheck(result)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check], config=SCORE_MODE)
    forged = b" forged\r\n\tX-ASSP-NG-Score: -100\r\n"  # invalid: no field to continue
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, forged + MESSAGE) == QUEUED
    # Score (or, without a score, ID) is ASSP-NG's last field: nothing may continue it.
    own = b"X-ASSP-NG-Score: 10 (session_limits=10)\r\n" if score else b""
    assert split_id(fake.messages[0])[2] == own + MESSAGE + b".\r\n"


async def test_maillog_record_fields(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c, "bob@example.com", "carol@example.com")
        assert await send_message(c) == QUEUED
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    [record] = proxy.maillog  # no session record after a message record
    assert (record.instance, record.txn, record.listener) == ("test", 1, "inbound")
    assert (record.ip, record.ptr, record.helo, record.tls, record.auth) == (
        "127.0.0.1", "client.example", "client.example", "", "")
    assert (record.mail_from, record.rcpts) == (SENDER, ["bob@example.com", "carol@example.com"])
    assert (record.size, record.score, record.result) == (len(MESSAGE), 0, "accepted")
    assert record.mta == "250 2.0.0 Ok: queued as FAKE1"
    assert record.duration_s >= 0
    assert split_id(fake.messages[0])[0] == record.session
    assert (f"from=<{SENDER}> rcpt=<bob@example.com>,<carol@example.com> size={len(MESSAGE)} "
            'score=0 result=accepted mta="250 2.0.0 Ok: queued as FAKE1"'
            ) in format_maillog(record)


async def test_second_transaction_gets_its_own_record(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
        await open_transaction(c, "carol@example.com", sender="", greet=False)
        assert await send_message(c, b"Subject: second\r\n\r\nagain\r\n") == QUEUED
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    assert [split_id(message)[1] for message in fake.messages] == [1, 2]
    first, second = proxy.maillog
    assert (first.txn, first.mail_from, first.rcpts) == (1, SENDER, ["bob@example.com"])
    assert (second.txn, second.mail_from, second.rcpts) == (2, "<>", ["carol@example.com"])
    assert first.session == second.session
    assert [first.result, second.result] == ["accepted", "accepted"]
    assert proxy.health.events == ["accepted", "accepted"]


async def test_data_needs_a_transaction_with_recipients(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await c.expect_banner()
        assert (await c.send("EHLO client.example")).code == 250
        assert await c.send("DATA") == R_BAD_SEQUENCE
        assert await c.send("MAIL FROM:<alice@remote.example>") == OK
        assert await c.send("DATA") == R_NO_RCPT
        assert await c.send("RCPT TO:<bob@example.com>") == OK
        assert await c.send("DATA now") == R_BAD_ARG
        assert await send_message(c) == QUEUED
    assert fake.received.count(b"DATA") == 1


@pytest.mark.parametrize("attempt", [b"\n.\n", b"\r.\n"])
async def test_smuggling_attempt_stays_one_message(proxy_with: StartProxy, attempt: bytes
                                                   ) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    smuggled = b"MAIL FROM:<evil@remote.example>\r\nRCPT TO:<victim@example.com>\r\nDATA\r\n"
    async with proxy.dialog() as c:
        await open_transaction(c)
        wire = HEADER + b"\r\nfirst" + attempt + smuggled + b"forged\r\n"
        assert await send_message(c, wire) == QUEUED
        assert await c.send("QUIT") == R_BYE
    await proxy.wait_sessions()
    [message] = fake.messages
    assert fake.received.count(b"DATA") == 1
    assert not any(line.startswith(b"MAIL FROM:<evil") for line in fake.received)
    assert split_id(message)[2] == HEADER + b"\r\nfirst\r\n..\r\n" + smuggled + b"forged\r\n.\r\n"


# --- check decisions and header fields -----------------------------------------------------


async def test_reject_sends_rset_and_554(proxy_with: StartProxy) -> None:
    check = ContentCheck(CheckResult(True, reason="bad body"), phase=Phase.BODY)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check])
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == R_REJECT
        assert await c.send("MAIL FROM:<alice@remote.example>") == OK  # the transaction ended
    await proxy.wait_sessions()
    assert fake.messages == []
    assert b"DATA" not in fake.received
    assert fake.received[-2:] == [b"RSET", b"MAIL FROM:<alice@remote.example>"]
    [record] = proxy.maillog
    assert (record.result, record.mta, record.size) == ("rejected", "-", len(MESSAGE))
    assert proxy.health.events == ["rejected"]


async def test_too_many_messages_421_at_mail_closes_the_session(proxy_with: StartProxy
                                                                ) -> None:
    """R63: the production check list runs here; its 421 at MAIL ends the session."""
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, config={"limits.session.messages": 1})
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
        assert await c.send(f"MAIL FROM:<{SENDER}>") == R_TOO_MANY_MSG
        await c.expect_closed()
    await proxy.wait_sessions()
    assert [line for line in fake.received if line.startswith(b"MAIL")] == [
        f"MAIL FROM:<{SENDER}>".encode()]
    assert proxy.sessions[0]._result == "rejected"


async def test_check_421_at_header_ends_the_session(proxy_with: StartProxy) -> None:
    gone = Reply.of(421, "4.7.0 Go away")
    fake = FakeBackend()
    check = ContentCheck(CheckResult(True, reason="bad", reply=gone, temporary=True))
    proxy = await start(proxy_with, fake, checks=[check])
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == gone
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.messages == []
    assert [r.result for r in proxy.maillog] == ["tempfailed"]


async def test_data_in_tempfail_mode_451_before_354(proxy_with: StartProxy) -> None:
    """Spec 6.2: DATA in TEMPFAIL is refused before 354; nothing reaches the MTA."""
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        proxy.deps.state.force_tempfail("test")
        assert await c.send("DATA") == R_TEMPFAIL_CMD
        assert await c.send("QUIT") == R_BYE
    assert b"DATA" not in fake.received
    assert fake.messages == []


async def test_tempfail_decision_451(proxy_with: StartProxy) -> None:
    check = ContentCheck(CheckResult(True, reason="busy", temporary=True))
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check])
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == R_CHECK_TEMPFAIL
    await proxy.wait_sessions()
    assert check.seen[-1][0] is Phase.HEADER  # BODY never ran
    assert fake.received[-1] == b"RSET"
    assert [r.result for r in proxy.maillog] == ["tempfailed"]
    assert proxy.health.events == ["tempfailed"]


async def test_testmode_adds_test_header_and_delivers(proxy_with: StartProxy, etc_dir: Path
                                                      ) -> None:
    write_default(etc_dir, "testmode = true\n")
    check = ContentCheck(CheckResult(True, reason="spam pattern"), phase=Phase.BODY)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check])
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
    await proxy.wait_sessions()
    [message] = fake.messages
    assert split_id(message)[2] == (
        b"X-ASSP-NG-Test: would reject: session_limits: spam pattern\r\n" + MESSAGE + b".\r\n")
    [record] = proxy.maillog
    assert record.result == "accepted-test"
    assert proxy.health.events == ["accepted"]


async def test_testmode_connect_would_reject_reaches_the_message(
        proxy_with: StartProxy, etc_dir: Path) -> None:
    """R62, spec 4.8: a penalty-box hit at CONNECT in test mode is tagged and logged."""
    write_default(etc_dir, "testmode = true\n")
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, peer=PUBLIC_PEER)
    await proxy.box.block(PUBLIC_NET, 3600, "listed")
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
    await proxy.wait_sessions()
    [message] = fake.messages
    rest = split_id(message)[2]
    assert re.match(rb"X-ASSP-NG-Test: would reject: penalty_box: blocked until \S+ "
                    rb"\(level 0\): listed\r\n", rest), rest[:200]
    [record] = proxy.maillog
    assert record.result == "accepted-test"


async def test_connect_score_counts_in_every_message(proxy_with: StartProxy) -> None:
    """R62: a CONNECT-phase score is part of each message's score (not summed twice)."""
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, peer=PUBLIC_PEER, config={
        "checks.penalty_box.mode": "score", "checks.penalty_box.msg_score": 7})
    await proxy.box.block(PUBLIC_NET, 3600, "listed")
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
        await open_transaction(c, greet=False)
        assert await send_message(c) == QUEUED
    await proxy.wait_sessions()
    for message in fake.messages:
        assert split_id(message)[2].startswith(b"X-ASSP-NG-Score: 7 (penalty_box=7)\r\n")
    assert [record.score for record in proxy.maillog] == [7, 7]


@pytest.mark.parametrize("add_header", [True, False])
async def test_score_header_and_warning(proxy_with: StartProxy, etc_dir: Path, add_header: bool
                                        ) -> None:
    write_default(etc_dir, f"scoring.add_header = {str(add_header).lower()}\n")
    check = ContentCheck(CheckResult(True, msg_score=40, reason="suspicious"))
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check], config=SCORE_MODE)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
    await proxy.wait_sessions()
    expected = b"X-ASSP-NG-Score: 40 (session_limits=40)\r\n" if add_header else b""
    expected += b"X-ASSP-NG-Warning: score 40 above warning level 35\r\n"
    assert split_id(fake.messages[0])[2] == expected + MESSAGE + b".\r\n"
    assert proxy.maillog[0].score == 40


@pytest.mark.parametrize("score,tagged", [(40, True), (10, False)])
async def test_subject_tag_keeps_folding_and_encoding(
    proxy_with: StartProxy, etc_dir: Path, score: int, tagged: bool
) -> None:
    write_default(etc_dir, 'scoring.warn_subject_tag = "[SPAM]"\n')
    check = ContentCheck(CheckResult(True, msg_score=score, reason="suspicious"))
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check], config=SCORE_MODE)
    subject = b"subject:\t=?UTF-8?B?SGVsbG8=?=\r\n =?UTF-8?B?V29ybGQ=?=\r\n"
    header = b"X-Subject: not this one\r\n" + subject + b"From: alice@remote.example\r\n"
    body = b"\r\nSubject: a body line\r\n"
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, header + body) == QUEUED
    await proxy.wait_sessions()
    rest = split_id(fake.messages[0])[2]
    if tagged:
        subject = b"subject:\t[SPAM] =?UTF-8?B?SGVsbG8=?=\r\n =?UTF-8?B?V29ybGQ=?=\r\n"
        assert rest.startswith(b"X-ASSP-NG-Score: 40 (session_limits=40)\r\n"
                               b"X-ASSP-NG-Warning: score 40 above warning level 35\r\n")
    else:
        assert rest.startswith(b"X-ASSP-NG-Score: 10 (session_limits=10)\r\nX-Subject:")
    assert rest.endswith(b"X-Subject: not this one\r\n" + subject
                         + b"From: alice@remote.example\r\n" + body + b".\r\n")


async def test_subject_tag_without_subject_changes_nothing(proxy_with: StartProxy,
                                                           etc_dir: Path) -> None:
    write_default(etc_dir, 'scoring.warn_subject_tag = "[SPAM]"\n')
    check = ContentCheck(CheckResult(True, msg_score=40, reason="suspicious"))
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check], config=SCORE_MODE)
    message = b"From: alice@remote.example\r\nX-Subject: none\r\n\r\nSubject: body\r\n"
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, message) == QUEUED
    assert split_id(fake.messages[0])[2].endswith(b"level 35\r\n" + message + b".\r\n")


async def test_check_reason_with_crlf_gives_single_line_field(proxy_with: StartProxy) -> None:
    check = ContentCheck(CheckResult(True, reason="bad\r\nX-Injected: yes\rmore\nend"))
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check],
                        config={"checks.session_limits.mode": "test"})
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
    [message] = fake.messages
    assert split_id(message)[2] == (
        b"X-ASSP-NG-Test: would reject: session_limits: bad  X-Injected: yes more end\r\n"
        + MESSAGE + b".\r\n")


async def test_long_check_reasons_fit_the_line_limit(proxy_with: StartProxy) -> None:
    check = ContentCheck(CheckResult(True, reason="é" * 1000))
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, checks=[check],
                        config={"checks.session_limits.mode": "test"})
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED
    field, rest = split_id(fake.messages[0])[2].split(b"\r\n", 1)
    assert field.startswith(b"X-ASSP-NG-Test: would reject: session_limits: \xc3\xa9")
    assert 990 <= len(field) <= 998
    field.decode("utf-8")  # cut on a character boundary
    assert rest == MESSAGE + b".\r\n"


@pytest.mark.parametrize("headers", [True, False])
async def test_body_never_tapped(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture, headers: bool
) -> None:
    caplog.set_level(logging.DEBUG)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    proxy.deps.debug_rules.add(RuleKind.ALL, "", 600, headers)
    texts = record_debug_writes(proxy)
    message = b"Subject: tapped subject\r\n\r\nBODY-SECRET first\r\nBODY-SECRET second\r\n"
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, message) == QUEUED
    await proxy.wait_sessions()
    for expected in ("C>P DATA", "P>C 354 End data with <CR><LF>.<CR><LF>", "P>M DATA",
                     "M>P 250 2.0.0 Ok: queued as FAKE1", "P>C 250 2.0.0 Ok: queued as FAKE1"):
        assert expected in texts
    header_lines = [t for t in texts if "Subject" in t or "X-ASSP-NG" in t]
    if headers:
        assert header_lines[0].startswith("P>M X-ASSP-NG-ID: test-")
        assert header_lines[1:] == ["P>M Subject: tapped subject"]
    else:
        assert header_lines == []
    assert not any("BODY-SECRET" in text for text in texts)
    assert "BODY-SECRET" not in debug_file_text(proxy)
    assert "BODY-SECRET" not in caplog.text


# --- MTA replies and failures --------------------------------------------------------------


async def test_refusal_reaches_the_client_before_the_rset(proxy_with: StartProxy) -> None:
    """C10, spec 4.7: reply first, then RSET to the MTA. A backend lost at that RSET still
    ends the session, but the client has its refusal and the maillog says rejected."""
    check = ContentCheck(CheckResult(True, reason="bad body"), phase=Phase.BODY)
    fake = FakeBackend(errors={b"RSET": BackendClosed("connection lost")})
    proxy = await start(proxy_with, fake, checks=[check])
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == R_REJECT
        assert await c.reply() == R_BACKEND_LOST
        await c.expect_closed()
    await proxy.wait_sessions()
    assert fake.received[-1] == b"RSET"
    assert [record.result for record in proxy.maillog] == ["rejected"]


async def test_mta_refusal_reaches_the_client_before_the_rset(proxy_with: StartProxy) -> None:
    refused = Reply.of(554, "5.7.1 Refused by the MTA")
    fake = FakeBackend(final_reply=refused, errors={b"RSET": BackendClosed("connection lost")})
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == refused
        assert await c.reply() == R_BACKEND_LOST
        await c.expect_closed()
    await proxy.wait_sessions()
    assert [record.result for record in proxy.maillog] == ["rejected"]


async def test_backend_final_reply_relayed(proxy_with: StartProxy) -> None:
    full = Reply.of(452, "4.3.1 Insufficient system storage")
    fake = FakeBackend(final_reply=full)
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == full
        assert await c.send("MAIL FROM:<alice@remote.example>") == OK
    await proxy.wait_sessions()
    assert len(fake.messages) == 1
    assert fake.received[-3:] == [b"DATA", b"RSET", b"MAIL FROM:<alice@remote.example>"]
    [record] = proxy.maillog
    assert (record.result, record.mta) == ("tempfailed", "452 4.3.1 Insufficient system storage")
    assert proxy.health.events == ["tempfailed"]


async def test_backend_non_354_relayed(proxy_with: StartProxy) -> None:
    refused = Reply.of(554, "5.5.1 Error: no valid recipients")
    fake = FakeBackend(replies={"DATA": refused})
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == refused
        assert await c.send("MAIL FROM:<alice@remote.example>") == OK
    await proxy.wait_sessions()
    assert fake.messages == []
    assert fake.received[-3:] == [b"DATA", b"RSET", b"MAIL FROM:<alice@remote.example>"]
    [record] = proxy.maillog
    assert (record.result, record.mta) == ("rejected", "554 5.5.1 Error: no valid recipients")
    assert proxy.health.events == ["rejected"]


async def test_backend_lost_during_data_421(proxy_with: StartProxy) -> None:
    fake = FakeBackend(errors={b"DATA": BackendClosed("backend closed the connection")})
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == R_BACKEND_LOST
        await c.expect_closed()
    await proxy.wait_sessions()
    [record] = proxy.maillog
    assert (record.result, record.txn) == ("tempfailed", 1)
    assert proxy.health.events == ["tempfailed", "backend_lost"]
    assert fake.closes == 1


class FailingHealth(FakeHealth):
    def record(self, event: str) -> None:
        raise RuntimeError("health broke")


def failing_maillog(record: object) -> None:
    raise RuntimeError("maillog broke")


async def test_delivered_message_survives_failing_maillog_and_health(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, health=FailingHealth(), maillog=failing_maillog)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == QUEUED  # never a 421 after delivery: no duplicate
        assert await c.send("NOOP") == OK
    await proxy.wait_sessions()
    assert len(fake.messages) == 1
    assert "cannot write the message record: RuntimeError" in caplog.text
    assert "cannot count the message: RuntimeError" in caplog.text


# --- size, buffering, storage failures -----------------------------------------------------


async def test_oversize_552_after_full_read(proxy_with: StartProxy) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, config={"max_message_size": 1000})
    big = HEADER + b"\r\n" + lines(80)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, big) == R_SIZE
        assert await c.send("NOOP") == OK  # the rest of the data was read and discarded
    await proxy.wait_sessions()
    assert fake.messages == []
    assert fake.received[-2:] == [b"RSET", b"NOOP"]
    [record] = proxy.maillog
    assert (record.result, record.size) == ("rejected", len(big))
    assert spool_files(proxy) == []
    assert proxy.deps.budget.used == 0


async def test_large_message_spooled_and_cleaned(proxy_with: StartProxy, tmp_path: Path) -> None:
    fake = SpoolWatchingBackend(tmp_path / "spool")
    proxy = await start(proxy_with, fake, config={"buffer.memory_per_message": 4096})
    big = HEADER + b"\r\n" + lines(3000, 70)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, big) == QUEUED
    await proxy.wait_sessions()
    assert len(fake.spooled) == 1  # the message was in a spool file while it was delivered
    [message] = fake.messages
    assert split_id(message)[2] == big + b".\r\n"
    assert proxy.maillog[0].size == len(big)
    assert spool_files(proxy) == []
    assert proxy.deps.budget.used == 0


@pytest.mark.parametrize("how", ["close", "reset"])
async def test_client_disconnect_mid_data_cleans_up(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture, how: str
) -> None:
    caplog.set_level(logging.INFO)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, config={"buffer.memory_per_message": 1024})
    partial = HEADER + b"\r\n" + lines(40)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(partial)
        await wait_until(lambda: len(spool_files(proxy)) == 1)
        if how == "reset":  # an RST instead of a FIN
            sock = c.writer.get_extra_info("socket")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            c.writer.transport.abort()
    await proxy.wait_sessions()
    assert spool_files(proxy) == []
    assert proxy.deps.budget.used == 0
    assert proxy.deps.connections.total == 0
    assert fake.closes == 1  # FakeBackend.close() stands for QUIT and close
    assert fake.messages == [] and b"DATA" not in fake.received
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    [record] = proxy.maillog
    assert (record.result, record.txn, record.size) == ("disconnected", 1, len(partial))
    assert proxy.health.events == []


async def test_storage_failure_discards_then_451_in_sync(
    proxy_with: StartProxy, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, config={
        "buffer.memory_per_message": 1024, "paths.spool": str(tmp_path / "missing")})
    big = HEADER + b"\r\n" + lines(40)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(big)
        await wait_until(lambda: "cannot store the message" in caplog.text)
        await c.send_raw(lines(40) + b".\r\n")  # read and discarded up to the end of data
        assert await c.reply() == R_TEMPFAIL_CMD
        await open_transaction(c, greet=False)  # the stream stayed in sync
        assert await send_message(c) == QUEUED  # a small message stays in memory
    await proxy.wait_sessions()
    assert len(fake.messages) == 1
    assert fake.received.count(b"RSET") == 1
    assert [(r.result, r.size) for r in proxy.maillog] == [
        ("tempfailed", len(big) + len(lines(40))), ("accepted", len(MESSAGE))]
    assert proxy.health.events == ["tempfailed", "accepted"]
    assert "cannot store the message: FileNotFoundError" in caplog.text
    assert proxy.deps.budget.used == 0


async def test_spool_read_failure_before_delivery_451(
    proxy_with: StartProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: MessageBuffer, limit: int) -> bytes:
        raise OSError("I/O error")

    monkeypatch.setattr(MessageBuffer, "read_head", broken)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == R_TEMPFAIL_CMD
        assert await c.send("NOOP") == OK
    await proxy.wait_sessions()
    assert fake.received[-2:] == [b"RSET", b"NOOP"]
    assert [r.result for r in proxy.maillog] == ["tempfailed"]


async def test_spool_read_failure_while_streaming_closes(
    proxy_with: StartProxy, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real = MessageBuffer.iter_chunks

    def broken(self: MessageBuffer, start: int = 0, chunk: int = 65536) -> Iterator[bytes]:
        if start > 0:  # the body, read while the MTA receives the message
            raise OSError("I/O error")
        return real(self, start, chunk)

    monkeypatch.setattr(MessageBuffer, "iter_chunks", broken)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == R_TEMPFAIL
        await c.expect_closed()
    await proxy.wait_sessions()
    assert [r.result for r in proxy.maillog] == ["tempfailed"]
    assert proxy.health.events == ["tempfailed"]
    assert "cannot read the stored message: OSError" in caplog.text
    assert fake.closes == 1


async def test_header_too_large_552(proxy_with: StartProxy, monkeypatch: pytest.MonkeyPatch
                                    ) -> None:
    monkeypatch.setattr(session_data, "HEADER_LIMIT", len(HEADER))  # the empty line is beyond
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c) == session_data.R_HEADER_TOO_LARGE
        await open_transaction(c, greet=False)
        assert await send_message(c, HEADER) == QUEUED  # all header, within the limit
    await proxy.wait_sessions()
    [message] = fake.messages
    assert split_id(message)[2] == HEADER + b".\r\n"
    assert [r.result for r in proxy.maillog] == ["rejected", "accepted"]


@pytest.mark.parametrize("extra,reply", [
    (0, QUEUED), (1, Reply.of(552, "5.3.4 Message header too large"))])
async def test_header_limit_is_256_kib(proxy_with: StartProxy, extra: int, reply: Reply
                                       ) -> None:
    header = padded_header(256 * 1024 - 2 + extra)  # the empty line ends at 256 KiB (+ extra)
    fake = FakeBackend()
    proxy = await start(proxy_with, fake)
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await send_message(c, header + b"\r\n" + BODY) == reply
    assert len(fake.messages) == (1 if extra == 0 else 0)


# --- protocol errors and timeouts ----------------------------------------------------------


async def test_pipelined_quit_after_end_of_data_still_delivers(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, config={"limits.session.protocol_errors": 2})
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(MESSAGE + b".\r\nQUIT\r\n")
        assert await c.reply() == QUEUED
        # The pipelined QUIT was discarded unanswered and the session goes on: the next
        # reply answers NOOP, so the leftover got no reply of its own.
        assert await c.send("NOOP") == OK
        assert await c.send("FOO") == R_TOO_MANY_ERRORS  # the leftover was error number one
        await c.expect_closed()
    await proxy.wait_sessions()
    assert len(fake.messages) == 1
    assert b"QUIT" not in fake.received
    assert [r.result for r in proxy.maillog] == ["accepted"]
    assert "discarded 6 bytes sent after the end of data" in caplog.text


async def test_pipelined_leftover_at_error_limit_closes_after_reply(
    proxy_with: StartProxy, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, peer=PUBLIC_PEER, config={
        "limits.session.protocol_errors": 1, "abuse.protocol_error_ip_score": 7})
    pipelined = b"MAIL FROM:<evil@remote.example>\r\n"
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(MESSAGE + b".\r\n" + pipelined)
        assert await c.reply() == QUEUED
        assert await c.reply() == R_TOO_MANY_ERRORS
        await c.expect_closed()
    await proxy.wait_sessions()
    assert len(fake.messages) == 1
    assert not any(line.startswith(b"MAIL FROM:<evil") for line in fake.received)
    assert (await proxy.box.status(PUBLIC_NET)).score == 7
    assert [r.result for r in proxy.maillog] == ["accepted"]
    assert proxy.health.events == ["accepted"]
    assert f"discarded {len(pipelined)} bytes" in caplog.text
    assert "evil" not in caplog.text


@pytest.mark.parametrize("setting", ["timeouts.data_block", "timeouts.data_total"])
async def test_data_timeout_421(proxy_with: StartProxy, setting: str) -> None:
    fake = FakeBackend()
    proxy = await start(proxy_with, fake, config={setting: 0.3})
    async with proxy.dialog() as c:
        await open_transaction(c)
        assert await c.send("DATA") == R_DATA_GO
        await c.send_raw(HEADER)

        async def trickle() -> None:  # keeps every data block in time
            with contextlib.suppress(OSError):
                for _ in range(40):
                    await c.send_raw(b"x")
                    await asyncio.sleep(0.05)

        task = asyncio.create_task(trickle()) if setting == "timeouts.data_total" else None
        assert await c.reply(timeout=2) == R_IDLE
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await c.expect_closed()
    await proxy.wait_sessions()
    assert b"DATA" not in fake.received
    assert fake.closes == 1
    [record] = proxy.maillog
    assert (record.result, record.txn, record.size) == ("timeout", 1, len(HEADER))
    assert proxy.health.events == []
