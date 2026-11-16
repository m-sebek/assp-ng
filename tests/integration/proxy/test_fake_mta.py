# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests of the FakeMta test double itself (state machine, recording)."""

import asyncio
import base64
from collections.abc import AsyncIterator

import pytest

from tests.support.fake_mta import FakeMta


class Client:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def cmd(self, line: str) -> str:
        """Send one command and return the first line of the reply (all lines consumed)."""
        self.writer.write(line.encode() + b"\r\n")
        await self.writer.drain()
        return await self.reply()

    async def reply(self) -> str:
        first = ""
        while True:
            raw = (await asyncio.wait_for(self.reader.readline(), 2)).decode().rstrip("\r\n")
            first = first or raw
            if raw[3:4] != "-":
                return first


@pytest.fixture
async def fake() -> AsyncIterator[FakeMta]:
    mta = FakeMta()
    await mta.start()
    yield mta
    await mta.stop()


async def connect(mta: FakeMta) -> Client:
    assert mta._server is not None
    port = mta._server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client = Client(reader, writer)
    assert (await client.reply()).startswith("220")
    return client


async def test_mail_before_ehlo_is_503(fake):
    c = await connect(fake)
    assert (await c.cmd("MAIL FROM:<a@x>")).startswith("503")


async def test_rcpt_before_mail_and_data_without_rcpt_are_503(fake):
    c = await connect(fake)
    await c.cmd("EHLO c")
    assert (await c.cmd("RCPT TO:<b@x>")).startswith("503")
    await c.cmd("MAIL FROM:<a@x>")
    assert (await c.cmd("DATA")).startswith("503")


async def test_nested_mail_is_503_and_rset_clears(fake):
    c = await connect(fake)
    await c.cmd("EHLO c")
    await c.cmd("MAIL FROM:<a@x>")
    assert (await c.cmd("MAIL FROM:<a@x>")).startswith("503 5.5.1 Error: nested MAIL")
    await c.cmd("RSET")
    assert (await c.cmd("MAIL FROM:<a@x>")).startswith("250")


async def test_xclient_needs_new_ehlo_afterwards(fake):
    c = await connect(fake)
    assert (await c.cmd("XCLIENT ADDR=1.2.3.4")).startswith("503")
    await c.cmd("EHLO c")
    assert (await c.cmd("XCLIENT ADDR=1.2.3.4 NAME=a+20b")).startswith("220")
    assert fake.xclient_attrs == [{"ADDR": "1.2.3.4", "NAME": "a b"}]
    assert (await c.cmd("MAIL FROM:<a@x>")).startswith("503")
    await c.cmd("EHLO c")
    assert (await c.cmd("MAIL FROM:<a@x>")).startswith("250")


async def test_xclient_not_implemented_when_disabled():
    mta = FakeMta(xclient=False)
    await mta.start()
    try:
        c = await connect(mta)
        await c.cmd("EHLO c")
        assert (await c.cmd("XCLIENT ADDR=1.2.3.4")).startswith("550")
    finally:
        await mta.stop()


async def test_helo_is_single_line(fake):
    c = await connect(fake)
    assert await c.cmd("HELO c") == "250 fake.mta"


async def test_malformed_mail_and_rcpt_are_501(fake):
    c = await connect(fake)
    await c.cmd("EHLO c")
    assert (await c.cmd("MAIL")).startswith("501")
    assert (await c.cmd("MAIL FROM:")).startswith("501")
    await c.cmd("MAIL FROM:<a@x>")
    assert (await c.cmd("RCPT TO:")).startswith("501")
    assert (await c.cmd("RCPT")).startswith("501")


async def test_rejected_rcpt_override_is_not_recorded():
    mta = FakeMta(replies={"RCPT": "452 4.2.2 Mailbox full"})
    await mta.start()
    try:
        c = await connect(mta)
        await c.cmd("EHLO c")
        await c.cmd("MAIL FROM:<a@x>")
        assert (await c.cmd("RCPT TO:<b@x>")).startswith("452")
        assert (await c.cmd("DATA")).startswith("503")
    finally:
        await mta.stop()


async def test_data_override_354_still_reads_body():
    mta = FakeMta(replies={"DATA": "354 go ahead"})
    await mta.start()
    try:
        c = await connect(mta)
        for line in ("EHLO c", "MAIL FROM:<a@x>", "RCPT TO:<b@x>"):
            await c.cmd(line)
        assert (await c.cmd("DATA")).startswith("354")
        assert (await c.cmd("hi\r\n.")).startswith("250")
        assert mta.messages == [("a@x", ["b@x"], b"hi\r\n")]
    finally:
        await mta.stop()


async def test_auth_payload_redacted_and_attempts_recorded(fake):
    c = await connect(fake)
    await c.cmd("EHLO c")
    good = base64.b64encode(b"\x00test\x00secret").decode()
    bad = base64.b64encode(b"\x00test\x00wrong").decode()
    assert (await c.cmd(f"AUTH PLAIN {good}")).startswith("235")
    assert (await c.cmd(f"AUTH PLAIN {bad}")).startswith("535")
    assert fake.auth_attempts == [("PLAIN", "test", True), ("PLAIN", "test", False)]
    assert not any(b"secret" in x or good.encode() in x or bad.encode() in x for x in fake.lines)


async def test_concurrent_connections_have_independent_state(fake):
    a = await connect(fake)
    b = await connect(fake)
    await a.cmd("EHLO a")
    assert (await b.cmd("MAIL FROM:<x@y>")).startswith("503")
    assert (await a.cmd("MAIL FROM:<x@y>")).startswith("250")
