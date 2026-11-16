# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio

import pytest

from asspng.smtp import replies
from asspng.smtp.replies import BackendProtocolError, ReadTimeout, Reply, read_reply


def test_encode_single():
    assert Reply.of(250, "OK").encode() == b"250 OK\r\n"


def test_encode_multiline():
    assert Reply.of(250, "a", "b").encode() == b"250-a\r\n250 b\r\n"


def test_encode_empty_line():
    assert Reply.of(250, "").encode() == b"250 \r\n"
    assert Reply(250, ()).encode() == b"250 \r\n"


def test_classification():
    assert Reply.of(250, "x").is_positive
    assert Reply.of(354, "x").is_positive
    assert not Reply.of(450, "x").is_positive
    assert Reply.of(450, "x").is_temporary
    assert Reply.of(550, "x").is_permanent
    assert not Reply.of(550, "x").is_temporary


def test_constants_exact():
    assert replies.R_RELAY_DENIED == Reply(554, ("5.7.1 Relay access denied",))
    assert replies.R_DATA_GO.encode() == b"354 End data with <CR><LF>.<CR><LF>\r\n"
    assert replies.R_POLICY_SPLIT == Reply(452, ("4.5.3 Too many recipients, try again",))
    assert replies.R_INTERNAL.code == 421
    assert replies.R_DOMAINS_UNAVAILABLE == Reply(451, ("4.3.0 Local domain list unavailable",))


async def test_read_single(reader_from):
    assert await read_reply(reader_from(b"250 OK\r\n"), 1) == Reply(250, ("OK",))


async def test_read_multiline(reader_from):
    r = await read_reply(reader_from(b"250-x\r\n250 y\r\n"), 1)
    assert r == Reply(250, ("x", "y"))


async def test_read_bare_code(reader_from):
    assert await read_reply(reader_from(b"250\r\n"), 1) == Reply(250, ("",))


async def test_read_leaves_following_data(reader_from):
    rd = reader_from(b"250 a\r\n220 b\r\n")
    assert (await read_reply(rd, 1)).code == 250
    assert (await read_reply(rd, 1)).code == 220


@pytest.mark.parametrize("data", [
    b"250-x\r\n251 y\r\n",
    b"abc def\r\n",
    b"25 x\r\n",
    b"2500 x\r\n",
    b"250xfoo\r\n",
    b"250-x\r\n",
    b"",
    b"250 no newline",
])
async def test_protocol_errors(reader_from, data):
    with pytest.raises(BackendProtocolError):
        await read_reply(reader_from(data), 1)


async def test_max_lines(reader_from):
    data = b"250-x\r\n" * 5 + b"250 y\r\n"
    with pytest.raises(BackendProtocolError):
        await read_reply(reader_from(data), 1, max_lines=5)
    assert len((await read_reply(reader_from(data), 1, max_lines=6)).lines) == 6


async def test_overlong_reply_line(reader_from):
    with pytest.raises(BackendProtocolError):
        await read_reply(reader_from(b"250 " + b"A" * 70000 + b"\r\n"), 1)


async def test_timeout():
    with pytest.raises(ReadTimeout):
        await read_reply(asyncio.StreamReader(), 0.01)
