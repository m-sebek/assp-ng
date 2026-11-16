# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio

import pytest

from asspng.smtp.lines import ConnectionClosed, LineTooLong, read_line
from asspng.smtp.replies import ReadTimeout


async def test_crlf(reader_from):
    assert await read_line(reader_from(b"NOOP\r\n"), 2048, 1) == b"NOOP"


async def test_bare_lf(reader_from):
    assert await read_line(reader_from(b"NOOP\n"), 2048, 1) == b"NOOP"


async def test_empty_line(reader_from):
    assert await read_line(reader_from(b"\r\n"), 2048, 1) == b""


async def test_exactly_at_limit(reader_from):
    assert await read_line(reader_from(b"A" * 10 + b"\r\n"), 10, 1) == b"A" * 10
    assert await read_line(reader_from(b"A" * 10 + b"\n"), 10, 1) == b"A" * 10


async def test_limit_plus_one(reader_from):
    with pytest.raises(LineTooLong):
        await read_line(reader_from(b"A" * 11 + b"\r\n"), 10, 1)
    with pytest.raises(LineTooLong):
        await read_line(reader_from(b"A" * 11 + b"\n"), 10, 1)


async def test_line_too_long_consumes_rest(reader_from):
    r = reader_from(b"A" * 3000 + b"\r\nNOOP\r\n")
    with pytest.raises(LineTooLong):
        await read_line(r, 2048, 1)
    assert await read_line(r, 2048, 1) == b"NOOP"


async def test_huge_line_beyond_stream_limit(reader_from):
    r = reader_from(b"A" * 200000 + b"\r\nNOOP\r\n")
    with pytest.raises(LineTooLong):
        await read_line(r, 2048, 1)
    assert await read_line(r, 2048, 1) == b"NOOP"


async def test_overlong_without_newline_then_eof(reader_from):
    r = reader_from(b"A" * 3000)
    with pytest.raises(ConnectionClosed):
        await read_line(r, 2048, 1)


async def test_eof(reader_from):
    with pytest.raises(ConnectionClosed):
        await read_line(reader_from(b""), 2048, 1)


async def test_partial_line_then_eof(reader_from):
    with pytest.raises(ConnectionClosed):
        await read_line(reader_from(b"NOOP"), 2048, 1)


async def test_timeout():
    with pytest.raises(ReadTimeout):
        await read_line(asyncio.StreamReader(), 2048, 0.01)


@pytest.mark.parametrize("data,size", [
    (b"A" * 3000 + b"\r\n", 3000),
    (b"A" * 3000 + b"\n", 3000),
    (b"A" * 200000 + b"\r\n", 200000),
    (b"A" * 200000 + b"\n", 200000),
], ids=["3000-crlf", "3000-lf", "200000-crlf", "200000-lf"])
async def test_line_too_long_reports_length(reader_from, data, size):
    with pytest.raises(LineTooLong) as info:
        await read_line(reader_from(data), 2048, 1)
    assert info.value.length == size
