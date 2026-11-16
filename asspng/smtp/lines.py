# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded line reading for command lines from untrusted clients."""

import asyncio

from asspng.smtp.replies import ReadTimeout


class LineTooLong(Exception):
    """A line exceeded the allowed length (it has been consumed up to its newline).

    ``length`` is the size of the discarded line in bytes, without its line ending.
    """

    def __init__(self, message: str, length: int) -> None:
        super().__init__(message)
        self.length = length


class ConnectionClosed(Exception):
    """The peer closed the connection before a complete line arrived."""


async def _read_line(reader: asyncio.StreamReader, limit: int) -> bytes:
    too_long = False
    discarded = 0
    last = b""
    while True:
        try:
            raw = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            raise ConnectionClosed("connection closed") from exc
        except asyncio.LimitOverrunError as exc:
            # Discard what is buffered without a newline and keep looking for one.
            chunk = await reader.readexactly(exc.consumed)
            discarded += len(chunk)
            last = chunk[-1:] or last
            too_long = True
            continue
        line = raw[:-1]
        if line.endswith(b"\r"):
            line = line[:-1]
        elif not line and last == b"\r":
            discarded -= 1  # the CR of a CRLF split across the discarded part
        if too_long or len(line) > limit:
            raise LineTooLong(f"line exceeds {limit} bytes", discarded + len(line))
        return line


async def read_line(reader: asyncio.StreamReader, limit: int, timeout: float) -> bytes:
    """Read one line without its ``\\r\\n`` or ``\\n``.

    ``limit`` counts content bytes excluding the terminator. An over-long line
    is consumed up to its newline before ``LineTooLong`` is raised, so the next
    call reads the following line. ``timeout`` covers the whole line.
    """
    try:
        async with asyncio.timeout(timeout):
            return await _read_line(reader, limit)
    except TimeoutError as exc:
        raise ReadTimeout("timed out reading line") from exc
