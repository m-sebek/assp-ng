# SPDX-License-Identifier: GPL-3.0-or-later
"""A small scripted SMTP client for session tests."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import AsyncIterator

from asspng.smtp.replies import Reply, read_reply

DEFAULT_TIMEOUT_S = 2.0


def client_tls_context() -> ssl.SSLContext:
    """A client context for the self-signed test certificates (no verification)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class SmtpDialog:
    """One client connection: send lines, read replies, check that the server closed."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def expect_banner(self, timeout: float = DEFAULT_TIMEOUT_S) -> Reply:
        """Read the greeting and require a 220."""
        banner = await self.reply(timeout)
        assert banner.code == 220, banner
        return banner

    async def reply(self, timeout: float = DEFAULT_TIMEOUT_S) -> Reply:
        """Read one (possibly multi-line) reply."""
        return await read_reply(self.reader, timeout)

    async def send(self, line: str | bytes, timeout: float = DEFAULT_TIMEOUT_S) -> Reply:
        """Send one command line (CRLF is added) and return the reply."""
        await self.send_raw((line.encode() if isinstance(line, str) else line) + b"\r\n")
        return await self.reply(timeout)

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def raw_line(self, timeout: float = DEFAULT_TIMEOUT_S) -> bytes:
        """Read one raw line from the server, including its line ending."""
        async with asyncio.timeout(timeout):
            return await self.reader.readuntil(b"\n")

    async def expect_closed(self, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        """Require that the server closes the connection without sending anything more."""
        try:
            async with asyncio.timeout(timeout):
                data = await self.reader.read()
        except ConnectionResetError:
            return
        assert data == b"", data

    async def starttls(self, ctx: ssl.SSLContext, server_hostname: str | None = None) -> None:
        """Upgrade the connection to TLS (after the server's 220 to STARTTLS)."""
        await self.writer.start_tls(ctx, server_hostname=server_hostname)

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(OSError, TimeoutError):
            async with asyncio.timeout(DEFAULT_TIMEOUT_S):
                await self.writer.wait_closed()


@contextlib.asynccontextmanager
async def smtp_dialog(
    host: str, port: int, ssl_context: ssl.SSLContext | None = None
) -> AsyncIterator[SmtpDialog]:
    """Connect to ``host:port`` (with implicit TLS when ``ssl_context`` is given); the
    connection is closed when the block ends."""
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
    dialog = SmtpDialog(reader, writer)
    try:
        yield dialog
    finally:
        await dialog.close()
