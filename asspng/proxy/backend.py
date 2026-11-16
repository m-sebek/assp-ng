# SPDX-License-Identifier: GPL-3.0-or-later
"""The proxy's connection to the real MTA: XCLIENT, lockstep commands and DATA."""

import asyncio
import contextlib
from collections.abc import Iterable
from typing import Protocol

from asspng.net.ipnet import IPAddress
from asspng.proxy.xclient import format_xclient
from asspng.smtp.datacodec import Stuffer
from asspng.smtp.replies import BackendProtocolError, ReadTimeout, Reply, read_reply

_QUIT_TIMEOUT_S = 5.0


class BackendError(Exception):
    """The backend failed or refused to cooperate."""


class BackendTimeout(BackendError):
    """The backend did not answer in time."""


class BackendClosed(BackendError):
    """The backend closed the connection."""


class XclientUnsupported(BackendError):
    """The backend does not advertise XCLIENT."""


class Backend(Protocol):
    async def connect(self) -> Reply: ...

    async def xclient(
        self, addr: IPAddress, port: int, name: str, helo_name: str
    ) -> Reply: ...

    async def command(self, line: bytes, timeout_s: float) -> Reply: ...

    async def data(
        self, chunks: Iterable[bytes], timeout_354_s: float, timeout_final_s: float
    ) -> Reply: ...

    async def close(self) -> None: ...


class SmtpBackend(Backend):
    """One TCP connection to the MTA. Not safe for concurrent use.

    Once an operation has raised a ``BackendError`` the backend is broken: ``close()``
    then aborts the transport instead of sending QUIT.
    """

    def __init__(
        self, host: str, port: int, *, connect_timeout_s: float, banner_timeout_s: float
    ) -> None:
        self._host = host
        self._port = port
        self._connect_timeout_s = connect_timeout_s
        self._banner_timeout_s = banner_timeout_s
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._broken = False

    async def connect(self) -> Reply:
        """Open the connection and return the banner, whatever its code."""
        if self._writer is not None:
            raise RuntimeError("connect() called twice")
        try:
            async with asyncio.timeout(self._connect_timeout_s):
                self._reader, self._writer = await asyncio.open_connection(
                    self._host, self._port
                )
        except TimeoutError as exc:
            self._broken = True
            raise BackendTimeout("connect timed out") from exc
        except OSError as exc:
            self._broken = True
            raise BackendError(f"connect failed: {type(exc).__name__}") from exc
        return await self._read(self._banner_timeout_s)

    async def xclient(
        self, addr: IPAddress, port: int, name: str, helo_name: str
    ) -> Reply:
        """EHLO, check the XCLIENT capability, send XCLIENT and return the new greeting."""
        if "\r" in helo_name or "\n" in helo_name:
            raise ValueError("helo_name must not contain CR or LF")
        ehlo = await self.command(b"EHLO " + helo_name.encode("ascii", "replace"), 30.0)
        if not 200 <= ehlo.code < 300:
            self._broken = True
            raise BackendError(f"EHLO rejected with {ehlo.code}")
        keywords = {text.split(" ", 1)[0].upper() for text in ehlo.lines[1:]}
        if "XCLIENT" not in keywords:
            self._broken = True
            raise XclientUnsupported("backend does not advertise XCLIENT")
        await self._write(format_xclient(addr, port, name), 30.0)
        reply = await self._read(30.0)
        if reply.code != 220:
            self._broken = True
            raise BackendError(f"XCLIENT rejected with {reply.code}")
        return reply

    async def command(self, line: bytes, timeout_s: float) -> Reply:
        if b"\r" in line or b"\n" in line:
            raise ValueError("command line must not contain CR or LF")
        await self._write(line + b"\r\n", timeout_s)
        return await self._read(timeout_s)

    async def data(
        self, chunks: Iterable[bytes], timeout_354_s: float, timeout_final_s: float
    ) -> Reply:
        """Send DATA and, on 354, the stuffed chunks; return the final (or non-354) reply."""
        reply = await self.command(b"DATA", timeout_354_s)
        if reply.code != 354:
            return reply
        try:
            stuffer = Stuffer()
            for chunk in chunks:
                out = stuffer.feed(chunk)
                if out:
                    await self._write(out, timeout_354_s)
            await self._write(stuffer.finish(), timeout_final_s)
            return await self._read(timeout_final_s)
        except BaseException:
            # The stream is in the middle of a message: the connection cannot be reused.
            self._broken = True
            raise

    async def close(self) -> None:
        """Best-effort QUIT and close; never raises, safe to call repeatedly.

        A backend that has failed is aborted at once. Otherwise the whole QUIT sequence
        runs under one timeout and the transport is aborted if it does not finish.
        """
        reader, writer = self._reader, self._writer
        self._reader = self._writer = None
        if writer is None:
            return
        try:
            if not self._broken and reader is not None:
                try:
                    async with asyncio.timeout(_QUIT_TIMEOUT_S):
                        writer.write(b"QUIT\r\n")
                        await writer.drain()
                        await read_reply(reader, _QUIT_TIMEOUT_S)
                        writer.close()
                        await writer.wait_closed()
                except Exception:  # best effort: the peer may be gone or hung
                    pass
        finally:
            with contextlib.suppress(Exception):
                writer.transport.abort()

    async def _write(self, data: bytes, timeout_s: float) -> None:
        writer = self._writer
        if writer is None:
            raise BackendClosed("not connected")
        try:
            async with asyncio.timeout(timeout_s):
                writer.write(data)
                await writer.drain()
        except TimeoutError as exc:
            self._broken = True
            raise BackendTimeout("timed out writing to the backend") from exc
        except OSError as exc:
            self._broken = True
            raise BackendClosed("connection lost while writing") from exc

    async def _read(self, timeout_s: float) -> Reply:
        reader = self._reader
        if reader is None:
            raise BackendClosed("not connected")
        try:
            return await read_reply(reader, timeout_s)
        except ReadTimeout as exc:
            self._broken = True
            raise BackendTimeout("timed out waiting for the backend") from exc
        except OSError as exc:
            self._broken = True
            raise BackendClosed("connection lost while reading") from exc
        except BackendProtocolError as exc:
            self._broken = True
            if reader.at_eof() or isinstance(exc.__cause__, asyncio.IncompleteReadError):
                raise BackendClosed("backend closed the connection") from exc
            raise BackendError("malformed reply from backend") from exc
