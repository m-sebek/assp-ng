# SPDX-License-Identifier: GPL-3.0-or-later
"""SMTP replies: construction, encoding and parsing of backend (MTA) replies."""

import asyncio
from dataclasses import dataclass
from typing import Self


class BackendProtocolError(Exception):
    """The backend sent something that is not a well-formed SMTP reply."""


class ReadTimeout(Exception):
    """Reading from a peer did not complete in time."""


@dataclass(frozen=True)
class Reply:
    code: int
    lines: tuple[str, ...]

    @classmethod
    def of(cls, code: int, *lines: str) -> Self:
        return cls(code, tuple(lines))

    def encode(self) -> bytes:
        """Encode as wire bytes; a reply without text gives ``b"<code> \\r\\n"``."""
        lines = self.lines or ("",)
        last = len(lines) - 1
        return b"".join(
            f"{self.code}{' ' if i == last else '-'}{text}\r\n".encode()
            for i, text in enumerate(lines)
        )

    @property
    def is_positive(self) -> bool:
        return 200 <= self.code < 400

    @property
    def is_temporary(self) -> bool:
        return 400 <= self.code < 500

    @property
    def is_permanent(self) -> bool:
        return 500 <= self.code < 600


async def _read_reply_lines(
    reader: asyncio.StreamReader, max_lines: int
) -> Reply:
    code: int | None = None
    texts: list[str] = []
    while True:
        try:
            raw = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            raise BackendProtocolError("connection closed inside a reply") from exc
        except asyncio.LimitOverrunError as exc:
            raise BackendProtocolError("reply line too long") from exc
        line = raw[:-1]
        if line.endswith(b"\r"):
            line = line[:-1]
        head, sep, text = line[:3], line[3:4], line[4:]
        if len(head) != 3 or not head.isdigit() or sep not in (b"-", b" ", b""):
            raise BackendProtocolError("malformed reply line")
        line_code = int(head)
        if code is not None and line_code != code:
            raise BackendProtocolError("mixed reply codes")
        code = line_code
        texts.append(text.decode("utf-8", errors="replace"))
        if len(texts) > max_lines:
            raise BackendProtocolError("reply has too many lines")
        if sep != b"-":
            return Reply(code, tuple(texts))


async def read_reply(
    reader: asyncio.StreamReader, timeout: float, max_lines: int = 100
) -> Reply:
    """Read one (possibly multi-line) reply; ``timeout`` covers the whole reply."""
    try:
        async with asyncio.timeout(timeout):
            return await _read_reply_lines(reader, max_lines)
    except TimeoutError as exc:
        raise ReadTimeout("timed out reading reply") from exc


R_RELAY_DENIED = Reply.of(554, "5.7.1 Relay access denied")
R_TOO_MANY_RCPT = Reply.of(452, "4.5.3 Too many recipients")
R_POLICY_SPLIT = Reply.of(452, "4.5.3 Too many recipients, try again")
R_AUTH_REQUIRED = Reply.of(530, "5.7.0 Authentication required")
R_ENCRYPTION_REQUIRED = Reply.of(538, "5.7.11 Encryption required")
R_SIZE = Reply.of(552, "5.3.4 Message size exceeds limit")
R_NO_RCPT = Reply.of(554, "5.5.1 No valid recipients")
R_SCORE = Reply.of(554, "5.7.1 Message score too high")
R_VRFY = Reply.of(252, "2.5.2 Cannot VRFY user")
R_NOT_IMPL = Reply.of(502, "5.5.1 Command not implemented")
R_SYNTAX = Reply.of(500, "5.5.2 Syntax error")
R_LINE_TOO_LONG = Reply.of(500, "5.5.2 Line too long")
R_BAD_ARG = Reply.of(501, "5.5.4 Invalid argument")
R_TLS_READY = Reply.of(220, "2.0.0 Ready to start TLS")
R_TLS_UNAVAILABLE = Reply.of(454, "4.7.0 TLS not available")
R_TLS_ACTIVE = Reply.of(503, "5.5.1 TLS already active")
R_BAD_SEQUENCE = Reply.of(503, "5.5.1 Bad sequence of commands")
R_AUTH_TEMPFAIL = Reply.of(454, "4.7.0 Temporary authentication failure")
R_BACKEND_DOWN = Reply.of(421, "4.3.2 Service temporarily unavailable")
R_TEMPFAIL = Reply.of(421, "4.3.0 Service temporarily unavailable")
R_TEMPFAIL_CMD = Reply.of(451, "4.3.0 Service temporarily unavailable")
R_TOO_MANY_ERRORS = Reply.of(421, "4.7.0 Too many errors")
R_TOO_MANY_CONN = Reply.of(421, "4.7.0 Too many connections")
R_TOO_MANY_MSG = Reply.of(421, "4.7.0 Too many messages")
R_TRY_LATER = Reply.of(421, "4.7.0 Try again later")
R_BACKEND_LOST = Reply.of(421, "4.4.2 Connection to mail server lost")
R_RATE = Reply.of(451, "4.7.1 Rate limit exceeded")
R_IDLE = Reply.of(421, "4.4.2 Idle timeout")
R_INTERNAL = Reply.of(421, "4.3.0 Internal error, try again later")
R_BYE = Reply.of(221, "2.0.0 Bye")
R_DATA_GO = Reply.of(354, "End data with <CR><LF>.<CR><LF>")
R_HELP = Reply.of(214, "2.0.0 See RFC 5321")
R_DOMAINS_UNAVAILABLE = Reply.of(451, "4.3.0 Local domain list unavailable")
