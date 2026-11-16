# SPDX-License-Identifier: GPL-3.0-or-later
"""Scripted fake MTA (Postfix stand-in) for tests of the proxy backend and sessions."""

import asyncio
import base64
import contextlib
import re
from contextvars import ContextVar
from dataclasses import dataclass, field

_MAIL_RE = re.compile(r"^MAIL\s+FROM:\s*(<[^>]*>|[^\s<>]+)", re.IGNORECASE)
_RCPT_RE = re.compile(r"^RCPT\s+TO:\s*(<[^>]+>|[^\s<>]+)", re.IGNORECASE)
_XTEXT_RE = re.compile(rb"\+([0-9A-F]{2})")

NEW, GREETED, MAIL, RCPT = "new", "greeted", "mail", "rcpt"


@dataclass
class _Conn:
    """Per-connection protocol state (each connection runs in its own task)."""

    state: str = NEW
    mail_from: str = ""
    rcpts: list[str] = field(default_factory=list)


_CONN: ContextVar[_Conn] = ContextVar("fake_mta_conn")


def _xtext_decode(value: str) -> str:
    raw = _XTEXT_RE.sub(lambda m: bytes([int(m.group(1), 16)]), value.encode("latin-1"))
    return raw.decode("utf-8", errors="replace")


def _is_ok(reply: str) -> bool:
    return reply[:1] == "2"


class FakeMta:
    """A small asyncio SMTP server with a Postfix-like state machine and test knobs.

    Knobs (verbs are uppercase):
      ``hang_on``: never answer that command (``DATA_END``: the reply after the body).
      ``close_on``: close the connection when that command arrives.
      ``partial_close_on``: send the start of a multi-line reply, then close.
      ``garbage_on``: answer that command with a malformed reply line.
      ``replies``: verb -> full reply text overriding the default (``"452 4.3.1 Full"``);
        ``DATA_END`` overrides the reply after the message body.
      ``banner_delay``: seconds to wait before the banner.
      ``no_read_after_data``: stop reading once DATA was accepted with 354.

    Recording: ``lines`` (command lines, AUTH payloads redacted), ``auth_attempts``
    ``(mechanism, username, ok)``, ``messages`` ``(mail_from, rcpts, body)`` and
    ``xclient_attrs`` (xtext decoded).
    """

    def __init__(
        self,
        *,
        xclient: bool = True,
        banner_code: int = 220,
        hang_on: str | None = None,
        replies: dict[str, str] | None = None,
        close_on: str | None = None,
        partial_close_on: str | None = None,
        garbage_on: str | None = None,
        banner_delay: float = 0.0,
        no_read_after_data: bool = False,
    ) -> None:
        self.xclient = xclient
        self.banner_code = banner_code
        self.hang_on = hang_on.upper() if hang_on else None
        self.close_on = close_on.upper() if close_on else None
        self.partial_close_on = partial_close_on.upper() if partial_close_on else None
        self.garbage_on = garbage_on.upper() if garbage_on else None
        self.banner_delay = banner_delay
        self.no_read_after_data = no_read_after_data
        self.replies = {k.upper(): v for k, v in (replies or {}).items()}
        self.lines: list[bytes] = []
        self.auth_attempts: list[tuple[str, str, bool]] = []
        self.messages: list[tuple[str, list[str], bytes]] = []
        self.xclient_attrs: list[dict[str, str]] = []
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def _c(self) -> _Conn:
        return _CONN.get()

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        host, port = self._server.sockets[0].getsockname()[:2]
        return host, port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        for writer in list(self._writers):
            writer.transport.abort()
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        self._writers.add(writer)
        try:
            await self._session(reader, writer)
        except (OSError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        finally:
            self._writers.discard(writer)
            self._tasks.discard(task)
            writer.transport.abort()

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, text: str) -> None:
        writer.write(text.encode() + b"\r\n")
        await writer.drain()

    async def _reply(self, writer: asyncio.StreamWriter, verb: str, default: str) -> str:
        text = self.replies.get(verb, default)
        await self._send(writer, text)
        return text

    @staticmethod
    async def _readline(reader: asyncio.StreamReader) -> bytes:
        raw = await reader.readline()
        if not raw:
            raise ConnectionResetError
        return raw.rstrip(b"\r\n")

    async def _session(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        _CONN.set(_Conn())
        if self.banner_delay:
            await asyncio.sleep(self.banner_delay)
        await self._send(writer, f"{self.banner_code} fake.mta ESMTP")
        while True:
            line = await self._readline(reader)
            text = line.decode("latin-1")
            verb = text.split(" ", 1)[0].upper()
            self.lines.append(self._redact(verb, text, line))
            if verb == self.hang_on:
                await asyncio.Event().wait()
            if verb == self.close_on:
                return
            if verb == self.partial_close_on:
                writer.write(b"250-partial reply\r\n")
                await writer.drain()
                return
            if verb == self.garbage_on:
                await self._send(writer, "this is not a reply")
                continue
            if await self._dispatch(reader, writer, verb, text):
                return

    @staticmethod
    def _redact(verb: str, text: str, line: bytes) -> bytes:
        if verb != "AUTH":
            return line
        parts = text.split()
        return " ".join(parts[:2] + (["<auth payload>"] if len(parts) > 2 else [])).encode()

    def _reset_envelope(self) -> None:
        self._c.mail_from = ""
        self._c.rcpts = []
        if self._c.state in (MAIL, RCPT):
            self._c.state = GREETED

    async def _dispatch(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, verb: str, text: str
    ) -> bool:
        """Handle one command; return True when the connection is to be closed."""
        if verb in ("EHLO", "HELO"):
            await self._ehlo(writer, verb)
        elif verb == "XCLIENT":
            await self._xclient(writer, text)
        elif verb == "AUTH":
            await self._auth(reader, writer, text)
        elif verb == "MAIL":
            await self._mail(writer, text)
        elif verb == "RCPT":
            await self._rcpt(writer, text)
        elif verb == "DATA":
            await self._data(reader, writer)
        elif verb == "RSET":
            if _is_ok(await self._reply(writer, verb, "250 2.0.0 Ok")):
                self._reset_envelope()
        elif verb == "NOOP":
            await self._reply(writer, verb, "250 2.0.0 Ok")
        elif verb == "QUIT":
            await self._reply(writer, verb, "221 2.0.0 Bye")
            return True
        else:
            await self._reply(writer, verb, "502 5.5.2 Error: command not recognized")
        return False

    async def _ehlo(self, writer: asyncio.StreamWriter, verb: str) -> None:
        if verb in self.replies:
            reply = await self._reply(writer, verb, "")
        elif verb == "HELO":
            reply = await self._reply(writer, verb, "250 fake.mta")
        else:
            caps = ["SIZE 10240000", "8BITMIME", "AUTH PLAIN LOGIN"]
            if self.xclient:
                caps.append("XCLIENT NAME ADDR PORT")
            out = ["250-fake.mta"] + [f"250-{c}" for c in caps[:-1]] + [f"250 {caps[-1]}"]
            writer.write("\r\n".join(out).encode() + b"\r\n")
            await writer.drain()
            reply = out[0]
        if _is_ok(reply):
            self._c.mail_from, self._c.rcpts = "", []
            self._c.state = GREETED

    async def _xclient(self, writer: asyncio.StreamWriter, text: str) -> None:
        if not self.xclient:
            await self._reply(writer, "XCLIENT", "550 5.5.1 Error: command not implemented")
            return
        if self._c.state != GREETED:
            await self._reply(writer, "XCLIENT", "503 5.5.1 Error: send EHLO first")
            return
        attrs = dict(p.split("=", 1) for p in text.split()[1:] if "=" in p)
        reply = await self._reply(writer, "XCLIENT", "220 fake.mta ESMTP")
        if _is_ok(reply):
            if "NAME" in attrs:
                attrs["NAME"] = _xtext_decode(attrs["NAME"])
            self.xclient_attrs.append(attrs)
            # Postfix forgets the greeting: a fresh EHLO is required.
            self._c.state = NEW

    async def _mail(self, writer: asyncio.StreamWriter, text: str) -> None:
        if self._c.state == NEW:
            await self._reply(writer, "MAIL", "503 5.5.1 Error: send HELO/EHLO first")
            return
        if self._c.state != GREETED:
            await self._reply(writer, "MAIL", "503 5.5.1 Error: nested MAIL command")
            return
        match = _MAIL_RE.match(text)
        if match is None:
            await self._reply(writer, "MAIL", "501 5.5.4 Syntax: MAIL FROM:<address>")
            return
        if _is_ok(await self._reply(writer, "MAIL", "250 2.1.0 Ok")):
            self._c.mail_from = match.group(1).strip("<>")
            self._c.rcpts = []
            self._c.state = MAIL

    async def _rcpt(self, writer: asyncio.StreamWriter, text: str) -> None:
        if self._c.state in (NEW, GREETED):
            await self._reply(writer, "RCPT", "503 5.5.1 Error: need MAIL command")
            return
        match = _RCPT_RE.match(text)
        if match is None:
            await self._reply(writer, "RCPT", "501 5.5.4 Syntax: RCPT TO:<address>")
            return
        rcpt = match.group(1).strip("<>")
        default = (
            "550 5.1.1 User unknown"
            if rcpt.split("@")[0].lower() == "unknown"
            else "250 2.1.5 Ok"
        )
        if _is_ok(await self._reply(writer, "RCPT", default)):
            self._c.rcpts.append(rcpt)
            self._c.state = RCPT

    @staticmethod
    def _credentials_ok(user: bytes, password: bytes) -> bool:
        return user == b"test" and password == b"secret"

    async def _auth(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, text: str
    ) -> None:
        if "AUTH" in self.replies:
            await self._send(writer, self.replies["AUTH"])
            return
        parts = text.split()
        mech = parts[1].upper() if len(parts) > 1 else ""
        user = b""
        ok = False
        try:
            if mech == "PLAIN":
                payload = parts[2] if len(parts) > 2 else await self._prompt(reader, writer, "")
                fields = base64.b64decode(payload).split(b"\x00")
                if len(fields) == 3:
                    user = fields[1]
                    ok = self._credentials_ok(fields[1], fields[2])
            elif mech == "LOGIN":
                if len(parts) > 2:
                    user_b64 = parts[2]
                else:
                    user_b64 = await self._prompt(reader, writer, "VXNlcm5hbWU6")
                pass_b64 = await self._prompt(reader, writer, "UGFzc3dvcmQ6")
                user = base64.b64decode(user_b64)
                ok = self._credentials_ok(user, base64.b64decode(pass_b64))
        except ValueError:
            ok = False
        self.auth_attempts.append((mech, user.decode("latin-1"), ok))
        if ok:
            await self._send(writer, "235 2.7.0 Authentication successful")
        else:
            await self._send(writer, "535 5.7.8 Error: authentication failed")

    async def _prompt(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, challenge: str
    ) -> str:
        await self._send(writer, f"334 {challenge}".rstrip())
        line = await self._readline(reader)
        self.lines.append(b"<auth payload>")
        return line.decode("latin-1")

    async def _data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._c.state != RCPT:
            await self._reply(writer, "DATA", "503 5.5.1 Error: need RCPT command")
            return
        reply = await self._reply(writer, "DATA", "354 End data with <CR><LF>.<CR><LF>")
        if reply[:3] != "354":
            return
        if self.no_read_after_data:
            await asyncio.Event().wait()
        body = bytearray()
        while True:
            raw = await reader.readuntil(b"\r\n")
            if raw == b".\r\n":
                break
            body += raw[1:] if raw.startswith(b".") else raw
        if self.hang_on == "DATA_END":
            await asyncio.Event().wait()
        final = await self._reply(writer, "DATA_END", "250 2.0.0 Ok: queued as FAKE1")
        if _is_ok(final):
            self.messages.append((self._c.mail_from, list(self._c.rcpts), bytes(body)))
        self._c.mail_from, self._c.rcpts = "", []
        self._c.state = GREETED
