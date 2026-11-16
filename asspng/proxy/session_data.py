# SPDX-License-Identifier: GPL-3.0-or-later
"""DATA of a session (spec 4.7, 4.8, 4.9): buffering, HEADER and BODY checks, ASSP-NG's own
header fields and delivery to the MTA.

``on_data`` is a module function taking the ``Session``; ``Session._command_handlers``
registers it, like the envelope handlers. It reads and changes the session's package-private
attributes and uses its helpers, so only the session's command loop may call it.

ASSP-NG answers 354 itself and reads the whole message into a ``MessageBuffer`` before the
MTA sees anything of it. ``DataReceiver`` (client side) and the ``Stuffer`` in
``Backend.data`` (MTA side) leave exactly one end of data, which neutralises SMTP smuggling.
PIPELINING is not offered: bytes a client sends after the end of data in the same read are
discarded unanswered (only their count is logged). The message is still handled as usual,
and after its reply the leftover counts as one protocol error.

Every message that reached DATA gets its own maillog record: accepted, accepted-test,
rejected, tempfailed, disconnected or timeout. The session then writes no session record.
Message bodies are never tapped or logged; a debug rule with ``--headers`` taps the header
lines as they are sent to the MTA.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from asspng.checks.base import CheckContext, Phase, TransactionInfo
from asspng.checks.engine import R_REJECT, Decision, Outcome
from asspng.checks.engine import R_TEMPFAIL as R_CHECK_TEMPFAIL
from asspng.proxy.backend import BackendClosed, BackendError
from asspng.proxy.buffer import MessageBuffer
from asspng.proxy.session_util import message_record, sanitized_text
from asspng.smtp.commands import Command
from asspng.smtp.datacodec import DataReceiver
from asspng.smtp.headers import format_field, split_header, strip_fields
from asspng.smtp.replies import (
    R_BAD_ARG,
    R_BAD_SEQUENCE,
    R_DATA_GO,
    R_IDLE,
    R_NO_RCPT,
    R_SIZE,
    R_TEMPFAIL,
    R_TEMPFAIL_CMD,
    Reply,
)

if TYPE_CHECKING:
    from asspng.proxy.session import Session

_log = logging.getLogger(__name__)

# The header block is copied and edited in memory, outside the buffer budget, so it must end
# within this many bytes (256 KiB: 500 sessions with two copies stay well below MemoryMax).
# A longer one is refused with R_HEADER_TOO_LARGE.
HEADER_LIMIT = 256 * 1024
R_HEADER_TOO_LARGE = Reply.of(552, "5.3.4 Message header too large")

_READ_SIZE = 65536
_OWN_PREFIX = "X-ASSP-NG-"
_MAX_LINE = 998  # RFC 5322 line length limit, without the CRLF
_SUBJECT = re.compile(rb"^(subject:)([ \t]*)", re.IGNORECASE | re.MULTILINE)
# Header fields whose values are credentials: the debug log shows only their names.
_CREDENTIAL_FIELD = re.compile(
    rb"^(authorization|proxy-authorization|cookie)[ \t]*:", re.IGNORECASE)
# Per-message health events (consumed by the health endpoint) by maillog result.
_HEALTH_EVENTS = {"accepted": "accepted", "accepted-test": "accepted",
                  "rejected": "rejected", "tempfailed": "tempfailed"}


class _SpoolReadError(Exception):
    """Reading the stored message failed while the MTA was receiving it."""


class _Sink:
    """The ``DataReceiver`` sink: stores the decoded message in the buffer.

    After a storage failure it only counts, so the end of data is still found and the
    client stream stays in sync.
    """

    def __init__(self, session_id: str, buffer: MessageBuffer) -> None:
        self._session_id = session_id
        self._buffer = buffer
        self.size = 0  # every decoded byte, stored or not
        self.failed = False

    def __call__(self, data: bytes) -> None:
        self.size += len(data)
        if self.failed:
            return
        try:
            self._buffer.write(data)
        except (OSError, ValueError) as exc:  # e.g. a full disk or a missing spool directory
            self.failed = True
            _log.warning("s=%s cannot store the message: %s; discarding the rest",
                         self._session_id, type(exc).__name__)


async def on_data(session: Session, command: Command) -> None:
    """Receive, check and deliver one message; the buffer is always closed."""
    if await session._refused_by_state("DATA"):
        return
    txn = session._txn
    if command.arg:
        await session._protocol_error(R_BAD_ARG)
        return
    if txn is None:
        await session._protocol_error(R_BAD_SEQUENCE)
        return
    if not txn.recipients:  # every recipient was refused: not a protocol error
        await session._reply(R_NO_RCPT)
        return
    buffer = MessageBuffer(session._deps.budget, Path(session._text("paths.spool")),
                           session._int("buffer.memory_per_message"),
                           session._int("max_message_size"))
    try:
        await _handle_message(session, txn, buffer)
    finally:
        txn.message = None
        buffer.close()


async def _handle_message(session: Session, txn: TransactionInfo, buffer: MessageBuffer
                          ) -> None:
    await session._reply(R_DATA_GO)  # nothing is sent to the MTA yet
    sink = _Sink(session.id, buffer)
    receiver = DataReceiver(sink)
    ended = await _receive(session, receiver)
    if ended is not None:  # the MTA never saw DATA: closing the backend is enough
        _log_message(session, txn, ended, sink.size)
        if ended == "timeout":
            await session._finish("timeout", R_IDLE)
        else:
            session._end("disconnected")
        return
    if receiver.leftover:
        _log.warning("s=%s discarded %d bytes sent after the end of data",
                     session.id, len(receiver.leftover))
    await _process(session, txn, buffer, sink)
    if receiver.leftover and not session._closing:
        await session._protocol_error(None)  # after the message's reply, none of its own


async def _process(session: Session, txn: TransactionInfo, buffer: MessageBuffer, sink: _Sink
                   ) -> None:
    """Refuse, or check and deliver, a completely received message."""
    if sink.size > session._int("max_message_size"):
        await _refuse(session, txn, "rejected", R_SIZE, sink.size)
        return
    read = None if sink.failed else _read_header(session, buffer)
    if read is None:
        await _refuse(session, txn, "tempfailed", R_TEMPFAIL_CMD, sink.size)
        return
    header, complete = read
    if not complete:
        await _refuse(session, txn, "rejected", R_HEADER_TOO_LARGE, sink.size)
        return
    txn.message = buffer
    decision = await _run_checks(session)
    if decision.outcome is Outcome.REJECT:
        await _refuse(session, txn, "rejected", decision.reply or R_REJECT, sink.size)
    elif decision.outcome is Outcome.TEMPFAIL:
        await _refuse(session, txn, "tempfailed", decision.reply or R_CHECK_TEMPFAIL, sink.size)
    else:
        await _deliver(session, txn, buffer, _outgoing_head(session, txn, header), len(header),
                       sink.size)


async def _receive(session: Session, receiver: DataReceiver) -> str | None:
    """Feed the client's data to ``receiver`` up to the end of data.

    Returns None once the end of data was found, otherwise the maillog result:
    ``timeout`` (a data block or the whole transfer took too long) or ``disconnected``.
    """
    reader = session._reader
    block_s = session._seconds("timeouts.data_block")
    try:
        async with asyncio.timeout(session._seconds("timeouts.data_total")):
            while True:
                async with asyncio.timeout(block_s):
                    chunk = await reader.read(_READ_SIZE)
                if not chunk:
                    return "disconnected"
                if receiver.feed(chunk):
                    return None
    except TimeoutError:
        return "timeout"
    except OSError:  # the connection was reset
        return "disconnected"


def _read_header(session: Session, buffer: MessageBuffer) -> tuple[bytes, bool] | None:
    """The stored message's header block (``split_header``) and whether it ended within
    ``HEADER_LIMIT`` bytes; None when the message cannot be read."""
    try:
        head = buffer.read_head(HEADER_LIMIT)
    except (OSError, ValueError) as exc:
        _log.warning("s=%s cannot read the stored message: %s", session.id, type(exc).__name__)
        return None
    header, body_start = split_header(head)
    # Without an empty line the whole head is the header: complete only if it is all there is.
    return header, body_start != len(header) or buffer.size == len(head)


async def _run_checks(session: Session) -> Decision:
    engine = session._deps.engine
    decision = await engine.run_phase(Phase.HEADER, session._check_context())
    if decision.outcome is Outcome.CONTINUE:
        decision = await engine.run_phase(Phase.BODY, session._check_context())
    return decision


async def _refuse(session: Session, txn: TransactionInfo, result: str, reply: Reply,
                  size: int) -> None:
    """Log the undelivered message, answer the client, then end the transaction at the MTA
    (it has not seen DATA) with RSET (spec 4.7). A 421 ends the session instead."""
    _log_message(session, txn, result, size)
    session._reset_transaction()
    await session._refuse(reply)
    await _rset_backend(session)


async def _rset_backend(session: Session) -> None:
    """End the MTA's transaction after the client got its reply; a lost backend ends the
    session (``BackendError`` reaches the command loop), the maillog record stays."""
    if not session._closing:
        await session._forward(b"RSET")


# --- header fields -------------------------------------------------------------------------


def _outgoing_head(session: Session, txn: TransactionInfo, header: bytes) -> bytes:
    """ASSP-NG's fields, then the client's header without X-ASSP-NG-* fields and, in the
    warning band, with the Subject tagged."""
    ctx = session._check_context()
    header = _without_leading_continuations(strip_fields(header, _OWN_PREFIX))
    tag = sanitized_text(str(ctx.setting("scoring.warn_subject_tag"))).strip()
    if txn.warn and tag:
        header = _tag_subject(header, tag)
    return _own_fields(session, txn, ctx) + header


def _without_leading_continuations(header: bytes) -> bytes:
    """``header`` without the continuation lines before its first field. They are invalid
    and would otherwise fold onto ASSP-NG's last own field."""
    lines = header.splitlines(keepends=True)
    first = next((i for i, line in enumerate(lines) if not line.startswith((b" ", b"\t"))),
                 len(lines))
    return b"".join(lines[first:])


def _own_fields(session: Session, txn: TransactionInfo, ctx: CheckContext) -> bytes:
    """The fields of spec 4.8, in the order of its table."""
    fields = [_field("X-ASSP-NG-ID", f"{session._text('instance')}-{session.id}-{txn.number}")]
    if txn.score != 0 and ctx.setting("scoring.add_header"):
        # A reason note is "<check name>: <reason>".
        details = "; ".join(f"{note.split(':', 1)[0]}={points}" for note, points in txn.reasons)
        fields.append(_field("X-ASSP-NG-Score", f"{txn.score} ({details})"))
    if txn.warn:
        warn = ctx.setting("scoring.warn")
        fields.append(_field("X-ASSP-NG-Warning", f"score {txn.score} above warning level {warn}"))
    if txn.would_reject:
        fields.append(_field("X-ASSP-NG-Test", "would reject: " + "; ".join(txn.would_reject)))
    return b"".join(fields)


def _field(name: str, value: str) -> bytes:
    """One header line. Control characters become spaces, so no CR or LF taken from a check
    reason can start another field, and the value is cut to the line length limit."""
    encoded = sanitized_text(value).encode("utf-8")[:_MAX_LINE - len(name) - 2]
    return format_field(name, encoded.decode("utf-8", "ignore"))


def _tag_subject(header: bytes, tag: str) -> bytes:
    """Prefix the first Subject field's value with ``tag``; its folding and encoded words
    stay as they are."""
    match = _SUBJECT.search(header)
    if match is None:
        return header
    name, blanks = match.groups()
    return (header[:match.start()] + name + (blanks or b" ") + tag.encode("utf-8") + b" "
            + header[match.end():])


# --- delivery ------------------------------------------------------------------------------


async def _deliver(session: Session, txn: TransactionInfo, buffer: MessageBuffer, head: bytes,
                   body_start: int, size: int) -> None:
    """Send the message to the MTA and relay its final (or non-354) reply."""
    backend = session._backend
    if backend is None:
        raise BackendClosed("no backend connection")
    session._tap.line("P>M", "DATA")
    try:
        reply = await backend.data(_content(session, head, buffer, body_start),
                                   session._seconds("timeouts.backend_command"),
                                   session._seconds("timeouts.backend_final"))
    except BackendError:
        _log_message(session, txn, "tempfailed", size)
        raise  # the command loop answers 421 and closes
    except _SpoolReadError as exc:
        _log.warning("s=%s cannot read the stored message: %s", session.id, exc)
        _log_message(session, txn, "tempfailed", size)
        await session._finish("tempfailed", R_TEMPFAIL)  # the MTA holds part of a message
        return
    session._note_mta(reply)
    accepted = 200 <= reply.code < 300
    if accepted:
        result = "accepted-test" if txn.would_reject else "accepted"
    else:
        result = "tempfailed" if reply.is_temporary else "rejected"
    _log_message(session, txn, result, size, session._last_mta)
    if accepted:
        session._info.messages += 1
    session._reset_transaction()
    await session._reply(reply)
    if not accepted:
        await _rset_backend(session)  # after a refused DATA the MTA keeps the transaction


def _content(session: Session, head: bytes, buffer: MessageBuffer, body_start: int
             ) -> Iterator[bytes]:
    """The message for the MTA: ``head``, then the stored message from ``body_start``.

    It runs while the MTA receives the message, so the header lines are tapped only after
    the MTA accepted DATA.
    """
    if session._tap.headers:
        secret_field = False
        for line in head.split(b"\r\n")[:-1]:
            if line[:1] not in (b" ", b"\t"):  # a folded continuation belongs to its field
                match = _CREDENTIAL_FIELD.match(line)
                secret_field = match is not None
                if match is not None:
                    line = line[:match.end()] + b" <redacted>"
            elif secret_field:
                line = b" <redacted>"
            session._tap.line("P>M", session._redacted(line))
    yield head
    try:
        yield from buffer.iter_chunks(body_start)
    except (OSError, ValueError) as exc:
        raise _SpoolReadError(type(exc).__name__) from exc


def _log_message(session: Session, txn: TransactionInfo, result: str, size: int,
                 mta: str = "-") -> None:
    """Write the message's maillog record (no session record follows) and count it."""
    session._txn_logged = True
    deps = session._deps
    try:
        deps.maillog(message_record(
            session._info, session._ptr, txn, instance=session._text("instance"),
            result=result, mta=mta, size=size, started=session._started, now=deps.clock()))
    except Exception as exc:
        _log.warning("s=%s cannot write the message record: %s", session.id,
                     type(exc).__name__)
    event = _HEALTH_EVENTS.get(result)
    if event is None:
        return
    try:
        deps.health.record(event)
    except Exception as exc:
        _log.warning("s=%s cannot count the message: %s", session.id, type(exc).__name__)
