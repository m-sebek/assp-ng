# SPDX-License-Identifier: GPL-3.0-or-later
"""Session helpers that need no session state: settings, reply formatting, maillog records."""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Collection
from datetime import datetime

from asspng.checks.base import SessionInfo, TransactionInfo
from asspng.config.model import ConfigSnapshot
from asspng.log.maillog import MaillogRecord
from asspng.net.dns import PtrResult
from asspng.smtp.commands import CommandSyntaxError, parse_command
from asspng.smtp.replies import Reply

_CONTROL_TO_SPACE = {code: " " for code in (*range(0x20), 0x7F)}
# Well-known SMTP and extension verbs that may have no handler (they are answered locally
# and never forwarded); a client line with one of them is still logged as a command.
_KNOWN_VERBS = frozenset({
    "VRFY", "EXPN", "HELP", "DATA", "BDAT", "XCLIENT", "XFORWARD", "ETRN", "TURN", "ATRN",
    "SEND", "SOML", "SAML", "VERB",
})


def config_int(config: ConfigSnapshot, key: str) -> int:
    """A SYSTEM setting that must be an integer (durations are integer seconds)."""
    value = config.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"setting {key} is not an integer")
    return value


def config_seconds(config: ConfigSnapshot, key: str) -> float:
    """A SYSTEM setting that must be a number, as float seconds."""
    value = config.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"setting {key} is not a number")
    return float(value)


def config_text(config: ConfigSnapshot, key: str) -> str:
    return str(config.get(key))


def is_known_command(line: bytes, handled: Collection[str]) -> bool:
    """Whether ``line`` parses as a command with a handled or well-known verb.

    Any other client line may be an AUTH payload sent outside an exchange (pipelined, or
    after a refusal), so the session logs it by its length only.
    """
    try:
        verb = parse_command(line).verb
    except CommandSyntaxError:
        return False
    return verb in handled or verb in _KNOWN_VERBS


def sanitized_text(text: str) -> str:
    """``text`` with every control character replaced by a space."""
    return text.translate(_CONTROL_TO_SPACE)


def sanitized(reply: Reply) -> Reply:
    """``reply`` with every control character in its text replaced by a space."""
    return Reply(reply.code, tuple(sanitized_text(text) for text in reply.lines))


def wire_lines(reply: Reply) -> list[str]:
    """The reply's lines as they appear on the wire, without line endings."""
    lines = reply.lines or ("",)
    last = len(lines) - 1
    return [f"{reply.code}{' ' if i == last else '-'}{text}" for i, text in enumerate(lines)]


def tls_version(writer: asyncio.StreamWriter) -> str | None:
    """The negotiated TLS version of the client connection; None without TLS."""
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    version: str | None = ssl_object.version()
    return version


def session_record(
    info: SessionInfo,
    ptr: PtrResult | None,
    *,
    instance: str,
    result: str,
    mta: str,
    started: float,
    now: float,
) -> MaillogRecord:
    """The maillog record of a session that wrote no per-message record."""
    return MaillogRecord(
        ts=datetime.fromtimestamp(now).astimezone(),
        instance=instance,
        session=info.session_id,
        txn=None,
        listener=info.listener.name,
        ip=str(info.client_ip),
        ptr=(ptr.name or "") if ptr is not None else "",
        helo=info.helo or "",
        tls=info.tls_version or "",
        auth=info.auth_user or "",
        mail_from="",
        rcpts=[],
        size=None,
        score=None,
        result=result,
        mta=mta,
        duration_s=max(0.0, now - started),
    )


def message_record(
    info: SessionInfo,
    ptr: PtrResult | None,
    txn: TransactionInfo,
    *,
    instance: str,
    result: str,
    mta: str,
    size: int,
    started: float,
    now: float,
) -> MaillogRecord:
    """The maillog record of one message (spec 8.5); ``size`` is the received size."""
    record = session_record(info, ptr, instance=instance, result=result, mta=mta,
                            started=started, now=now)
    return dataclasses.replace(
        record,
        txn=txn.number,
        mail_from="<>" if txn.mail_from is None else str(txn.mail_from),
        rcpts=[str(rcpt) for rcpt in txn.recipients],
        size=size,
        score=txn.score,
    )
