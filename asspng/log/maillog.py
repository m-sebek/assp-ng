# SPDX-License-Identifier: GPL-3.0-or-later
"""The key=value maillog line (spec 8.5)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

MAILLOG_LOGGER = "asspng.maillog"


@dataclass
class MaillogRecord:
    ts: datetime
    instance: str
    session: str
    txn: int | None
    listener: str
    ip: str
    ptr: str
    helo: str
    tls: str
    auth: str
    mail_from: str
    rcpts: list[str]
    size: int | None
    score: int | None
    result: str
    mta: str
    duration_s: float


def _is_control(ch: str) -> bool:
    return ord(ch) < 0x20 or ord(ch) == 0x7F


def _value(text: str) -> str:
    """Encode one value: `-` if empty, control chars escaped, quoted if needed."""
    if not text:
        return "-"
    quote = any(c in ' "' or _is_control(c) for c in text)
    out: list[str] = []
    for ch in text:
        if _is_control(ch):
            out.append(f"\\x{ord(ch):02x}")
        elif quote and ch in '\\"':
            out.append("\\" + ch)
        else:
            out.append(ch)
    body = "".join(out)
    return f'"{body}"' if quote else body


def _addr(addr: str) -> str:
    return addr if addr == "<>" else f"<{addr}>"


def format_maillog(rec: MaillogRecord) -> str:
    """Return one maillog line (no line ending); never contains a raw control char."""
    # Addresses are encoded as a whole so `<a b>` is quoted like any other value.
    mail_from = _value(_addr(rec.mail_from)) if rec.mail_from else "-"
    rcpt = _value(",".join(_addr(r) for r in rec.rcpts)) if rec.rcpts else "-"
    fields = [
        ("s", _value(rec.session)),
        ("t", "-" if rec.txn is None else str(rec.txn)),
        ("l", _value(rec.listener)),
        ("ip", _value(rec.ip)),
        ("ptr", _value(rec.ptr)),
        ("helo", _value(rec.helo)),
        ("tls", _value(rec.tls)),
        ("auth", _value(rec.auth)),
        ("from", mail_from),
        ("rcpt", rcpt),
        ("size", "-" if rec.size is None else str(rec.size)),
        ("score", "-" if rec.score is None else str(rec.score)),
        ("result", _value(rec.result)),
        ("mta", _value(rec.mta)),
        ("dur", f"{rec.duration_s:.2f}s"),
    ]
    head = f"{rec.ts.isoformat(timespec='seconds')} {_value(rec.instance)}"
    return head + " " + " ".join(f"{k}={v}" for k, v in fields)


def log_maillog(rec: MaillogRecord) -> None:
    """Format and log ``rec`` at INFO on the maillog logger."""
    logging.getLogger(MAILLOG_LOGGER).info("%s", format_maillog(rec))
