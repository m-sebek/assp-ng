# SPDX-License-Identifier: GPL-3.0-or-later
"""Credential redaction for log messages.

``redact_text`` applies, per line:

(a) the line-start rule of ``asspng.proxy.auth.redact_auth`` (R19): a line starting, after
    optional whitespace, with the word AUTH keeps only a following PLAIN or LOGIN token;
    everything after it becomes ``<redacted>``;
(b) if (a) changed nothing, a mid-line rule (R20): every whole-word, case-insensitive AUTH
    followed by whitespace, an optional PLAIN/LOGIN token and a payload token has only that
    payload token replaced by ``<redacted>``. The rest of the line is untouched, so
    client-controlled values in a maillog line cannot blank out following fields.

Application code must not phrase its own messages as "AUTH <word>" (write "authentication"
instead), and must pass raw client lines through ``asspng.proxy.auth.redact_auth`` or log
them with ``extra={"auth": True}``.
"""

from __future__ import annotations

import logging
import re

_AUTH_VERB = re.compile(r"([ \t]*AUTH)(?![A-Za-z0-9])", re.IGNORECASE)
_MECH_TOKEN = re.compile(r"([ \t]+(?:PLAIN|LOGIN))(?=[ \t\r\n]|\Z)", re.IGNORECASE)
_MID_AUTH = re.compile(
    r"(?<![A-Za-z0-9])(AUTH[ \t]+(?:(?:PLAIN|LOGIN)[ \t]+)?)"
    r"(?!(?:PLAIN|LOGIN)(?![A-Za-z0-9]))[^\s\"\\]+",
    re.IGNORECASE,
)
_BLANK = " \t\r\n"
_STANDARD_ATTRS = frozenset(
    logging.LogRecord("x", 0, "", 0, "", None, None).__dict__
) | {"message", "asctime"}
_FORMATTER = logging.Formatter()


def _redact_line(line: str) -> str:
    verb = _AUTH_VERB.match(line)
    if verb is None:
        return line
    rest = line[verb.end():]
    if not rest.strip(_BLANK):
        return line
    mech = _MECH_TOKEN.match(rest)
    if mech is None:
        return verb.group(1) + " <redacted>"
    if not rest[mech.end():].strip(_BLANK):
        return line
    return verb.group(1) + mech.group(1) + " <redacted>"


def _redact_any(line: str) -> str:
    changed = _redact_line(line)
    if changed != line:
        return changed
    return _MID_AUTH.sub(lambda m: m.group(1) + "<redacted>", line)


def redact_text(text: str) -> str:
    """Redact AUTH payloads on every line of ``text``."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    for raw in lines:
        body = raw.rstrip("\r\n")
        out.append(_redact_any(body) + raw[len(body):])
    return "".join(out)


class RedactionFilter(logging.Filter):
    """Rewrite records in place so no AUTH payload reaches any handler.

    Never raises: logging's filter step is outside its error protection.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        masked = bool(getattr(record, "auth", False))
        # Non-standard attributes become journald fields; drop them all.
        for name in [k for k in record.__dict__ if k not in _STANDARD_ATTRS]:
            delattr(record, name)
        try:
            if masked:
                record.msg = "<redacted>"
                record.args = None
            else:
                text = record.getMessage()
                redacted = redact_text(text)
                if redacted != text:
                    record.msg = redacted
                    record.args = None
        except Exception:
            record.msg = "<unformattable log message>"
            record.args = None
        try:
            if record.exc_info:
                formatted = _FORMATTER.formatException(record.exc_info)
                record.exc_text = redact_text(formatted)
                record.exc_info = None
            elif record.exc_text:
                record.exc_text = redact_text(record.exc_text)
            if record.stack_info:
                record.stack_info = redact_text(record.stack_info)
        except Exception:
            record.exc_text = "<unformattable exception>"
            record.exc_info = None
        return True
