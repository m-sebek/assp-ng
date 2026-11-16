# SPDX-License-Identifier: GPL-3.0-or-later
"""SMTP AUTH passthrough helpers.

The MTA verifies credentials; the proxy only needs the username (rate limits,
logging). Passwords and raw payloads are decoded into locals only and are never
stored, logged or put into exception messages.
"""

from __future__ import annotations

import base64
import binascii
import re

MAX_USERNAME_BYTES = 256

_AUTH_VERB = re.compile(rb"([ \t]*AUTH)(?![A-Za-z0-9])", re.IGNORECASE)
_MECH_TOKEN = re.compile(rb"([ \t]+(?:PLAIN|LOGIN))(?=[ \t\r\n]|\Z)", re.IGNORECASE)
_BLANK = b" \t\r\n"


class AuthSyntaxError(ValueError):
    """Malformed AUTH exchange. Messages are fixed strings, never client data.

    Errors are always raised outside any ``except`` block so that no
    ``__context__`` or ``__cause__`` can carry client data.
    """


def _b64decode(text: str) -> bytes | None:
    """Strict base64 decode; None on failure (caller raises, to avoid context)."""
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None


def _checked_username(raw: bytes | None) -> str:
    if raw is None:
        raise AuthSyntaxError("invalid base64 in AUTH response")
    if not raw or len(raw) > MAX_USERNAME_BYTES:
        raise AuthSyntaxError("invalid AUTH username length")
    try:
        name: str | None = raw.decode("utf-8")
    except UnicodeDecodeError:
        name = None
    if name is None:
        raise AuthSyntaxError("invalid UTF-8 in AUTH username")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in name):
        raise AuthSyntaxError("control character in AUTH username")
    return name


def _username_from_b64(text: str) -> str:
    return _checked_username(_b64decode(text))


def _plain_username(text: str) -> str:
    decoded = _b64decode(text)
    if decoded is None:
        raise AuthSyntaxError("invalid base64 in AUTH response")
    fields = decoded.split(b"\x00")
    if len(fields) != 3:
        raise AuthSyntaxError("malformed AUTH PLAIN payload")
    return _checked_username(fields[1])


class AuthExchange:
    """Tracks one AUTH exchange and extracts the username."""

    __slots__ = ("_mechanism", "_done", "username", "cancelled")

    def __init__(self, mechanism: str, initial: str | None) -> None:
        mech = mechanism.upper()
        if not mechanism.isascii() or mech not in ("PLAIN", "LOGIN"):
            raise AuthSyntaxError("unsupported AUTH mechanism")
        self._mechanism = mech
        self._done = False
        self.username: str | None = None
        self.cancelled = False
        if initial is not None:
            self.on_client_line("" if initial == "=" else initial)

    def on_client_line(self, line: str) -> None:
        """Feed one client response line (without line ending)."""
        if self._done:
            return
        if line.strip() == "*":
            self.cancelled = True
            self._done = True
            return
        if self.username is None:
            # Fail closed: any error ends the exchange, so a later line (the
            # password) is never decoded as a username.
            self._done = True
            if self._mechanism == "PLAIN":
                self.username = _plain_username(line)
            else:
                self.username = _username_from_b64(line)
                self._done = False
        else:
            # LOGIN password step: ignored entirely, never decoded.
            self._done = True

    def __repr__(self) -> str:
        return (
            f"AuthExchange(mechanism={self._mechanism!r}, "
            f"username_known={self.username is not None}, cancelled={self.cancelled})"
        )


def redact_auth(line: bytes, in_exchange: bool) -> bytes:
    """Return a log-safe version of a client line.

    In an exchange everything is redacted. Otherwise an AUTH line keeps only
    the verb and a PLAIN or LOGIN mechanism token (the only mechanisms
    forwarded); any other token, being possibly a payload, is redacted too.
    """
    if in_exchange:
        return b"<redacted>"
    verb = _AUTH_VERB.match(line)
    if verb is None:
        return line
    rest = line[verb.end():]
    if not rest.strip(_BLANK):
        return line
    mech = _MECH_TOKEN.match(rest)
    if mech is None:
        return verb.group(1) + b" <redacted>"
    if not rest[mech.end():].strip(_BLANK):
        return line
    return verb.group(1) + mech.group(1) + b" <redacted>"
