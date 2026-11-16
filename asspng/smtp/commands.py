# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse SMTP command lines into typed values."""

from __future__ import annotations

import re
from dataclasses import dataclass

from asspng.smtp.address import (
    Address,
    AddressError,
    AtSignInLocalPart,
    parse_path,
    split_path,
)

_VERB_RE = re.compile(r"[A-Za-z]{1,32}")
_PARAM_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
_FROM_RE = re.compile(r"FROM:[ \t]*", re.IGNORECASE)
_TO_RE = re.compile(r"TO:[ \t]*", re.IGNORECASE)


class CommandSyntaxError(ValueError):
    """Raised for a malformed command line or command argument."""


class CommandArgumentError(CommandSyntaxError):
    """The command is well formed but its argument is not (answered with 501)."""


@dataclass(frozen=True)
class Command:
    verb: str  # uppercased
    arg: str


@dataclass(frozen=True)
class MailFrom:
    path: Address | None
    params: dict[str, str | None]


@dataclass(frozen=True)
class RcptTo:
    path: Address
    params: dict[str, str | None]


def parse_command(line: bytes) -> Command:
    """Decode a raw command line (UTF-8) into verb and argument."""
    try:
        text: str | None = line.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        # Raised outside the except block so no context keeps the raw line.
        raise CommandSyntaxError("command is not valid UTF-8")
    text = text.rstrip("\r\n").strip(" \t")
    if "\0" in text or "\r" in text or "\n" in text:
        raise CommandSyntaxError("control character in command")
    parts = re.split(r"[ \t]+", text, maxsplit=1)
    verb, arg = parts[0], (parts[1] if len(parts) > 1 else "")
    if not _VERB_RE.fullmatch(verb):
        raise CommandSyntaxError("invalid command verb")
    return Command(verb.upper(), arg)


def _parse_params(text: str, max_params: int) -> dict[str, str | None]:
    params: dict[str, str | None] = {}
    for token in text.split():
        key, eq, value = token.partition("=")
        if not _PARAM_KEY_RE.fullmatch(key) or (eq and not value):
            raise CommandSyntaxError("invalid parameter")
        key = key.upper()
        if key in params:
            raise CommandSyntaxError("duplicate parameter")
        if len(params) >= max_params:
            raise CommandSyntaxError("too many parameters")
        params[key] = value if eq else None
    return params


def _parse_path_and_params(
    arg: str, prefix: re.Pattern[str], max_params: int
) -> tuple[Address | None, dict[str, str | None]]:
    m = prefix.match(arg)
    if m is None:
        raise CommandSyntaxError("bad syntax")
    rest = arg[m.end():]
    try:
        if rest.startswith("<"):
            path_text, rest = split_path(rest)
            if rest and rest[0] not in " \t":
                raise CommandSyntaxError("garbage after path")
        else:
            # Lenient, like Postfix: accept an address without angle brackets.
            path_text, _, rest = rest.partition(" ")
            if not path_text or path_text.startswith("<"):
                raise CommandSyntaxError("missing path")
            path_text = f"<{path_text}>"
        path = parse_path(path_text)
    except AtSignInLocalPart as exc:
        raise CommandArgumentError(f"bad address: {exc}") from exc
    except AddressError as exc:
        raise CommandSyntaxError(f"bad address: {exc}") from exc
    return path, _parse_params(rest, max_params)


def parse_mail_from(arg: str, max_params: int = 10) -> MailFrom:
    """Parse the argument of MAIL: ``FROM:<path> [PARAM[=VALUE] ...]``."""
    path, params = _parse_path_and_params(arg, _FROM_RE, max_params)
    return MailFrom(path, params)


def parse_rcpt_to(arg: str, max_params: int = 10) -> RcptTo:
    """Parse the argument of RCPT: ``TO:<path> [PARAM[=VALUE] ...]``."""
    path, params = _parse_path_and_params(arg, _TO_RE, max_params)
    if path is None:
        raise CommandSyntaxError("null path not allowed in RCPT")
    return RcptTo(path, params)
