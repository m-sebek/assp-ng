# SPDX-License-Identifier: GPL-3.0-or-later
"""EHLO capability filter: show clients only an allow-list of the MTA's capabilities."""

from asspng.smtp.replies import Reply

_KEPT = frozenset({"SIZE", "8BITMIME", "SMTPUTF8", "ENHANCEDSTATUSCODES", "DSN"})


def _keyword(line: str) -> str:
    parts = line.split(None, 1)
    return parts[0].upper() if parts else ""


def _mta_size(line: str) -> int:
    """The MTA's advertised limit; 0 when absent, non-numeric or unlimited."""
    parts = line.split()
    if len(parts) > 1 and parts[1].isascii() and parts[1].isdigit():
        return int(parts[1])
    return 0


def filter_ehlo(
    mta: Reply,
    *,
    hostname: str,
    offer_starttls: bool,
    auth_allowed: bool,
    max_size: int,
) -> Reply:
    """Rewrite the MTA's EHLO reply into the capability list shown to the client."""
    if not mta.is_positive:
        return mta
    lines = [hostname]
    mta_has_auth = False
    for line in mta.lines[1:]:
        keyword = _keyword(line)
        if keyword == "SIZE":
            lines.append(f"SIZE {min(_mta_size(line) or max_size, max_size)}")
        elif keyword in _KEPT:
            lines.append(line)
        elif keyword == "AUTH":
            mta_has_auth = True
    if offer_starttls:
        lines.append("STARTTLS")
    if auth_allowed and mta_has_auth:
        lines.append("AUTH PLAIN LOGIN")
    return Reply(mta.code, tuple(lines))
