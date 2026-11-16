# SPDX-License-Identifier: GPL-3.0-or-later
"""Header block utilities for decoded message content (every line ends with CRLF)."""

import re

MAX_VALUE_BYTES = 998

# RFC 5322 field name: printable US-ASCII except colon.
_FIELD_NAME = re.compile(r"[!-9;-~]+")


def split_header(data: bytes) -> tuple[bytes, int]:
    """Return the header block and the offset where the body starts.

    The header block includes the CRLF that ends its last field; the offset points past
    the empty line. Without an empty line, all of ``data`` is the header.
    """
    if data.startswith(b"\r\n"):
        return b"", 2
    end = data.find(b"\r\n\r\n")
    if end < 0:
        return data, len(data)
    return data[:end + 2], end + 4


def strip_fields(header: bytes, prefix: str) -> bytes:
    """Remove every field whose name starts with ``prefix`` (case-insensitive).

    A field's continuation lines (starting with a space or a tab) are removed with it.
    """
    wanted = prefix.encode("ascii").lower()
    kept: list[bytes] = []
    dropping = False
    for line in header.splitlines(keepends=True):
        if not line.startswith((b" ", b"\t")):
            name, colon, _ = line.partition(b":")
            dropping = bool(colon) and name.lower().startswith(wanted)
        if not dropping:
            kept.append(line)
    return b"".join(kept)


def format_field(name: str, value: str) -> bytes:
    """Return ``name: value`` as one header line ending with CRLF.

    Raises ``ValueError`` for an invalid name, a value containing CR or LF, or a value
    longer than ``MAX_VALUE_BYTES`` bytes, so that no header can be injected.
    """
    if not _FIELD_NAME.fullmatch(name):
        raise ValueError("invalid header field name")
    if "\r" in value or "\n" in value:
        raise ValueError("header field value must not contain CR or LF")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_VALUE_BYTES:
        raise ValueError(f"header field value exceeds {MAX_VALUE_BYTES} bytes")
    return name.encode("ascii") + b": " + encoded + b"\r\n"
