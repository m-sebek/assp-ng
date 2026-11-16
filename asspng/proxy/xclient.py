# SPDX-License-Identifier: GPL-3.0-or-later
"""The Postfix XCLIENT command line (see Postfix XCLIENT_README)."""

from asspng.net.ipnet import IPAddress


def _xtext(value: str) -> str:
    """Encode per RFC 3461 xtext: bytes outside 0x21-0x7E, ``+`` and ``=`` become ``+HH``."""
    out: list[str] = []
    for byte in value.encode("utf-8"):
        if 0x21 <= byte <= 0x7E and byte not in (0x2B, 0x3D):
            out.append(chr(byte))
        else:
            out.append(f"+{byte:02X}")
    return "".join(out)


def format_xclient(addr: IPAddress, port: int, name: str) -> bytes:
    """Build ``XCLIENT ADDR=... PORT=... NAME=...`` including the CRLF."""
    addr_text = f"IPV6:{addr}" if addr.version == 6 else str(addr)
    return f"XCLIENT ADDR={addr_text} PORT={port} NAME={_xtext(name)}\r\n".encode("ascii")
