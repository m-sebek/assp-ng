# SPDX-License-Identifier: GPL-3.0-or-later
"""Smuggling-safe DATA decoding (client side) and encoding (MTA side).

The client's message is decoded with one strict rule set and re-encoded so that every
line ends with CRLF and every line starting with ``.`` is dot-stuffed. The MTA therefore
sees exactly one end of data, the one appended by ``Stuffer.finish``, whatever it accepts
as a line break.
"""

from collections.abc import Callable

# A physical line longer than this is passed on in pieces instead of being held whole.
MAX_HELD_LINE = 8192


def _to_crlf(data: bytes) -> bytes:
    """Turn every CRLF, bare CR and bare LF into CRLF."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")


class DataReceiver:
    """Decode the client's DATA stream up to the end-of-data line.

    Physical lines end only at CRLF. A physical line that is exactly ``.`` ends the data;
    a physical line starting with ``.`` loses that one dot. A bare CR or LF inside a
    physical line becomes a CRLF line break; the logical lines it creates are never
    unstuffed and never end the data. ``sink`` receives the decoded content, in which
    every line ends with CRLF.
    """

    def __init__(self, sink: Callable[[bytes], None]) -> None:
        self._sink = sink
        # Unprocessed bytes: the part of the current physical line not yet passed on. It
        # never contains a CRLF and is at most MAX_HELD_LINE bytes between calls.
        self._buf = bytearray()
        # True when _buf[0] is the first byte of a physical line (nothing of it passed on).
        self._line_start = True
        self._done = False
        self.leftover = b""

    def feed(self, chunk: bytes) -> bool:
        """Process ``chunk``; return ``True`` once the end of data has been seen.

        After that, ``leftover`` holds the bytes that followed the end-of-data line, and
        further chunks are appended to it.
        """
        if self._done:
            self.leftover += chunk
            return True
        buf = self._buf
        # A CRLF can only start at the last held byte (a CR) or later.
        scan = max(len(buf) - 1, 0)
        buf += chunk

        if self._line_start and buf.startswith(b".\r\n"):
            end = 0
        else:
            end = buf.find(b"\r\n.\r\n", scan)
            if end >= 0:
                end += 2
        if end >= 0:
            self._pass_lines(bytes(buf[:end]))
            self.leftover = bytes(buf[end + 3:])
            self._done = True
            buf.clear()
            return True

        end = buf.rfind(b"\r\n", scan)
        if end >= 0:
            self._pass_lines(bytes(buf[:end + 2]))
            del buf[:end + 2]
            self._line_start = True
        if len(buf) > MAX_HELD_LINE:
            self._pass_piece()
        return False

    def _pass_lines(self, lines: bytes) -> None:
        """Pass on complete physical lines, each ending with CRLF."""
        if not lines:
            return
        if self._line_start and lines.startswith(b"."):
            lines = lines[1:]
        # A CRLF in the raw stream always ends a physical line, and removing the dot after
        # it cannot create a new CRLF, so every remaining CRLF is still a physical break.
        self._sink(_to_crlf(lines.replace(b"\r\n.", b"\r\n")))

    def _pass_piece(self) -> None:
        """Pass on the held start of an over-long physical line, keeping a trailing CR."""
        buf = self._buf
        keep = 1 if buf.endswith(b"\r") else 0
        piece = bytes(buf[:len(buf) - keep])
        del buf[:len(buf) - keep]
        if self._line_start and piece.startswith(b"."):
            piece = piece[1:]
        self._line_start = False
        # The piece holds no CRLF, so every CR and LF in it is bare.
        self._sink(_to_crlf(piece))


class Stuffer:
    """Encode decoded content for the MTA: CRLF line ends and dot-stuffing.

    Any bare CR or LF in the input becomes CRLF, so the MTA never receives one. A CR at
    the end of a chunk is held until the next chunk shows whether an LF follows.
    """

    def __init__(self) -> None:
        self._line_start = True
        self._held_cr = False
        self._finished = False

    def feed(self, chunk: bytes) -> bytes:
        """Return the encoded form of ``chunk``."""
        if self._finished:
            raise RuntimeError("Stuffer.feed() called after finish()")
        if self._held_cr:
            chunk = b"\r" + chunk
            self._held_cr = False
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
            self._held_cr = True
        if not chunk:
            return b""
        out = _to_crlf(chunk).replace(b"\r\n.", b"\r\n..")
        if self._line_start and out.startswith(b"."):
            out = b"." + out
        self._line_start = out.endswith(b"\r\n")
        return out

    def finish(self) -> bytes:
        """Return the final bytes: a CRLF if the last line is open, then ``.\\r\\n``."""
        if self._finished:
            raise RuntimeError("Stuffer.finish() called twice")
        self._finished = True
        # A held CR is a bare CR at the very end, which is a line break of its own.
        if self._held_cr or not self._line_start:
            return b"\r\n.\r\n"
        return b".\r\n"
