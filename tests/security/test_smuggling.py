# SPDX-License-Identifier: GPL-3.0-or-later
"""SMTP smuggling: the MTA must never see an end of data that the proxy did not see."""

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from asspng.smtp.datacodec import DataReceiver, Stuffer

# How different MTAs may split the wire into lines. A smuggling attack works when the
# proxy and the MTA disagree, so the re-encoded wire must end at the same place in all.
MTA_LINE_BREAKS = {
    "CRLF only": rb"\r\n",
    "bare LF too": rb"\r?\n",
    "bare CR or LF too": rb"\r\n|\r|\n",
}

PIECES = st.sampled_from(
    [b"\r", b"\n", b".", b"a", b"\r\n", b"\r\n.", b".\r", b".\n", b"\x00", b"MAIL FROM:<x@evil>"]
)


def end_of_data(wire: bytes, line_break: bytes) -> int | None:
    """Offset just after the first line that is exactly ``.``, as an MTA would see it."""
    pos = 0
    for match in re.finditer(line_break, wire):
        if wire[pos:match.start()] == b".":
            return match.end()
        pos = match.end()
    return None


def relay(client_data: bytes) -> tuple[bool, bytes]:
    """Receive ``client_data`` like the proxy and re-encode it for the MTA."""
    out: list[bytes] = []
    done = DataReceiver(out.append).feed(client_data)
    stuffer = Stuffer()
    return done, stuffer.feed(b"".join(out)) + stuffer.finish()


@pytest.mark.parametrize(
    "smuggle", [b"\n.\n", b"\r.\r", b"\r\n.\r", b"\n.\r\n", b"\r.\r\n", b".\n"]
)
def test_smuggling_variant_is_content(smuggle):
    out = []
    rx = DataReceiver(out.append)
    done = rx.feed(b"Subject: a\r\n\r\nbody" + smuggle + b"MAIL FROM:<x@evil>\r\n.\r\n")
    assert done and b"MAIL FROM:<x@evil>" in b"".join(out)
    st_ = Stuffer()
    stuffed = st_.feed(b"".join(out)) + st_.finish()
    # The only terminator comes from finish().
    assert stuffed.count(b"\r\n.\r\n") == 1 and stuffed.endswith(b"\r\n.\r\n")


@pytest.mark.parametrize(
    "smuggle",
    [b"\n.\n", b"\r.\r", b"\r\n.\r", b"\n.\r\n", b"\r.\r\n", b".\n", b"\r\n\x00.\r\n",
     b"\r\n.\n", b"\n.\r", b"\r\n..\r\n"],
)
@pytest.mark.parametrize("line_break", MTA_LINE_BREAKS.values(), ids=list(MTA_LINE_BREAKS))
def test_mta_sees_one_message(smuggle, line_break):
    done, wire = relay(b"Subject: a\r\n\r\nbody" + smuggle + b"MAIL FROM:<x@evil>\r\n.\r\n")
    assert done
    assert end_of_data(wire, line_break) == len(wire)


@given(st.lists(PIECES, max_size=60).map(b"".join))
def test_any_client_data_gives_one_message_in_every_mta_view(client_data):
    done, wire = relay(client_data + b"\r\n.\r\n")
    assert done
    without_crlf = wire.replace(b"\r\n", b"")
    assert b"\r" not in without_crlf and b"\n" not in without_crlf
    for line_break in MTA_LINE_BREAKS.values():
        assert end_of_data(wire, line_break) == len(wire)


@given(st.binary(max_size=2000))
def test_random_bytes_give_one_message_in_every_mta_view(client_data):
    done, wire = relay(client_data + b"\r\n.\r\n")
    assert done
    for line_break in MTA_LINE_BREAKS.values():
        assert end_of_data(wire, line_break) == len(wire)
