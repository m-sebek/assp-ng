# SPDX-License-Identifier: GPL-3.0-or-later
import re
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from asspng.smtp.datacodec import DataReceiver, Stuffer

# Pieces that make the interesting byte combinations (bare CR/LF, dots at line starts,
# CRLF split across chunks, lines longer than 8 KiB) likely in generated input.
PIECES = st.sampled_from(
    [b"\r", b"\n", b".", b"..", b"a", b"\r\n", b"\r\n.", b"\r\n.\r\n", b"\x00", b"y" * 5000]
)
RAW = st.lists(PIECES, max_size=40).map(b"".join)


def normalize(data: bytes) -> bytes:
    data = re.sub(rb"\r\n|\r|\n", b"\r\n", data)
    if data and not data.endswith(b"\r\n"):
        data += b"\r\n"
    return data


def reference(raw: bytes) -> tuple[bytes, int]:
    """A line-by-line model of the receiver: (content, offset just after the end line)."""
    out = []
    pos = 0
    while (end := raw.find(b"\r\n", pos)) >= 0:
        line = raw[pos:end]
        pos = end + 2
        if line == b".":
            return b"".join(out), pos
        if line.startswith(b"."):
            line = line[1:]
        out.append(re.sub(rb"\r|\n", b"\r\n", line) + b"\r\n")
    raise AssertionError("no end-of-data line")


def receive(*chunks: bytes) -> tuple[bytes, bool, DataReceiver]:
    out: list[bytes] = []
    rx = DataReceiver(out.append)
    done = False
    for chunk in chunks:
        done = rx.feed(chunk)
    return b"".join(out), done, rx


def split_at(data: bytes, cuts: list[int]) -> list[bytes]:
    bounds = [0, *sorted(c % (len(data) + 1) for c in cuts), len(data)]
    return [data[a:b] for a, b in zip(bounds, bounds[1:])]


def stuff(*chunks: bytes) -> bytes:
    st_ = Stuffer()
    return b"".join(st_.feed(c) for c in chunks) + st_.finish()


# --- DataReceiver -------------------------------------------------------------------------


def test_unstuff_and_terminate():
    out = []
    rx = DataReceiver(out.append)
    assert rx.feed(b"..x\r\n.\r\n")
    assert b"".join(out) == b".x\r\n"


def test_split_chunks_cr_boundary():
    out = []
    rx = DataReceiver(out.append)
    assert not rx.feed(b"a\r")
    assert rx.feed(b"\n.\r\n")
    assert b"".join(out) == b"a\r\n"


def test_empty_message():
    assert receive(b".\r\n")[:2] == (b"", True)


def test_empty_line_then_end():
    assert receive(b"\r\n.\r\n")[:2] == (b"\r\n", True)


def test_not_done_without_terminator():
    assert receive(b"Subject: a\r\n\r\nbody\r\n")[1] is False


def test_terminator_split_into_single_bytes():
    data = b"a\r\n.\r\n"
    content, done, _ = receive(*(data[i:i + 1] for i in range(len(data))))
    assert (content, done) == (b"a\r\n", True)


def test_dot_line_split_across_chunks_is_unstuffed():
    assert receive(b"x\r\n.", b".y\r\n.\r\n")[:2] == (b"x\r\n.y\r\n", True)


def test_dot_then_cr_is_not_the_end():
    content, done, _ = receive(b"x\r\n.\r", b"y\r\n")
    assert not done
    assert content == b"x\r\n\r\ny\r\n"


def test_bare_cr_and_lf_become_crlf():
    content, done, _ = receive(b"a\rb\nc\r\r\nd\n\re\r\n.\r\n")
    assert done
    assert content == b"a\r\nb\r\nc\r\n\r\nd\r\n\r\ne\r\n"


@pytest.mark.parametrize("line", [b"\n.", b"\r.", b".\n", b".\r", b"\n.\r", b"\r.\n"])
def test_logical_dot_lines_are_content(line):
    content, done, _ = receive(b"x" + line + b"\r\n.\r\n")
    assert done
    assert content == re.sub(rb"\r|\n", b"\r\n", b"x" + line) + b"\r\n"


def test_logical_lines_are_not_unstuffed():
    assert receive(b"a\n..b\r\n.\r\n")[0] == b"a\r\n..b\r\n"


def test_only_one_dot_is_removed():
    assert receive(b"...\r\n.\r\n")[0] == b"..\r\n"


def test_leftover_is_bytes_after_terminator():
    _, done, rx = receive(b"a\r\n.\r\nQUIT\r\n")
    assert done
    assert rx.leftover == b"QUIT\r\n"


def test_leftover_empty_when_terminator_ends_chunk():
    assert receive(b"a\r\n.\r\n")[2].leftover == b""


def test_feed_after_done_returns_true_and_extends_leftover():
    out: list[bytes] = []
    rx = DataReceiver(out.append)
    assert rx.feed(b"a\r\n.\r\nRSET\r\n")
    assert rx.feed(b"QUIT\r\n")
    assert rx.leftover == b"RSET\r\nQUIT\r\n"
    assert b"".join(out) == b"a\r\n"


def test_long_line_is_flushed_before_it_ends():
    out: list[bytes] = []
    rx = DataReceiver(out.append)
    for _ in range(100):
        assert not rx.feed(b"z" * 1000)
    assert len(b"".join(out)) >= 100_000 - 8192 - 1000
    assert rx.feed(b"\r\n.\r\n")
    assert b"".join(out) == b"z" * 100_000 + b"\r\n"


def test_long_line_starting_with_dot_loses_one_dot():
    content, done, _ = receive(b"." + b"z" * 20_000, b"\r\n.\r\n")
    assert done
    assert content == b"z" * 20_000 + b"\r\n"


def test_long_line_ending_in_dot_is_not_the_end():
    content, done, _ = receive(b"z" * 20_000, b".\r\n", b"y\r\n")
    assert not done
    assert content == b"z" * 20_000 + b".\r\ny\r\n"


def test_long_line_cr_at_flush_boundary_pairs_with_next_lf():
    content, done, _ = receive(b"z" * 9000 + b"\r", b"\n.\r\n")
    assert done
    assert content == b"z" * 9000 + b"\r\n"


def test_long_line_cr_at_flush_boundary_is_bare_if_no_lf_follows():
    content, done, _ = receive(b"z" * 9000 + b"\r", b".\r\n.\r\n")
    assert done
    assert content == b"z" * 9000 + b"\r\n.\r\n"


@given(RAW, st.lists(st.integers(min_value=0), max_size=6))
def test_receiver_matches_reference_for_any_chunking(raw, cuts):
    raw += b"\r\n.\r\n"
    expected, end = reference(raw)
    out: list[bytes] = []
    rx = DataReceiver(out.append)
    fed = 0
    for chunk in split_at(raw, cuts):
        fed += len(chunk)
        # Done exactly from the chunk that completes the end-of-data line on.
        assert rx.feed(chunk) is (fed >= end)
    assert b"".join(out) == expected
    assert rx.leftover == raw[end:]


@given(st.binary(max_size=4000), st.integers(min_value=0))
def test_roundtrip(content, cut):
    expected = normalize(content)
    wire = stuff(expected)
    for chunks in ([wire], split_at(wire, [cut])):
        got, done, rx = receive(*chunks)
        assert done
        assert got == expected
        assert rx.leftover == b""


@given(RAW, st.integers(min_value=0))
def test_roundtrip_biased(content, cut):
    expected = normalize(content)
    got, done, rx = receive(*split_at(stuff(expected), [cut]))
    assert (got, done, rx.leftover) == (expected, True, b"")


# --- Stuffer ------------------------------------------------------------------------------


def test_finish_alone_is_empty_message():
    assert Stuffer().finish() == b".\r\n"


def test_stuffs_dot_at_line_starts():
    assert stuff(b".a\r\nb\r\n.\r\n..\r\n") == b"..a\r\nb\r\n..\r\n...\r\n.\r\n"


def test_dot_not_at_line_start_is_untouched():
    assert stuff(b"a.\r\nb.c\r\n") == b"a.\r\nb.c\r\n.\r\n"


def test_finish_adds_missing_crlf():
    assert stuff(b"abc") == b"abc\r\n.\r\n"


def test_finish_does_not_double_crlf():
    assert stuff(b"abc\r\n") == b"abc\r\n.\r\n"


def test_bare_cr_and_lf_become_crlf_in_stuffer():
    assert stuff(b"a\rb\nc\r\r\nd\n\r.e") == b"a\r\nb\r\nc\r\n\r\nd\r\n\r\n..e\r\n.\r\n"


def test_trailing_bare_cr_is_a_line_break():
    assert stuff(b"a\r") == b"a\r\n.\r\n"


def test_dot_at_line_start_across_chunks():
    assert stuff(b"a\r\n", b".b") == b"a\r\n..b\r\n.\r\n"


def test_crlf_split_across_chunks_then_dot():
    assert stuff(b"a\r", b"\n.b") == b"a\r\n..b\r\n.\r\n"


def test_bare_cr_at_chunk_end_then_dot():
    assert stuff(b"a\r", b".b") == b"a\r\n..b\r\n.\r\n"


def test_cr_then_empty_chunks_is_held():
    st_ = Stuffer()
    assert st_.feed(b"a\r") == b"a"
    assert st_.feed(b"") == b""
    assert st_.feed(b"\n") == b"\r\n"
    assert st_.finish() == b".\r\n"


def test_dot_at_very_start():
    assert stuff(b".") == b"..\r\n.\r\n"


def test_dot_mid_line_across_chunks_is_untouched():
    assert stuff(b"a", b".b") == b"a.b\r\n.\r\n"


def test_trailing_bare_cr_after_complete_line_is_an_empty_line():
    assert stuff(b"a\r\n", b"\r") == b"a\r\n\r\n.\r\n"


def test_feed_after_finish_raises():
    st_ = Stuffer()
    st_.finish()
    with pytest.raises(RuntimeError):
        st_.feed(b"MAIL FROM:<x@evil>\r\n")
    with pytest.raises(RuntimeError):
        st_.finish()


def reference_stuff(content: bytes) -> bytes:
    lines = normalize(content).split(b"\r\n")[:-1]
    return b"".join(
        (b"." + line if line.startswith(b".") else line) + b"\r\n" for line in lines
    ) + b".\r\n"


@given(st.one_of(st.binary(max_size=2000), RAW), st.lists(st.integers(min_value=0), max_size=6))
def test_stuffer_matches_reference_for_any_chunking(content, cuts):
    assert stuff(*split_at(content, cuts)) == reference_stuff(content)


# --- Performance --------------------------------------------------------------------------


def chunked(data: bytes, size: int = 65536) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


@pytest.mark.parametrize(
    "line",
    [b"x" * 74 + b"\r\n", b".a\nb\rc" * 10 + b"\r\n", b"y" * (20 * 1024 * 1024)],
    ids=["short-lines", "bare-breaks-and-dots", "one-long-line"],
)
def test_twenty_megabytes_is_linear(line):
    body = line * (20 * 1024 * 1024 // len(line))
    start = time.perf_counter()
    st_ = Stuffer()
    wire = b"".join([*(st_.feed(c) for c in chunked(body)), st_.finish()])
    out: list[bytes] = []
    rx = DataReceiver(out.append)
    results = [rx.feed(c) for c in chunked(wire)]
    elapsed = time.perf_counter() - start
    assert results[-1] and not any(results[:-1])
    assert len(b"".join(out)) >= len(body)
    assert elapsed < 5.0
