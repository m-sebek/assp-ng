# SPDX-License-Identifier: GPL-3.0-or-later
import pytest

from asspng.smtp.headers import format_field, split_header, strip_fields

# --- split_header -------------------------------------------------------------------------


def test_split_header_and_body():
    data = b"Subject: a\r\nFrom: b\r\n\r\nbody\r\n"
    header, offset = split_header(data)
    assert header == b"Subject: a\r\nFrom: b\r\n"
    assert data[offset:] == b"body\r\n"


def test_split_header_without_body():
    data = b"Subject: a\r\n"
    assert split_header(data) == (data, len(data))


def test_split_header_empty_body():
    assert split_header(b"Subject: a\r\n\r\n") == (b"Subject: a\r\n", 14)


def test_split_header_starts_with_empty_line():
    assert split_header(b"\r\nbody\r\n") == (b"", 2)


def test_split_header_empty_data():
    assert split_header(b"") == (b"", 0)


def test_split_header_uses_first_empty_line():
    assert split_header(b"A: 1\r\n\r\nB: 2\r\n\r\nc") == (b"A: 1\r\n", 8)


# --- strip_fields -------------------------------------------------------------------------


def test_strip_folded():
    assert strip_fields(
        b"X-ASSP-NG-Score: 1\r\n  folded\r\nSubject: s\r\n", "x-assp-ng-"
    ) == b"Subject: s\r\n"


def test_strip_is_case_insensitive_both_ways():
    header = b"x-assp-ng-id: a\r\nX-Assp-Ng-Test: b\r\nTo: c\r\n"
    assert strip_fields(header, "X-ASSP-NG-") == b"To: c\r\n"


def test_strip_all_occurrences_anywhere():
    header = (
        b"Received: from a\r\n\tby b\r\n"
        b"X-ASSP-NG-Score: 1\r\n"
        b"Subject: s\r\n"
        b"X-ASSP-NG-Warning: w\r\n\tmore\r\n more\r\n"
        b"To: t\r\n"
    )
    assert strip_fields(header, "x-assp-ng-") == (
        b"Received: from a\r\n\tby b\r\nSubject: s\r\nTo: t\r\n"
    )


def test_strip_keeps_continuation_of_other_fields():
    header = b"Subject: a\r\n x-assp-ng-score: 1\r\nTo: t\r\n"
    assert strip_fields(header, "x-assp-ng-") == header


def test_strip_matches_name_not_value():
    header = b"Subject: X-ASSP-NG-Score: 1\r\n"
    assert strip_fields(header, "x-assp-ng-") == header


def test_strip_prefix_must_be_at_start_of_name():
    header = b"X-Old-X-ASSP-NG-Score: 1\r\n"
    assert strip_fields(header, "x-assp-ng-") == header


def test_strip_name_with_space_before_colon():
    assert strip_fields(b"X-ASSP-NG-Score : 1\r\nTo: t\r\n", "x-assp-ng-") == b"To: t\r\n"


def test_strip_keeps_line_without_colon():
    header = b"X-ASSP-NG-Score 1\r\nTo: t\r\n"
    assert strip_fields(header, "x-assp-ng-") == header


def test_strip_last_field_without_crlf():
    assert strip_fields(b"To: t\r\nX-ASSP-NG-ID: 1", "x-assp-ng-") == b"To: t\r\n"


def test_strip_nothing_to_strip():
    header = b"From: a\r\nTo: b\r\n"
    assert strip_fields(header, "x-assp-ng-") == header


def test_strip_empty_header():
    assert strip_fields(b"", "x-assp-ng-") == b""


# --- format_field -------------------------------------------------------------------------


def test_format_field():
    assert format_field("X-ASSP-NG-ID", "mx1-7f3a9c2e-1") == b"X-ASSP-NG-ID: mx1-7f3a9c2e-1\r\n"


def test_format_field_value_at_limit():
    assert format_field("X-A", "v" * 998) == b"X-A: " + b"v" * 998 + b"\r\n"


def test_format_field_value_too_long():
    with pytest.raises(ValueError):
        format_field("X-A", "v" * 999)


def test_format_field_limit_counts_bytes():
    with pytest.raises(ValueError):
        format_field("X-A", "é" * 500)


@pytest.mark.parametrize("value", ["a\r\nX-Evil: 1", "a\nb", "a\rb", "\r", "\n"])
def test_format_field_refuses_line_breaks_in_value(value):
    with pytest.raises(ValueError):
        format_field("X-A", value)


@pytest.mark.parametrize("name", ["", "X A", "X:A", "X-A\r\nX-Evil", "X-é", "X\tA"])
def test_format_field_refuses_invalid_names(name):
    with pytest.raises(ValueError):
        format_field(name, "v")
