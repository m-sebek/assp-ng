# SPDX-License-Identifier: GPL-3.0-or-later
import pytest

from asspng.smtp.address import (
    Address,
    AddressError,
    AtSignInLocalPart,
    normalize_domain,
    parse_path,
)


def test_idn_and_case():
    assert parse_path("<Jano@BÜCHER.Example>").key == "jano@xn--bcher-kva.example"


def test_null_path():
    assert parse_path("<>") is None


def test_source_route():
    assert str(parse_path("<@a.example,@b.example:x@c.example>")) == "x@c.example"


def test_quoted_local():
    assert parse_path('<"john doe"@example.com>').local == '"john doe"'


def test_quoted_local_with_at_and_angle():
    a = parse_path('<"a@b>c"@example.com>')
    assert a.local == '"a@b>c"'
    assert a.domain == "example.com"


def test_postmaster():
    assert parse_path("<postmaster>") == Address("postmaster", "")
    assert parse_path("<PostMaster>") == Address("postmaster", "")


def test_postmaster_str_and_key():
    a = Address("postmaster", "")
    assert str(a) == "postmaster"
    assert a.key == "postmaster@"


def test_str_and_key():
    a = parse_path("<Joe@Example.COM>")
    assert str(a) == "Joe@Example.COM"
    assert a.key == "joe@example.com"


def test_utf8_local_part():
    assert parse_path("<jänö@example.com>").local == "jänö"


def test_trailing_dot_and_literal():
    assert parse_path("<a@example.com.>").key == "a@example.com"
    assert parse_path("<a@[IPv6:2001:DB8::1]>").key == "a@[ipv6:2001:db8::1]"
    assert parse_path("<a@[192.0.2.1]>").domain == "[192.0.2.1]"


def test_whitespace_around_path_tolerated():
    assert str(parse_path("  <a@b.example> ")) == "a@b.example"


@pytest.mark.parametrize("text", [
    "", "a@b.example", "<a@b.example", "a@b.example>", "<<a@b.example>",
    "<a@b.example>>", "<a@b<c>", "<@b.example>", "<@x.example:>",
    "<@a.example,@b.example>", "<a@>", "<@>", "<nobody>", "<a b@c.example>",
    '<"unterminated@b.example>', "<a@b..example>", "<a@.example>",
    "<a@b.example\x00>", "<a@" + "x" * 64 + ".example>", "<a@[1.2.3.4>",
])
def test_invalid_paths(text):
    with pytest.raises(AddressError):
        parse_path(text)


def test_normalize_domain():
    assert normalize_domain("BÜCHER.Example.") == "xn--bcher-kva.example"
    assert normalize_domain("[IPv6:2001:DB8::1]") == "[ipv6:2001:db8::1]"
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain("") == ""


def test_normalize_domain_rejects_bad_label():
    with pytest.raises(AddressError):
        normalize_domain("a..b")


@pytest.mark.parametrize("text", ["<a@b@local.example>", "<a@b@c@local.example>",
                                  "<@x.example:a@b@local.example>"])
def test_unquoted_at_sign_in_local_part_is_refused(text):
    """R61: last-'@'-wins parsing must not accept routing syntax such as a@remote@local."""
    with pytest.raises(AtSignInLocalPart):
        parse_path(text)


def test_quoted_at_sign_in_local_part_still_parses():
    assert parse_path('<"a@b"@local.example>').local == '"a@b"'
