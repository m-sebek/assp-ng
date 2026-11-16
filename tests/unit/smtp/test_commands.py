# SPDX-License-Identifier: GPL-3.0-or-later
import pytest

from asspng.smtp.address import Address
from asspng.smtp.commands import (
    Command,
    CommandArgumentError,
    CommandSyntaxError,
    parse_command,
    parse_mail_from,
    parse_rcpt_to,
)


def test_lowercase_verb():
    assert parse_command(b"mail from:<a@b.example>") == Command("MAIL", "from:<a@b.example>")


def test_crlf_and_no_arg():
    assert parse_command(b"quit\r\n") == Command("QUIT", "")
    assert parse_command(b"NOOP\n") == Command("NOOP", "")


def test_extra_whitespace():
    assert parse_command(b"HELO   host.example  \r\n") == Command("HELO", "host.example")


def test_utf8_arg():
    assert parse_command("RCPT TO:<jänö@b.example>".encode()).arg == "TO:<jänö@b.example>"


@pytest.mark.parametrize(
    "line", [b"\xff\xfe", b"", b"\r\n", b"  ", b"MA\x00IL x", b"12 x", b"M@IL x"]
)
def test_garbage(line):
    with pytest.raises(CommandSyntaxError):
        parse_command(line)


def test_mail_space_and_params():
    m = parse_mail_from("FROM: <a@b.example> BODY=8BITMIME SMTPUTF8 SIZE=123")
    assert m.params == {"BODY": "8BITMIME", "SMTPUTF8": None, "SIZE": "123"}
    assert str(m.path) == "a@b.example"


def test_mail_case_and_lower_params():
    m = parse_mail_from("from:<a@b.example> size=5")
    assert m.params == {"SIZE": "5"}


def test_mail_null_sender():
    assert parse_mail_from("FROM:<>").path is None
    assert parse_mail_from("FROM:<> SIZE=0").params == {"SIZE": "0"}


def test_mail_unbracketed_lenient():
    assert str(parse_mail_from("FROM:a@b.example SIZE=1").path) == "a@b.example"


def test_mail_quoted_local_with_gt():
    m = parse_mail_from('FROM:<"a>b"@c.example> SIZE=1')
    assert m.path.local == '"a>b"'
    assert m.params == {"SIZE": "1"}


def test_mail_tabs_between_params():
    assert parse_mail_from("FROM:<a@b.example>\tSIZE=1\t BODY=7BIT").params == {
        "SIZE": "1", "BODY": "7BIT"}


@pytest.mark.parametrize("arg", [
    "", "FROM", "FROM:", "TO:<a@b.example>", "FROM:<a@b.example", "FROM:<a@b.example>SIZE=1",
    "FROM:<a@b.example> =1", "FROM:<a@b.example> SIZE=", "FROM:<a@b.example> SI$E=1",
    "FROM:<a@b.example> SIZE=1 SIZE=2", "FROM:<bad>", "FROM:<a@b.example> <c@d.example>",
])
def test_mail_invalid(arg):
    with pytest.raises(CommandSyntaxError):
        parse_mail_from(arg)


def test_too_many_params():
    with pytest.raises(CommandSyntaxError):
        parse_mail_from("FROM:<a@b.example> " + " ".join(f"P{i}=1" for i in range(11)))


def test_params_at_limit_ok():
    arg = "FROM:<a@b.example> " + " ".join(f"P{i}=1" for i in range(10))
    assert len(parse_mail_from(arg).params) == 10
    with pytest.raises(CommandSyntaxError):
        parse_mail_from(arg, max_params=9)


def test_rcpt_postmaster():
    assert parse_rcpt_to("TO:<postmaster>").path.domain == ""


def test_rcpt_basic():
    r = parse_rcpt_to("to: <X@Y.example> NOTIFY=NEVER")
    assert r.path == Address("X", "Y.example")
    assert r.params == {"NOTIFY": "NEVER"}


def test_rcpt_source_route():
    assert str(parse_rcpt_to("TO:<@r.example:x@y.example>").path) == "x@y.example"


@pytest.mark.parametrize("arg", ["TO:<>", "FROM:<a@b.example>", "TO:", "", "TO:<a@b.example"])
def test_rcpt_invalid(arg):
    with pytest.raises(CommandSyntaxError):
        parse_rcpt_to(arg)


def test_rcpt_too_many_params():
    with pytest.raises(CommandSyntaxError):
        parse_rcpt_to("TO:<a@b.example> " + " ".join(f"P{i}=1" for i in range(11)))


def test_invalid_utf8_error_carries_no_context():
    with pytest.raises(CommandSyntaxError) as info:
        parse_command(b"AUTH PLAIN \xff\xfesecret")
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


@pytest.mark.parametrize("parse, arg", [(parse_mail_from, "FROM:<a@b@local.example>"),
                                        (parse_rcpt_to, "TO:<a@b@local.example>"),
                                        (parse_rcpt_to, "TO:a@b@local.example")])
def test_unquoted_at_sign_in_local_part_is_an_argument_error(parse, arg):
    """R61: answered 501 (bad argument), not 500."""
    with pytest.raises(CommandArgumentError):
        parse(arg)
