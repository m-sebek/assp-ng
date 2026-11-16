# SPDX-License-Identifier: GPL-3.0-or-later
from asspng.smtp.ehlo import filter_ehlo
from asspng.smtp.replies import Reply

MTA = Reply.of(
    250, "mta.local", "PIPELINING", "SIZE 10240000", "VRFY", "ETRN", "STARTTLS",
    "AUTH PLAIN LOGIN", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN", "SMTPUTF8",
    "CHUNKING", "XCLIENT NAME ADDR", "XFORWARD NAME",
)


def run(mta: Reply, *, starttls: bool = False, auth: bool = False, size: int = 1000) -> Reply:
    return filter_ehlo(
        mta, hostname="h", offer_starttls=starttls, auth_allowed=auth, max_size=size
    )


def test_filter():
    r = filter_ehlo(
        MTA, hostname="mx1.example.com", offer_starttls=True, auth_allowed=False,
        max_size=52428800,
    )
    assert r.code == 250
    assert r.lines == (
        "mx1.example.com", "SIZE 10240000", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN",
        "SMTPUTF8", "STARTTLS",
    )


def test_auth_appended_when_allowed_and_mta_has_it():
    r = run(MTA, auth=True)
    assert r.lines[-1] == "AUTH PLAIN LOGIN"


def test_auth_only_if_mta_has_it():
    assert "AUTH PLAIN LOGIN" not in run(Reply.of(250, "m", "SIZE"), auth=True).lines


def test_legacy_auth_equals_line_does_not_count():
    assert "AUTH PLAIN LOGIN" not in run(Reply.of(250, "m", "AUTH=LOGIN"), auth=True).lines


def test_auth_not_offered_when_not_allowed():
    assert "AUTH PLAIN LOGIN" not in run(MTA, auth=False).lines


def test_size_zero_means_no_mta_limit():
    assert "SIZE 1000" in run(Reply.of(250, "m", "SIZE 0")).lines


def test_size_without_number_or_garbage():
    assert "SIZE 1000" in run(Reply.of(250, "m", "SIZE")).lines
    assert "SIZE 1000" in run(Reply.of(250, "m", "SIZE abc")).lines


def test_size_capped_to_max():
    assert "SIZE 1000" in run(Reply.of(250, "m", "SIZE 5000")).lines


def test_size_not_added_when_mta_lacks_it():
    r = run(Reply.of(250, "m", "8BITMIME"))
    assert r.lines == ("h", "8BITMIME")


def test_keywords_case_insensitive_and_text_kept():
    r = run(Reply.of(250, "m", "size 500", "8bitmime", "starttls"))
    assert r.lines == ("h", "SIZE 500", "8bitmime")


def test_non_positive_reply_unchanged():
    bad = Reply.of(550, "nope")
    assert run(bad, starttls=True, auth=True) is bad


def test_empty_body():
    r = run(Reply.of(250, "m"), starttls=True, auth=True)
    assert r.lines == ("h", "STARTTLS")
