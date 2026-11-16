# SPDX-License-Identifier: GPL-3.0-or-later
import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from asspng.log.maillog import MaillogRecord, format_maillog
from asspng.log.redact import RedactionFilter, redact_text

PASSWORD = "s3cr3t-Pa55word"

EXAMPLE = (
    "2026-11-12T17:30:01+01:00 mx1 s=7f3a9c2e t=1 l=inbound ip=203.0.113.5 "
    "ptr=mail.example.org helo=mail.example.org tls=TLSv1.3 auth=- "
    "from=<a@example.org> rcpt=<b@example.com> size=48211 score=0 result=accepted "
    'mta="250 2.0.0 Ok: queued as 4XyZ" dur=1.84s'
)


def make(**kw: object) -> MaillogRecord:
    base = MaillogRecord(
        ts=datetime(2026, 11, 12, 17, 30, 1, tzinfo=timezone(timedelta(hours=1))),
        instance="mx1", session="7f3a9c2e", txn=1, listener="inbound",
        ip="203.0.113.5", ptr="mail.example.org", helo="mail.example.org",
        tls="TLSv1.3", auth="", mail_from="a@example.org", rcpts=["b@example.com"],
        size=48211, score=0, result="accepted", mta="250 2.0.0 Ok: queued as 4XyZ",
        duration_s=1.84,
    )
    return replace(base, **kw)  # type: ignore[arg-type]


def test_exact_example_line() -> None:
    assert format_maillog(make()) == EXAMPLE


def test_quoting() -> None:
    line = format_maillog(make(helo='we ird"name\\x', rcpts=["a@x", "b@y"]))
    assert 'helo="we ird\\"name\\\\x"' in line
    assert "rcpt=<a@x>,<b@y>" in line


def test_control_chars_cannot_forge_lines() -> None:
    line = format_maillog(make(helo="evil\r\nfake=1", ptr="a\x7fb", mta="x\ny z"))
    assert "\n" not in line and "\r" not in line and "\x7f" not in line
    assert 'helo="evil\\x0d\\x0afake=1"' in line
    assert 'ptr="a\\x7fb"' in line
    assert 'mta="x\\x0ay z"' in line


def test_session_without_message() -> None:
    line = format_maillog(
        make(txn=None, mail_from="", rcpts=[], size=None, score=None, result="closed", mta="")
    )
    assert " t=- " in line
    assert "from=- rcpt=- size=- score=- result=closed mta=- dur=1.84s" in line


def test_null_sender() -> None:
    assert "from=<>" in format_maillog(make(mail_from="<>"))


def test_redaction_masks_auth() -> None:
    assert redact_text(f"AUTH PLAIN {PASSWORD}") == "AUTH PLAIN <redacted>"
    assert redact_text(f"  auth login {PASSWORD}") == "  auth LOGIN <redacted>".replace(
        "LOGIN", "login")
    assert redact_text(f"AUTH CRAM-MD5 {PASSWORD}") == "AUTH <redacted>"
    assert redact_text("AUTHOR foo") == "AUTHOR foo"
    assert redact_text("AUTH PLAIN") == "AUTH PLAIN"
    text = f"ok\nAUTH PLAIN {PASSWORD}\nmore"
    assert PASSWORD not in redact_text(text)


def _record(msg: str, *args: object, **kw: object) -> logging.LogRecord:
    rec = logging.LogRecord("asspng.x", logging.INFO, __file__, 1, msg, args or None, None)
    for k, v in kw.items():
        setattr(rec, k, v)
    return rec


def test_filter_redacts_formatted_message_and_args() -> None:
    rec = _record("%s", f"AUTH LOGIN {PASSWORD}")
    assert RedactionFilter().filter(rec) is True
    assert rec.args is None
    assert PASSWORD not in rec.getMessage()


def test_filter_auth_flag_masks_everything() -> None:
    rec = _record("%s", PASSWORD, auth=True)
    assert RedactionFilter().filter(rec) is True
    assert rec.getMessage() == "<redacted>"


def test_filter_redacts_exception_text() -> None:
    try:
        raise ValueError(f"bad\nAUTH PLAIN {PASSWORD}")
    except ValueError:
        import sys
        rec = _record("failed")
        rec.exc_info = sys.exc_info()
    RedactionFilter().filter(rec)
    assert rec.exc_info is None
    assert rec.exc_text is not None and PASSWORD not in rec.exc_text
    assert "ValueError" in rec.exc_text


def test_single_line_exception_message_is_redacted() -> None:
    import sys
    try:
        raise ValueError(f"AUTH PLAIN {PASSWORD}")
    except ValueError:
        rec = _record("failed")
        rec.exc_info = sys.exc_info()
    RedactionFilter().filter(rec)
    assert rec.exc_text is not None
    assert PASSWORD not in rec.exc_text and "AUTH PLAIN <redacted>" in rec.exc_text


def test_mid_line_redaction() -> None:
    assert redact_text(f"client sent AUTH PLAIN {PASSWORD}") == (
        "client sent AUTH PLAIN <redacted>")
    assert redact_text(f"x auth login {PASSWORD} tail") == "x auth login <redacted> tail"
    assert redact_text(f"x AUTH {PASSWORD}") == "x AUTH <redacted>"
    assert redact_text("x AUTH PLAIN") == "x AUTH PLAIN"
    raw = repr(b"AUTH PLAIN " + b"AHVzZXIAcGFzcw==" + b"\r\n")
    out = redact_text(f"got {raw}")
    assert "AHVzZXIAcGFzcw" not in out and "AUTH PLAIN <redacted>" in out


def test_mid_line_does_not_damage_maillog_line() -> None:
    line = format_maillog(make(helo="x AUTH y z"))
    out = redact_text(line)
    assert 'helo="x AUTH <redacted> z" tls=TLSv1.3' in out
    assert out.endswith("dur=1.84s")


def test_authlike_words_unchanged() -> None:
    assert redact_text("AUTHOR PLAIN x") == "AUTHOR PLAIN x"
    assert redact_text("OAUTH PLAIN x") == "OAUTH PLAIN x"


def test_filter_survives_bad_format_call() -> None:
    rec = _record("bad %d", "x")
    assert RedactionFilter().filter(rec) is True
    assert rec.getMessage() == "<unformattable log message>"


def test_filter_survives_unformattable_exception(monkeypatch: object) -> None:
    import sys
    from asspng.log import redact

    def boom(self: object, ei: object) -> str:
        raise RuntimeError("boom")

    try:
        raise ValueError("x")
    except ValueError:
        rec = _record("failed")
        rec.exc_info = sys.exc_info()
    monkeypatch.setattr(logging.Formatter, "formatException", boom)  # type: ignore[attr-defined]
    assert redact.RedactionFilter().filter(rec) is True
    assert rec.exc_info is None and rec.exc_text == "<unformattable exception>"


def test_filter_strips_non_standard_attributes() -> None:
    rec = _record("hello", line=f"AUTH PLAIN {PASSWORD}", auth=False)
    RedactionFilter().filter(rec)
    assert not hasattr(rec, "line") and not hasattr(rec, "auth")
    assert rec.getMessage() == "hello"
