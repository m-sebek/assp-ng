# SPDX-License-Identifier: GPL-3.0-or-later
import base64

import pytest

from asspng.proxy.auth import AuthExchange, AuthSyntaxError, redact_auth


def b64(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


PLAIN_SECRET = b64(b"\x00alice\x00secret")


def test_plain_initial() -> None:
    ex = AuthExchange("PLAIN", PLAIN_SECRET)
    assert ex.username == "alice"
    assert not ex.cancelled


def test_plain_with_authzid_and_lowercase_mechanism() -> None:
    ex = AuthExchange("plain", b64(b"boss\x00alice\x00secret"))
    assert ex.username == "alice"


def test_plain_continuation() -> None:
    ex = AuthExchange("PLAIN", None)
    assert ex.username is None
    ex.on_client_line(PLAIN_SECRET)
    assert ex.username == "alice"


def test_plain_equals_initial_is_empty_response() -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("PLAIN", "=")


@pytest.mark.parametrize("raw", [b"alice\x00secret", b"a\x00b\x00c\x00d", b"nonul"])
def test_plain_wrong_field_count(raw: bytes) -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("PLAIN", b64(raw))


def test_plain_empty_username() -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("PLAIN", b64(b"\x00\x00secret"))


def test_login_two_steps() -> None:
    ex = AuthExchange("LOGIN", None)
    assert ex.username is None
    ex.on_client_line(b64("alice"))
    assert ex.username == "alice"
    ex.on_client_line(b64("secret"))
    assert ex.username == "alice"
    assert not ex.cancelled


def test_login_initial_username() -> None:
    ex = AuthExchange("LOGIN", b64("alice"))
    assert ex.username == "alice"
    ex.on_client_line("!!!not base64 password!!!")
    assert ex.username == "alice"


def test_login_password_never_decoded() -> None:
    ex = AuthExchange("LOGIN", None)
    ex.on_client_line(b64("alice"))
    ex.on_client_line("%%%")  # would fail validate=True; must be ignored
    assert ex.username == "alice"


def test_cancel() -> None:
    ex = AuthExchange("LOGIN", None)
    ex.on_client_line("*")
    assert ex.cancelled
    assert ex.username is None


def test_cancel_at_password_step() -> None:
    ex = AuthExchange("LOGIN", b64("alice"))
    ex.on_client_line("*")
    assert ex.cancelled


def test_cancel_plain_continuation() -> None:
    ex = AuthExchange("PLAIN", None)
    ex.on_client_line("*")
    assert ex.cancelled


def test_bad_base64() -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("PLAIN", "@@@@")
    ex = AuthExchange("LOGIN", None)
    with pytest.raises(AuthSyntaxError):
        ex.on_client_line("not base64!")


def test_bad_utf8() -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("LOGIN", b64(b"\xff\xfe"))


def test_username_too_long_and_empty() -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("LOGIN", b64("a" * 257))
    assert AuthExchange("LOGIN", b64("a" * 256)).username == "a" * 256
    with pytest.raises(AuthSyntaxError):
        AuthExchange("LOGIN", "=")


def test_unknown_mechanism() -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("CRAM-MD5", None)


def _slot_values(ex: AuthExchange) -> str:
    return str([getattr(ex, s, None) for s in type(ex).__slots__])


def test_password_not_in_repr_or_vars() -> None:
    forbidden = ["secret", b64("secret"), PLAIN_SECRET]
    exchanges = []
    ex = AuthExchange("PLAIN", PLAIN_SECRET)
    exchanges.append(ex)
    ex = AuthExchange("PLAIN", None)
    ex.on_client_line(PLAIN_SECRET)
    exchanges.append(ex)
    ex = AuthExchange("LOGIN", None)
    ex.on_client_line(b64("alice"))
    ex.on_client_line(b64("secret"))
    exchanges.append(ex)
    for ex in exchanges:
        assert not hasattr(ex, "__dict__")
        text = repr(ex) + _slot_values(ex)
        for bad in forbidden:
            assert bad not in text
        assert "alice" not in repr(ex)


def test_exceptions_contain_no_secrets() -> None:
    cases = [
        lambda: AuthExchange("PLAIN", b64(b"alice\x00secret")),
        lambda: AuthExchange("PLAIN", b64(b"\x00\x00secret")),
        lambda: AuthExchange("LOGIN", b64(b"\xffsecret")),
        lambda: AuthExchange("LOGIN", "secret"),
        lambda: AuthExchange("LOGIN", b64("secret" * 100)),
        lambda: AuthExchange("secret", None),
        lambda: AuthExchange("PLAIN", "secret"),
        lambda: AuthExchange("LOGIN", b64("sec\x01ret")),
    ]
    for case in cases:
        with pytest.raises(AuthSyntaxError) as info:
            case()
        assert info.value.__cause__ is None
        assert info.value.__context__ is None
        text = str(info.value) + repr(info.value)
        assert "secret" not in text
        assert b64("secret") not in text


def test_redact() -> None:
    assert redact_auth(b"AUTH PLAIN xxx", False) == b"AUTH PLAIN <redacted>"
    assert redact_auth(b"auth plain xxx", False) == b"auth plain <redacted>"
    assert redact_auth(b"AUTH LOGIN dXNlcg==", False) == b"AUTH LOGIN <redacted>"
    assert redact_auth(b"  AUTH PLAIN xxx", False) == b"  AUTH PLAIN <redacted>"
    assert redact_auth(b"AUTH PLAIN =", False) == b"AUTH PLAIN <redacted>"


def test_redact_unchanged() -> None:
    assert redact_auth(b"AUTH LOGIN", False) == b"AUTH LOGIN"
    assert redact_auth(b"MAIL FROM:<a@b>", False) == b"MAIL FROM:<a@b>"
    assert redact_auth(b"AUTHX PLAIN foo", False) == b"AUTHX PLAIN foo"
    assert redact_auth(b"", False) == b""


def test_redact_in_exchange() -> None:
    assert redact_auth(b"c2VjcmV0", True) == b"<redacted>"
    assert redact_auth(b"*", True) == b"<redacted>"
    assert redact_auth(b"", True) == b"<redacted>"


@pytest.mark.parametrize("initial", [
    "=", b64("a" * 257), b64(b"\xff\xfe"), "!!!", b64("al\nice"), b64("al\x7fice"),
    b64("al\u0085ice"),
])
def test_login_error_fails_closed(initial: str) -> None:
    ex = AuthExchange("LOGIN", None)
    with pytest.raises(AuthSyntaxError):
        ex.on_client_line(initial)
    ex.on_client_line(b64("secret"))
    assert ex.username is None
    assert "secret" not in repr(ex) + _slot_values(ex)
    assert b64("secret") not in repr(ex) + _slot_values(ex)


def test_plain_error_fails_closed() -> None:
    ex = AuthExchange("PLAIN", None)
    with pytest.raises(AuthSyntaxError):
        ex.on_client_line(b64(b"nonul"))
    ex.on_client_line(PLAIN_SECRET)
    assert ex.username is None


def test_lines_after_completion_ignored() -> None:
    ex = AuthExchange("PLAIN", PLAIN_SECRET)
    ex.on_client_line(b64(b"\x00mallory\x00x"))
    ex.on_client_line("*")
    assert ex.username == "alice"
    assert not ex.cancelled
    ex = AuthExchange("LOGIN", b64("alice"))
    ex.on_client_line(b64("secret"))
    ex.on_client_line("*")
    ex.on_client_line(b64("mallory"))
    assert ex.username == "alice"
    assert not ex.cancelled


def test_non_ascii_mechanism_rejected() -> None:
    with pytest.raises(AuthSyntaxError):
        AuthExchange("PLA\u0131N", None)


@pytest.mark.parametrize("line", [
    b"AUTH=PLAIN secret",
    b"AUTH AAAAsecret+/==",
    b"AUTH PLAIN\x1csecret",
    b"AUTH PLAIN\xc2\xa0secret",
    b"AUTH PLAIN\x00secret",
    b"AUTH PLAIN\tsecret",
    b"AUTH   PLAIN   secret",
    b"\tAUTH PLAIN secret",
    b"AUTH PLAIN secret\r",
    b"AUTH PLAIN secret\r\n",
    b"AUTH " + b"X" * 30 + b" secret",
])
def test_redact_never_leaks(line: bytes) -> None:
    out = redact_auth(line, False)
    assert b"secret" not in out
    assert out.endswith(b"<redacted>")


def test_redact_keeps_bare_auth_forms() -> None:
    assert redact_auth(b"AUTH LOGIN\r\n", False) == b"AUTH LOGIN\r\n"
    assert redact_auth(b"AUTH", False) == b"AUTH"
    assert redact_auth(b"AUTH=PLAIN secret", False) == b"AUTH <redacted>"
    assert redact_auth(b"AUTH  PLAIN \tx", False) == b"AUTH  PLAIN <redacted>"


def test_redact_only_plain_login_tokens_kept() -> None:
    assert redact_auth(b"AUTH dGVzdA", False) == b"AUTH <redacted>"
    assert redact_auth(b"AUTH CRAM-MD5 abc", False) == b"AUTH <redacted>"
    assert redact_auth(b"AUTH CRAM-MD5", False) == b"AUTH <redacted>"
    assert redact_auth(b"AUTH plain secret", False) == b"AUTH plain <redacted>"
    assert redact_auth(b"auth Login", False) == b"auth Login"
