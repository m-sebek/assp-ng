# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path

import pytest

from asspng.config.loader import load_config
from asspng.config.policy import PolicyResolver
from asspng.smtp.address import Address, parse_path


def write(etc_dir: Path, sub: str, name: str, text: str) -> None:
    (etc_dir / sub).mkdir(exist_ok=True)
    (etc_dir / sub / f"{name}.toml").write_text(text, encoding="utf-8")


def rcpt(text: str) -> Address:
    address = parse_path(f"<{text}>")
    assert address is not None
    return address


def resolver(etc_dir: Path) -> PolicyResolver:
    return PolicyResolver(load_config(etc_dir))


def test_user_over_domain_over_default(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("scoring.limit = 60\n")
    write(etc_dir, "domain.d", "example.com", "scoring.limit = 80\n")
    write(etc_dir, "user.d", "jano@example.com", "scoring.limit = 99\n")
    r = resolver(etc_dir)
    user = r.for_recipient(rcpt("jano@example.com"))
    assert (user.values["scoring.limit"], user.sources["scoring.limit"]) == (99, "user")
    dom = r.for_recipient(rcpt("eva@example.com"))
    assert (dom.values["scoring.limit"], dom.sources["scoring.limit"]) == (80, "domain")
    dflt = r.for_recipient(rcpt("eva@other.org"))
    assert (dflt.values["scoring.limit"], dflt.sources["scoring.limit"]) == (60, "default")


def test_builtin_source(etc_dir: Path) -> None:
    p = resolver(etc_dir).for_recipient(rcpt("a@example.com"))
    assert p.values["scoring.limit"] == 50
    assert p.sources["scoring.limit"] == "built-in"
    assert "limits.user.messages_per_minute" not in p.values
    assert set(p.values) == set(p.sources)


def test_same_effective_values_same_fingerprint(etc_dir: Path) -> None:
    write(etc_dir, "domain.d", "example.com", "scoring.limit = 80\n")
    write(etc_dir, "user.d", "jano@example.com", "scoring.limit = 80\n")
    r = resolver(etc_dir)
    a = r.for_recipient(rcpt("jano@example.com"))
    b = r.for_recipient(rcpt("eva@example.com"))
    assert a.sources != b.sources
    assert a.fingerprint == b.fingerprint
    assert len(a.fingerprint) == 16


def test_different_testmode_different_fingerprint(etc_dir: Path) -> None:
    write(etc_dir, "user.d", "jano@example.com", "testmode = true\n")
    r = resolver(etc_dir)
    assert (r.for_recipient(rcpt("jano@example.com")).fingerprint
            != r.for_recipient(rcpt("eva@example.com")).fingerprint)


def test_idn_recipient_finds_domain_file(etc_dir: Path) -> None:
    write(etc_dir, "domain.d", "xn--bcher-kva.example", "scoring.limit = 77\n")
    p = resolver(etc_dir).for_recipient(rcpt("jano@BÜCHER.example"))
    assert p.values["scoring.limit"] == 77
    assert p.sources["scoring.limit"] == "domain"


def test_sender_policy_uses_user_layer(etc_dir: Path) -> None:
    write(etc_dir, "domain.d", "example.com", "limits.user.messages_per_hour = 200\n")
    write(etc_dir, "user.d", "jano@example.com", "limits.user.messages_per_minute = 5\n")
    r = resolver(etc_dir)
    p = r.for_sender("jano@example.com")
    assert p.values["limits.user.messages_per_minute"] == 5
    assert p.sources["limits.user.messages_per_minute"] == "user"
    assert p.values["limits.user.messages_per_hour"] == 200
    assert p.sources["limits.user.messages_per_hour"] == "domain"
    assert "scoring.limit" not in p.values


@pytest.mark.parametrize("username", ["", "plainuser", "@", "a@", "@b", "bad name@x@y"])
def test_sender_odd_usernames_use_defaults(etc_dir: Path, username: str) -> None:
    p = resolver(etc_dir).for_sender(username)
    assert p.values["limits.user.messages_per_minute"] == 30
    assert p.sources["limits.user.messages_per_minute"] == "built-in"


def test_default_policy_and_immutability(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("scoring.limit = 60\n")
    p = resolver(etc_dir).default_policy()
    assert p.sources["scoring.limit"] == "default"
    with pytest.raises(TypeError):
        p.values["scoring.limit"] = 1  # type: ignore[index]
