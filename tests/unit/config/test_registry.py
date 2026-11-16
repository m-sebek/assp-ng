# SPDX-License-Identifier: GPL-3.0-or-later
import string

import pytest

from asspng.config.errors import ConfigError
from asspng.config.registry import Level, Registry, Setting, parse_duration
from asspng.config.settings import REGISTRY


def test_duration() -> None:
    assert parse_duration("90d") == 7776000
    assert parse_duration("15m") == 900
    assert parse_duration("2h") == 7200
    assert parse_duration("30s") == 30
    assert parse_duration("45") == 45
    assert parse_duration(60) == 60  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["", "-5", "-5m", "1 m", " 1m", "5w", "m", "1.5h", "1mm"])
def test_duration_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(bad)


def test_duration_rejects_negative_int() -> None:
    with pytest.raises(ValueError):
        parse_duration(-1)  # type: ignore[arg-type]


def test_coerce_rejects_out_of_range() -> None:
    with pytest.raises(ConfigError) as exc:
        REGISTRY.coerce("scoring.limit", -1)
    assert "scoring.limit" in str(exc.value)
    assert exc.value.errors


def test_coerce_choices() -> None:
    with pytest.raises(ConfigError):
        REGISTRY.coerce("checks.conn_limits.mode", "maybe")
    assert REGISTRY.coerce("checks.conn_limits.mode", "score") == "score"


def test_levels() -> None:
    assert REGISTRY.get("testmode").level is Level.RECIPIENT
    assert REGISTRY.get("limits.user.messages_per_hour").level is Level.SENDER
    assert REGISTRY.get("redis.url").level is Level.SYSTEM


def test_all_keys_documented() -> None:
    allowed = set(string.printable) - set("\t\n\r\x0b\x0c")
    for s in REGISTRY.all():
        assert s.description, s.key
        assert set(s.description) <= allowed, s.key
        assert s.description.endswith("."), s.key


def test_every_default_coerces_and_fingerprint_matches_level() -> None:
    for s in REGISTRY.all():
        REGISTRY.coerce(s.key, s.default)
        assert s.fingerprint == (s.level is Level.RECIPIENT), s.key


def test_duplicate_register_raises() -> None:
    reg = Registry()
    s = Setting("a", "int", 1, Level.SYSTEM, "A.")
    reg.register(s)
    with pytest.raises(ValueError):
        reg.register(s)


def test_get_unknown_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        REGISTRY.get("no.such.key")
    with pytest.raises(KeyError):
        REGISTRY.coerce("no.such.key", 1)


def test_coerce_durations() -> None:
    assert REGISTRY.coerce("limits.auth.window", "15m") == 900
    assert REGISTRY.coerce("limits.auth.window", 30) == 30
    assert REGISTRY.coerce("penalty_box.ladder", ["24h", "7d"]) == [86400, 604800]
    assert REGISTRY.coerce("penalty_box.ladder", "24h, 7d") == [86400, 604800]
    with pytest.raises(ConfigError):
        REGISTRY.coerce("penalty_box.ladder", [])
    with pytest.raises(ConfigError):
        REGISTRY.coerce("limits.auth.window", "5w")


def test_coerce_int_strings_and_bool_rejection() -> None:
    assert REGISTRY.coerce("scoring.limit", "60") == 60
    assert REGISTRY.coerce("scoring.limit", "+60") == 60
    with pytest.raises(ConfigError):
        REGISTRY.coerce("scoring.limit", True)
    with pytest.raises(ConfigError):
        REGISTRY.coerce("scoring.limit", "6.5")
    with pytest.raises(ConfigError):
        REGISTRY.coerce("scoring.limit", 6.5)
    with pytest.raises(ConfigError):
        REGISTRY.coerce("scoring.limit", " 6")


def test_coerce_bool() -> None:
    for text, want in [("true", True), ("YES", True), ("On", True), ("1", True),
                       ("false", False), ("no", False), ("OFF", False), ("0", False)]:
        assert REGISTRY.coerce("testmode", text) is want
    assert REGISTRY.coerce("testmode", True) is True
    with pytest.raises(ConfigError):
        REGISTRY.coerce("testmode", "maybe")
    with pytest.raises(ConfigError):
        REGISTRY.coerce("testmode", 1)


def test_coerce_float_str_and_lists() -> None:
    reg = Registry()
    reg.register(Setting("f", "float", 1.5, Level.SYSTEM, "F.", minimum=0))
    reg.register(Setting("s", "str", "", Level.SYSTEM, "S."))
    reg.register(Setting("l", "list[str]", [], Level.SYSTEM, "L."))
    assert reg.coerce("f", "2.5") == 2.5
    assert reg.coerce("f", 2) == 2.0
    assert isinstance(reg.coerce("f", 2), float)
    with pytest.raises(ConfigError):
        reg.coerce("f", True)
    with pytest.raises(ConfigError):
        reg.coerce("f", "abc")
    assert reg.coerce("s", "x") == "x"
    with pytest.raises(ConfigError):
        reg.coerce("s", 5)
    assert reg.coerce("l", "a, b,c") == ["a", "b", "c"]
    assert reg.coerce("l", ["a", "b"]) == ["a", "b"]
    assert reg.coerce("l", "") == []
    with pytest.raises(ConfigError):
        reg.coerce("l", [1])


def test_network_prefix_bounds() -> None:
    assert REGISTRY.coerce("network.ipv4_prefix", 0) == 0
    with pytest.raises(ConfigError):
        REGISTRY.coerce("network.ipv4_prefix", 33)
    with pytest.raises(ConfigError):
        REGISTRY.coerce("network.ipv6_prefix", 129)
