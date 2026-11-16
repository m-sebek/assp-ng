# SPDX-License-Identifier: GPL-3.0-or-later
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest

from asspng.net.ipnet import (
    NetworkSet,
    is_private,
    load_network_file,
    network_key,
    parse_cidr_strict,
    parse_ip,
)


def test_mapped_ipv4_is_ipv4() -> None:
    assert parse_ip("::ffff:203.0.113.5") == IPv4Address("203.0.113.5")


def test_bracketed_v6() -> None:
    assert parse_ip("[2001:db8::1]") == IPv6Address("2001:db8::1")


def test_zone_is_stripped() -> None:
    assert parse_ip("fe80::1%eth0") == IPv6Address("fe80::1")


def test_invalid_ip_raises() -> None:
    with pytest.raises(ValueError):
        parse_ip("not-an-ip")


def test_key_v4() -> None:
    assert network_key(parse_ip("203.0.113.5")) == "203.0.113.5/32"


def test_key_v6_64() -> None:
    assert network_key(parse_ip("2001:db8:1:2:3:4:5:6")) == "2001:db8:1:2::/64"


def test_key_mapped() -> None:
    assert network_key(parse_ip("::ffff:203.0.113.5")) == "203.0.113.5/32"


def test_key_custom_prefixes() -> None:
    assert network_key(parse_ip("203.0.113.5"), v4_prefix=24) == "203.0.113.0/24"
    assert network_key(parse_ip("2001:db8:1:2::1"), v6_prefix=48) == "2001:db8:1::/48"


def test_private() -> None:
    assert is_private(parse_ip("10.1.2.3"))
    assert is_private(parse_ip("::1"))
    assert is_private(parse_ip("fe80::1"))
    assert not is_private(parse_ip("8.8.8.8"))


def test_strict_rejects_host_bits() -> None:
    with pytest.raises(ValueError):
        parse_cidr_strict("203.0.113.5/24")


def test_strict_bare() -> None:
    assert str(parse_cidr_strict("2001:db8::1")) == "2001:db8::1/128"
    assert str(parse_cidr_strict("192.0.2.7")) == "192.0.2.7/32"


def test_networkset() -> None:
    s = NetworkSet([parse_cidr_strict("192.0.2.0/24"), parse_cidr_strict("2001:db8::/32")])
    assert parse_ip("192.0.2.9") in s
    assert parse_ip("192.0.3.1") not in s
    assert parse_ip("2001:db8::5") in s
    assert parse_ip("2001:db9::5") not in s
    assert len(s) == 2


def test_file_loads(tmp_path: Path) -> None:
    p = tmp_path / "n.txt"
    p.write_text("# c\n\n192.0.2.0/24\n  2001:db8::/32  \n")
    assert [str(n) for n in load_network_file(p)] == ["192.0.2.0/24", "2001:db8::/32"]


def test_file_errors_carry_line(tmp_path: Path) -> None:
    p = tmp_path / "n.txt"
    p.write_text("# c\n192.0.2.0/24\nbogus\n")
    with pytest.raises(ValueError, match=":3:"):
        load_network_file(p)


def test_network_key_unmaps_raw_mapped_address() -> None:
    assert network_key(IPv6Address("::ffff:203.0.113.5")) == "203.0.113.5/32"


def test_networkset_matches_raw_mapped_address() -> None:
    s = NetworkSet([parse_cidr_strict("203.0.113.0/24")])
    assert IPv6Address("::ffff:203.0.113.5") in s
    assert IPv6Address("::ffff:203.0.114.5") not in s


def test_is_private_unmaps_raw_mapped_address() -> None:
    assert is_private(IPv6Address("::ffff:10.0.0.1"))
    assert not is_private(IPv6Address("::ffff:8.8.8.8"))


def test_file_inline_comment(tmp_path: Path) -> None:
    p = tmp_path / "n.txt"
    p.write_text("192.0.2.0/24 # office\n")
    assert [str(n) for n in load_network_file(p)] == ["192.0.2.0/24"]


def test_file_bad_encoding_names_path(tmp_path: Path) -> None:
    p = tmp_path / "n.txt"
    p.write_bytes(b"\xff\xfe\x00bad\n")
    with pytest.raises(ValueError, match="n.txt"):
        load_network_file(p)
