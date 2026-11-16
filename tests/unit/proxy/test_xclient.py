# SPDX-License-Identifier: GPL-3.0-or-later
from ipaddress import ip_address

from asspng.proxy.xclient import format_xclient


def test_xclient_v4():
    line = format_xclient(ip_address("192.0.2.7"), 4321, "mail.example.org")
    assert line == b"XCLIENT ADDR=192.0.2.7 PORT=4321 NAME=mail.example.org\r\n"


def test_xclient_v6_prefix():
    line = format_xclient(ip_address("2001:db8::1"), 25, "[UNAVAILABLE]")
    assert line == b"XCLIENT ADDR=IPV6:2001:db8::1 PORT=25 NAME=[UNAVAILABLE]\r\n"


def test_xtext_escapes_plus_and_space():
    line = format_xclient(ip_address("192.0.2.7"), 1, "a b+c=dé")
    assert line.endswith(b" NAME=a+20b+2Bc+3Dd+C3+A9\r\n")
