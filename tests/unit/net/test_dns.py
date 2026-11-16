# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the forward-confirmed PTR resolver, using a fake DNS resolver."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename
import pytest
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.ANY.PTR import PTR
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA

from asspng.net.dns import DnsPtrResolver, PtrResult, _valid_hostname
from asspng.net.ipnet import parse_ip

REV4 = "5.113.0.203.in-addr.arpa."


class FakeResolver:
    """Maps (qname, rdtype) to a list of rdata, an exception, or a coroutine function."""

    def __init__(self, table: dict[tuple[str, str], Any]) -> None:
        self.table = table
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, qname: Any, rdtype: str, lifetime: float | None = None) -> Any:
        key = (str(qname).lower(), rdtype)
        self.calls.append(key)
        result = self.table.get(key, dns.resolver.NXDOMAIN())
        if callable(result):
            result = await result()
        if isinstance(result, BaseException):
            raise result
        return result


def ptr(*names: str) -> list[Any]:
    """Real dnspython PTR rdata, so ``to_text()`` escapes the target as for names from the
    wire and the resolver sees the same types as from a real answer."""
    return [PTR(dns.rdataclass.IN, dns.rdatatype.PTR, dns.name.from_text(n)) for n in names]


def addrs(*values: str) -> list[Any]:
    """Real A or AAAA rdata for the given addresses."""
    return [
        AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, v) if ":" in v
        else A(dns.rdataclass.IN, dns.rdatatype.A, v)
        for v in values
    ]


def make(table: dict[tuple[str, str], Any], **kw: Any) -> tuple[DnsPtrResolver, FakeResolver]:
    fake = FakeResolver(table)
    kw.setdefault("timeout_s", 1.0)
    return DnsPtrResolver(resolver=fake, **kw), fake  # type: ignore[arg-type]


async def test_forward_confirmed() -> None:
    r, _ = make({
        (REV4, "PTR"): ptr("Mail.Example.org."),
        ("mail.example.org.", "A"): addrs("203.0.113.5"),
    })
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult("mail.example.org", False)


async def test_forward_confirmed_ipv6() -> None:
    addr = parse_ip("2001:db8::1")
    rev = str(dns.reversename.from_address("2001:db8::1"))
    r, _ = make({
        (rev, "PTR"): ptr("v6.example.org."),
        ("v6.example.org.", "AAAA"): addrs("2001:0db8:0:0:0:0:0:1"),
    })
    assert (await r.lookup(addr)).name == "v6.example.org"


async def test_not_confirmed_is_unavailable() -> None:
    r, _ = make({
        (REV4, "PTR"): ptr("fake.example.org."),
        ("fake.example.org.", "A"): addrs("198.51.100.1"),
    })
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, False)


async def test_second_target_confirms_and_limit_of_five() -> None:
    names = [f"h{i}.example.org." for i in range(7)]
    table: dict[tuple[str, str], Any] = {(REV4, "PTR"): ptr(*names)}
    for n in names:
        table[(n, "A")] = addrs("198.51.100.1")
    table[(names[1], "A")] = addrs("203.0.113.5")
    r, _ = make(table)
    assert (await r.lookup(parse_ip("203.0.113.5"))).name == "h1.example.org"
    table[(names[1], "A")] = addrs("198.51.100.1")
    table[(names[6], "A")] = addrs("203.0.113.5")
    r, fake = make(table)
    assert (await r.lookup(parse_ip("203.0.113.5"))) == PtrResult(None, False)
    assert len([c for c in fake.calls if c[1] == "A"]) == 5


async def test_nxdomain_is_definitive() -> None:
    r, _ = make({})
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, False)


async def test_noanswer_is_definitive() -> None:
    r, _ = make({(REV4, "PTR"): dns.resolver.NoAnswer()})
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, False)


@pytest.mark.parametrize("exc", [
    dns.resolver.LifetimeTimeout(), dns.resolver.NoNameservers(), dns.exception.DNSException(),
])
async def test_ptr_failures_are_temporary(exc: Exception) -> None:
    r, _ = make({(REV4, "PTR"): exc})
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, True)


async def test_forward_timeout_is_temporary() -> None:
    r, _ = make({
        (REV4, "PTR"): ptr("a.example.org."),
        ("a.example.org.", "A"): dns.resolver.LifetimeTimeout(),
    })
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, True)


async def test_forward_failure_but_later_confirmation_wins() -> None:
    r, _ = make({
        (REV4, "PTR"): ptr("a.example.org.", "b.example.org."),
        ("a.example.org.", "A"): dns.resolver.NoNameservers(),
        ("b.example.org.", "A"): addrs("203.0.113.5"),
    })
    assert (await r.lookup(parse_ip("203.0.113.5"))).name == "b.example.org"


async def test_forward_nxdomain_not_temporary() -> None:
    r, _ = make({
        (REV4, "PTR"): ptr("a.example.org."),
        ("a.example.org.", "A"): dns.resolver.NXDOMAIN(),
    })
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, False)


async def test_timeout_is_tempunavail() -> None:
    async def slow() -> Any:
        await asyncio.sleep(5)

    r, _ = make({(REV4, "PTR"): slow}, timeout_s=0.05)
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, True)


async def test_unexpected_exception_is_tempunavail() -> None:
    r, _ = make({(REV4, "PTR"): RuntimeError("boom")})
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, True)


async def test_cancellation_propagates() -> None:
    started = asyncio.Event()

    async def hang() -> Any:
        started.set()
        await asyncio.sleep(30)

    r, _ = make({(REV4, "PTR"): hang}, timeout_s=10)
    task = asyncio.ensure_future(r.lookup(parse_ip("203.0.113.5")))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_cache_hit() -> None:
    r, fake = make({
        (REV4, "PTR"): ptr("mail.example.org."),
        ("mail.example.org.", "A"): addrs("203.0.113.5"),
    })
    a = parse_ip("203.0.113.5")
    assert await r.lookup(a) == await r.lookup(a)
    assert len(fake.calls) == 2


async def test_negative_definitive_cached_and_temporary_not() -> None:
    r, fake = make({})
    a = parse_ip("203.0.113.5")
    await r.lookup(a)
    await r.lookup(a)
    assert len(fake.calls) == 1
    r, fake = make({(REV4, "PTR"): dns.resolver.LifetimeTimeout()})
    await r.lookup(a)
    await r.lookup(a)
    assert len(fake.calls) == 2


async def test_cache_expiry_uses_clock() -> None:
    now = [100.0]
    r, fake = make({}, cache_ttl_s=60, clock=lambda: now[0])
    a = parse_ip("203.0.113.5")
    await r.lookup(a)
    now[0] += 59
    await r.lookup(a)
    assert len(fake.calls) == 1
    now[0] += 2
    await r.lookup(a)
    assert len(fake.calls) == 2


async def test_cache_bounded_oldest_evicted() -> None:
    r, fake = make({}, max_entries=2)
    a, b, c = (parse_ip(f"203.0.113.{i}") for i in (1, 2, 3))
    for x in (a, b, c):
        await r.lookup(x)
    assert len(fake.calls) == 3
    await r.lookup(c)
    await r.lookup(b)
    assert len(fake.calls) == 3
    await r.lookup(a)
    assert len(fake.calls) == 4


def test_xclient_value() -> None:
    assert PtrResult("mail.example.org", False).xclient_value == "mail.example.org"
    assert PtrResult(None, False).xclient_value == "[UNAVAILABLE]"
    assert PtrResult(None, True).xclient_value == "[TEMPUNAVAIL]"


@pytest.mark.parametrize("bad", [
    "bad host.example.org.", "back\\\\slash.example.org.", "a<b.example.org.", ".",
    "caf\\195\\169.example.org.",  # raw UTF-8 bytes in a label: to_text() escapes them
    "-lead.example.org.", "trail-.example.org.",
])
async def test_invalid_hostname_not_confirmed(bad: str) -> None:
    r, fake = make({
        (REV4, "PTR"): ptr(bad),
        (bad.lower(), "A"): addrs("203.0.113.5"),
    })
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, False)
    assert [c for c in fake.calls if c[1] == "A"] == []


def test_hostname_length_limits() -> None:
    """Names from dnspython cannot exceed them; the check stays as defence in depth."""
    assert _valid_hostname("a" * 63 + ".example.org")
    assert not _valid_hostname("a" * 64 + ".example.org")
    assert not _valid_hostname(".".join(["a" * 63] * 4))  # 255 characters


async def test_only_ptr_and_address_rdata_are_used() -> None:
    """A record of another type in an answer is skipped, never read as a target or address."""
    other = CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, dns.name.from_text("cname.example.org."))
    r, fake = make({
        (REV4, "PTR"): [other],
        ("cname.example.org.", "A"): addrs("203.0.113.5"),
    })
    assert await r.lookup(parse_ip("203.0.113.5")) == PtrResult(None, False)
    assert [c for c in fake.calls if c[1] == "A"] == []

    r, _ = make({
        (REV4, "PTR"): ptr("mail.example.org."),
        ("mail.example.org.", "A"): [other, *addrs("203.0.113.5")],
    })
    assert (await r.lookup(parse_ip("203.0.113.5"))).name == "mail.example.org"


async def test_invalid_target_skipped_next_confirms() -> None:
    r, _ = make({
        (REV4, "PTR"): ptr("a<b.example.org.", "ok.example.org."),
        ("ok.example.org.", "A"): addrs("203.0.113.5"),
    })
    assert (await r.lookup(parse_ip("203.0.113.5"))).name == "ok.example.org"
