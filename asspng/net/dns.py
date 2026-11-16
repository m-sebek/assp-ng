# SPDX-License-Identifier: GPL-3.0-or-later
"""Forward-confirmed reverse DNS (PTR) lookup for the connecting client."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
from dns.rdtypes.ANY.PTR import PTR
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA

from asspng.net.ipnet import IPAddress

log = logging.getLogger(__name__)

MAX_PTR_TARGETS = 5
_LABEL_RE = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
MAX_NAME_LEN = 253


def _valid_hostname(name: str) -> bool:
    """True for a non-empty dotted name of plain hostname labels."""
    if not name or len(name) > MAX_NAME_LEN:
        return False
    return all(_LABEL_RE.fullmatch(label) for label in name.split("."))


@dataclass(frozen=True)
class PtrResult:
    """Outcome of a PTR lookup: a confirmed name, or none (temporary when DNS failed)."""

    name: str | None
    temporary: bool

    @property
    def xclient_value(self) -> str:
        """Value for the XCLIENT NAME= attribute."""
        if self.name is not None:
            return self.name
        return "[TEMPUNAVAIL]" if self.temporary else "[UNAVAILABLE]"


class PtrResolver(Protocol):
    """Anything that can resolve a client address to a forward-confirmed name."""

    async def lookup(self, addr: IPAddress) -> PtrResult: ...


class DnsPtrResolver:
    """PTR resolver with forward confirmation, one time budget and a bounded cache."""

    def __init__(
        self,
        timeout_s: float,
        cache_ttl_s: int = 3600,
        clock: Callable[[], float] = time.monotonic,
        resolver: dns.asyncresolver.Resolver | None = None,
        max_entries: int = 10000,
    ) -> None:
        self._timeout_s = timeout_s
        self._ttl = cache_ttl_s
        self._clock = clock
        self._resolver = resolver if resolver is not None else dns.asyncresolver.Resolver()
        self._max_entries = max_entries
        self._cache: OrderedDict[str, tuple[float, PtrResult]] = OrderedDict()

    async def lookup(self, addr: IPAddress) -> PtrResult:
        """Resolve addr; never raises except CancelledError."""
        key = str(addr)
        cached = self._cache.get(key)
        if cached is not None:
            if cached[0] > self._clock():
                return cached[1]
            del self._cache[key]
        try:
            result = await asyncio.wait_for(self._resolve(addr), self._timeout_s)
        except TimeoutError:
            return PtrResult(None, True)
        except Exception:
            log.debug("PTR lookup for %s failed unexpectedly", key, exc_info=True)
            return PtrResult(None, True)
        if not result.temporary:
            self._store(key, result)
        return result

    def _store(self, key: str, result: PtrResult) -> None:
        self._cache.pop(key, None)
        self._cache[key] = (self._clock() + self._ttl, result)
        while len(self._cache) > self._max_entries:
            self._cache.popitem(last=False)

    async def _resolve(self, addr: IPAddress) -> PtrResult:
        rev = dns.reversename.from_address(str(addr))
        try:
            answer = await self._resolver.resolve(rev, "PTR", lifetime=self._timeout_s)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return PtrResult(None, False)
        except dns.exception.DNSException:
            return PtrResult(None, True)
        rrtype = "A" if isinstance(addr, IPv4Address) else "AAAA"
        temporary = False
        # Only PTR (and below A/AAAA) records are read: their types carry ``target`` and
        # ``address``, and a record of any other type in an answer is ignored.
        targets = [rdata for rdata in answer if isinstance(rdata, PTR)][:MAX_PTR_TARGETS]
        for rdata in targets:
            text = rdata.target.to_text()
            name = text.rstrip(".").lower()
            if not _valid_hostname(name):
                continue
            try:
                fwd = await self._resolver.resolve(text, rrtype, lifetime=self._timeout_s)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException:
                temporary = True
                continue
            if any(isinstance(r, (A, AAAA)) and _same_address(r.address, addr) for r in fwd):
                return PtrResult(name, False)
        return PtrResult(None, temporary)


def _same_address(text: str, addr: IPAddress) -> bool:
    try:
        return ip_address(text) == addr
    except ValueError:
        return False
