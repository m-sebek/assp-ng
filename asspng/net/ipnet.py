# SPDX-License-Identifier: GPL-3.0-or-later
"""IP address and network helpers used to key per-network state."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


def parse_ip(text: str) -> IPAddress:
    """Parse an address, stripping brackets and a %zone and unwrapping IPv4-mapped IPv6."""
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.split("%", 1)[0]
    return _unmap(ip_address(text))


def _unmap(addr: IPAddress) -> IPAddress:
    """Return the embedded IPv4 address for an IPv4-mapped IPv6 address, else addr."""
    if isinstance(addr, IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def network_key(addr: IPAddress, v4_prefix: int = 32, v6_prefix: int = 64) -> str:
    """Return the CIDR string of the network containing addr, used as a state key."""
    addr = _unmap(addr)
    prefix = v4_prefix if isinstance(addr, IPv4Address) else v6_prefix
    return str(ip_network(f"{addr}/{prefix}", strict=False))


def is_private(addr: IPAddress) -> bool:
    """True for private, loopback, link-local, unspecified and reserved addresses."""
    addr = _unmap(addr)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    )


def parse_cidr_strict(text: str) -> IPNetwork:
    """Parse a CIDR; host bits must be clear. A bare address is a single-host network."""
    return ip_network(text.strip(), strict=True)


class NetworkSet:
    """A small set of networks with membership tests (linear scan per family)."""

    def __init__(self, networks: Iterable[IPNetwork]) -> None:
        self._v4: list[IPv4Network] = []
        self._v6: list[IPv6Network] = []
        for net in networks:
            if isinstance(net, IPv4Network):
                self._v4.append(net)
            else:
                self._v6.append(net)

    def __contains__(self, addr: object) -> bool:
        if isinstance(addr, (IPv4Address, IPv6Address)):
            addr = _unmap(addr)
        if isinstance(addr, IPv4Address):
            return any(addr in net for net in self._v4)
        if isinstance(addr, IPv6Address):
            return any(addr in net for net in self._v6)
        return False

    def __len__(self) -> int:
        return len(self._v4) + len(self._v6)


def load_network_file(path: Path) -> list[IPNetwork]:
    """Load networks, one per line; '#' comments and blank lines are ignored."""
    networks: list[IPNetwork] = []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: not valid UTF-8: {exc.reason}") from exc
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            networks.append(parse_cidr_strict(line))
        except ValueError as exc:
            raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return networks
