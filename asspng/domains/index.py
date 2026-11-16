# SPDX-License-Identifier: GPL-3.0-or-later
"""Local domain index and its on-disk snapshot.

The relay decision asks the index whether a recipient domain is local. The snapshot
lets the proxy start, or keep working, while MySQL is down.
"""

import json
import logging
import os
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from asspng.smtp.address import AddressError, normalize_domain

log = logging.getLogger(__name__)

_SNAPSHOT_VERSION = 1
_SNAPSHOT_MODE = 0o640


@dataclass(frozen=True)
class DomainEntry:
    domain: str
    include_subdomains: bool
    enabled: bool = True


def _is_storable(domain: str) -> bool:
    """Reject empty names and stray brackets; a bracketed literal must be whole."""
    if domain == "":
        return False
    if domain.startswith("["):
        return "[" not in domain[1:] and "]" not in domain[:-1]
    return "[" not in domain and "]" not in domain


class DomainIndex:
    """Set-based lookup of local domains.

    ``len()`` counts the valid entries held, including disabled ones.
    """

    def __init__(self, entries: Iterable[DomainEntry], available: bool = True) -> None:
        self.available = available
        self._count = 0
        self._exact: set[str] = set()
        self._with_subdomains: set[str] = set()
        for entry in entries:
            try:
                domain = normalize_domain(entry.domain)
            except AddressError:
                log.warning("skipping local domain entry with invalid domain %r", entry.domain)
                continue
            if not _is_storable(domain):
                log.warning("skipping local domain entry with invalid domain %r", entry.domain)
                continue
            self._count += 1
            if not entry.enabled:
                continue
            self._exact.add(domain)
            if entry.include_subdomains and not domain.startswith("["):
                self._with_subdomains.add(domain)

    @classmethod
    def unavailable(cls) -> "DomainIndex":
        return cls([], available=False)

    def __len__(self) -> int:
        return self._count

    def is_local(self, domain: str) -> bool:
        if domain == "":
            return True
        try:
            name = normalize_domain(domain)
        except AddressError:
            return False
        if name == "":
            return False
        if name in self._exact:
            return True
        if name.startswith("["):
            return False
        # Walk the parent labels: a.b.example.com -> b.example.com -> example.com -> com
        labels = name.split(".")
        for i in range(1, len(labels)):
            if ".".join(labels[i:]) in self._with_subdomains:
                return True
        return False


def save_snapshot(path: Path, entries: Sequence[DomainEntry]) -> None:
    """Write the snapshot atomically: temp file, fsync, rename, mode 0640."""
    payload = {
        "version": _SNAPSHOT_VERSION,
        "entries": [
            {
                "domain": e.domain,
                "include_subdomains": e.include_subdomains,
                "enabled": e.enabled,
            }
            for e in entries
        ],
    }
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_name, _SNAPSHOT_MODE)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def load_snapshot(path: Path) -> list[DomainEntry] | None:
    """Return the snapshot entries, or None if missing, unreadable or corrupt."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != _SNAPSHOT_VERSION \
            or isinstance(data.get("version"), bool):
        return None
    raw = data.get("entries")
    if not isinstance(raw, list):
        return None
    result: list[DomainEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            return None
        domain = item.get("domain")
        sub = item.get("include_subdomains")
        enabled = item.get("enabled")
        if not isinstance(domain, str) or not isinstance(sub, bool) \
                or not isinstance(enabled, bool):
            return None
        result.append(DomainEntry(domain, sub, enabled))
    return result
