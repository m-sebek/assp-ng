# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration scopes (``sys``, ``default``, ``domain:<d>``, ``user:<a>``) and their files.

The scope text comes from the command line and becomes part of a file name, so it is
validated strictly: no path separators, dots at the start, whitespace or control
characters, and a domain or address that is valid after normalisation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from asspng.smtp.address import AddressError, normalize_domain, parse_path

_DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*")
_LOCAL_RE = re.compile(r"[a-z0-9!#$%&'*+=?^_`{|}~-][a-z0-9!#$%&'*+=?^_`{|}~.-]*")
_MAX_NAME = 255 - len(".toml.bak")


class ScopeError(ValueError):
    """The scope text is not acceptable."""


@dataclass(frozen=True)
class Scope:
    """``kind`` is sys, default, domain or user; ``name`` is the normalised domain/address."""

    kind: str
    name: str

    @property
    def text(self) -> str:
        return self.kind if not self.name else f"{self.kind}:{self.name}"

    @property
    def system(self) -> bool:
        return self.kind == "sys"

    def path(self, etc_dir: Path) -> Path:
        if self.kind == "sys":
            return etc_dir / "assp-ng.toml"
        if self.kind == "default":
            return etc_dir / "default.toml"
        directory = etc_dir / ("domain.d" if self.kind == "domain" else "user.d")
        path = directory / f"{self.name}.toml"
        if path.parent != directory or path.name != f"{self.name}.toml":
            raise ScopeError("scope does not name a plain file")  # defence in depth
        return path


def looks_like_scope(text: str) -> bool:
    return text in ("sys", "default") or text.startswith(("domain:", "user:"))


def _unsafe(text: str) -> bool:
    return (any(c in "/\\" or c.isspace() or not c.isprintable() for c in text)
            or ".." in text)


def parse_scope(text: str) -> Scope:
    if _unsafe(text):
        raise ScopeError("scope contains a forbidden character or sequence")
    if text in ("sys", "default"):
        return Scope(text, "")
    kind, _, name = text.partition(":")
    if kind not in ("domain", "user") or not name or name.startswith("."):
        raise ScopeError("scope must be sys, default, domain:<domain> or user:<address>")
    if kind == "domain":
        return Scope("domain", _domain(name))
    return Scope("user", _address(name))


def _domain(name: str) -> str:
    try:
        domain = normalize_domain(name)
    except (AddressError, UnicodeError):
        raise ScopeError("not a valid domain") from None
    if not _DOMAIN_RE.fullmatch(domain) or len(domain) > _MAX_NAME:
        raise ScopeError("not a valid domain")
    return domain


def _address(name: str) -> str:
    try:
        address = parse_path(f"<{name}>")
        key = address.key if address is not None and address.domain else ""
    except (AddressError, UnicodeError):
        key = ""
    local, _, domain = key.rpartition("@")
    if not key or not _LOCAL_RE.fullmatch(local) or len(key) > _MAX_NAME:
        raise ScopeError("not a valid mailbox address")
    return f"{local}@{_domain(domain)}"
