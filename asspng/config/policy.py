# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-recipient and per-sender policy resolution (mailbox, domain, default, built-in)."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType

from asspng.config.model import ConfigSnapshot
from asspng.config.registry import Level, Registry
from asspng.config.settings import REGISTRY
from asspng.smtp.address import Address, parse_path

_EMPTY: Mapping[str, object] = MappingProxyType({})


@dataclass(frozen=True)
class Policy:
    """Resolved settings; ``fingerprint`` groups recipients that may share a transaction."""

    values: Mapping[str, object]
    sources: Mapping[str, str]
    fingerprint: str


class PolicyResolver:
    def __init__(self, snapshot: ConfigSnapshot, registry: Registry = REGISTRY) -> None:
        self._snapshot = snapshot
        self._registry = registry
        self._builtin: dict[Level, dict[str, object]] = {
            level: {s.key: self._freeze(registry.coerce(s.key, s.default))
                    for s in registry.all() if s.level is level}
            for level in (Level.RECIPIENT, Level.SENDER)
        }
        self._recipient_cached = lru_cache(maxsize=4096)(self._resolve_recipient)

    @staticmethod
    def _freeze(value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    def for_recipient(self, rcpt: Address) -> Policy:
        key = rcpt.key  # Address.domain keeps its original form; the key is normalized
        return self._recipient_cached(key, key.rpartition("@")[2])

    def for_sender(self, username: str) -> Policy:
        user_layer: Mapping[str, object] = _EMPTY
        domain_layer: Mapping[str, object] = _EMPTY
        if "@" in username:
            try:
                address = parse_path(f"<{username}>")
            except ValueError:  # AddressError; usernames come from AUTH
                address = None
            if address is not None:
                user_layer = self._snapshot.user_layers.get(address.key, _EMPTY)
                domain = address.key.rpartition("@")[2]
                domain_layer = self._snapshot.domain_layers.get(domain, _EMPTY)
        return self._build(Level.SENDER, user_layer, domain_layer)

    def default_policy(self) -> Policy:
        return self._build(Level.RECIPIENT, _EMPTY, _EMPTY)

    def _resolve_recipient(self, key: str, domain: str) -> Policy:
        return self._build(Level.RECIPIENT,
                           self._snapshot.user_layers.get(key, _EMPTY),
                           self._snapshot.domain_layers.get(domain, _EMPTY))

    def _build(self, level: Level, user: Mapping[str, object],
               domain: Mapping[str, object]) -> Policy:
        layers = (("user", user), ("domain", domain),
                  ("default", self._snapshot.default_layer))
        values: dict[str, object] = {}
        sources: dict[str, str] = {}
        for key, builtin in self._builtin[level].items():
            for name, layer in layers:
                if key in layer:
                    values[key] = self._freeze(layer[key])
                    sources[key] = name
                    break
            else:
                values[key] = builtin
                sources[key] = "built-in"
        return Policy(MappingProxyType(values), MappingProxyType(sources),
                      self._fingerprint(values))

    def _fingerprint(self, values: Mapping[str, object]) -> str:
        items = sorted((k, v) for k, v in values.items() if self._registry.get(k).fingerprint)
        return hashlib.sha256(repr(items).encode("utf-8")).hexdigest()[:16]
