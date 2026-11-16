# SPDX-License-Identifier: GPL-3.0-or-later
"""Immutable configuration snapshot produced by the loader."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from asspng.net.ipnet import NetworkSet


class ListenerKind(Enum):
    SMTP = "smtp"
    SUBMISSION = "submission"
    SUBMISSIONS = "submissions"


@dataclass(frozen=True)
class ListenerConfig:
    name: str
    kind: ListenerKind
    port: int
    ipv4: bool
    ipv6: bool
    bind4: str
    bind6: str
    backend_host: str
    backend_port: int
    xclient: bool
    auth: bool


@dataclass(frozen=True)
class CertificateConfig:
    """One entry of the shared certificate store; the files are not opened here."""

    name: str
    hostnames: tuple[str, ...]
    cert: Path
    key: Path


@dataclass(frozen=True)
class ConfigSnapshot:
    """Validated configuration. ``system`` holds every SYSTEM key (resolved);
    the layer mappings hold only the keys set in their files, coerced."""

    system: Mapping[str, object]
    listeners: tuple[ListenerConfig, ...]
    certificates: tuple[CertificateConfig, ...]
    default_layer: Mapping[str, object]
    domain_layers: Mapping[str, Mapping[str, object]]
    user_layers: Mapping[str, Mapping[str, object]]
    trusted: NetworkSet
    exempt: NetworkSet
    etc_dir: Path

    def get(self, key: str) -> object:
        """Return a SYSTEM value; raises KeyError for any other key."""
        return self.system[key]
