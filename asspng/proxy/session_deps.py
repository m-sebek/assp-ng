# SPDX-License-Identifier: GPL-3.0-or-later
"""What a ``Session`` needs from the rest of the proxy, shared by all sessions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from asspng.checks.engine import CheckEngine
from asspng.checks.limits import AuthLimitsCheck
from asspng.checks.penalty_box import PenaltyBox
from asspng.config.model import ConfigSnapshot, ListenerConfig
from asspng.config.policy import PolicyResolver
from asspng.domains.index import DomainIndex
from asspng.log.debug import DebugLog, DebugRules
from asspng.log.maillog import MaillogRecord
from asspng.net.dns import PtrResolver
from asspng.proxy.backend import Backend
from asspng.proxy.buffer import BufferBudget
from asspng.proxy.connections import ConnectionTracker
from asspng.state.controller import StateController
from asspng.tls.store import CertificateStore


class HealthCounters(Protocol):
    """Health and alert counters, shared by all sessions."""

    def record(self, event: str) -> None: ...

    def backend_result(self, listener: str, ok: bool) -> int:
        """Record a backend connection attempt; return the consecutive failures."""
        ...


@dataclass
class SessionDeps:
    """Everything a session uses. ``clock`` returns wall-clock seconds (like ``time.time``)."""

    config: ConfigSnapshot
    policies: PolicyResolver
    listener: ListenerConfig
    backend_factory: Callable[[ListenerConfig], Backend]
    engine: CheckEngine
    state: StateController
    penalty_box: PenaltyBox
    auth_limits: AuthLimitsCheck
    domains: Callable[[], DomainIndex]
    tls: CertificateStore
    resolver: PtrResolver
    connections: ConnectionTracker
    budget: BufferBudget
    maillog: Callable[[MaillogRecord], None]
    debug_rules: DebugRules
    debug_log: DebugLog
    health: HealthCounters
    memory_over_limit: Callable[[], bool]
    clock: Callable[[], float]
