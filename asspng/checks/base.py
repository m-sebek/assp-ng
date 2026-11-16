# SPDX-License-Identifier: GPL-3.0-or-later
"""Check framework types: phases, modes, results, session/transaction views, context."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from asspng.config.model import ConfigSnapshot, ListenerConfig
from asspng.config.policy import Policy
from asspng.config.registry import Level, Registry
from asspng.config.settings import REGISTRY
from asspng.net.ipnet import IPAddress, is_private
from asspng.proxy.buffer import MessageBuffer
from asspng.proxy.connections import ConnectionTracker
from asspng.smtp.address import Address
from asspng.smtp.replies import Reply
from asspng.state.base import StateStore


class Phase(Enum):
    CONNECT = 1
    HELO = 2
    AUTH = 3
    MAIL = 4
    RCPT = 5
    HEADER = 6
    BODY = 7


class Mode(Enum):
    OFF = "off"
    BLOCK = "block"
    MONITOR = "monitor"
    SCORE = "score"
    TEST = "test"


@dataclass(frozen=True)
class CheckResult:
    hit: bool
    msg_score: int = 0
    ip_score: int = 0
    reason: str = ""
    reply: Reply | None = None
    temporary: bool = False


NEUTRAL = CheckResult(False)


@dataclass(frozen=True)
class CheckSettings:
    mode: Mode
    msg_score: int
    ip_score: int
    timeout_s: float


@dataclass
class SessionInfo:
    session_id: str
    client_ip: IPAddress
    net_key: str
    listener: ListenerConfig
    tls_version: str | None
    auth_user: str | None
    helo: str | None
    trusted: bool
    exempt: bool
    messages: int
    protocol_errors: int
    invalid_recipients: int
    # Results of the checks before MAIL (CONNECT, HELO, AUTH): every new transaction starts
    # from them, so they count for each message of the session (ruling R62).
    score: int = 0
    reasons: list[tuple[str, int]] = field(default_factory=list)
    would_reject: list[str] = field(default_factory=list)


def spared_from_ip_score(session: SessionInfo) -> bool:
    """Whether the client never collects IP score: trusted, exempt, authenticated or a
    private address. The check engine and the session's own abuse scoring share this."""
    return (session.trusted or session.exempt or bool(session.auth_user)
            or is_private(session.client_ip))


@dataclass
class TransactionInfo:
    number: int
    mail_from: Address | None
    recipients: list[Address]
    current_rcpt: Address | None
    policy: Policy | None
    score: int
    reasons: list[tuple[str, int]]
    would_reject: list[str]
    warn: bool
    message: MessageBuffer | None
    score_limit_noted: bool = False


@dataclass
class CheckContext:
    """The checks' view of a session. ``tap(direction, text)`` is the session's debug tap
    (spec 8.11): the engine writes one ``CHK`` line per check decision to it."""

    session: SessionInfo
    txn: TransactionInfo | None
    config: ConfigSnapshot
    default_policy: Policy
    sender_policy: Policy | None
    state: StateStore
    clock: Callable[[], float]
    connections: ConnectionTracker
    registry: Registry = field(default=REGISTRY)
    tap: Callable[[str, str], None] | None = None

    def setting(self, key: str) -> object:
        """Resolve a setting by its level (SYSTEM, RECIPIENT or SENDER)."""
        level = self.registry.get(key).level
        if level is Level.SYSTEM:
            return self.config.get(key)
        if level is Level.RECIPIENT:
            if self.txn is not None and self.txn.policy is not None:
                return self.txn.policy.values[key]
            return self.default_policy.values[key]
        if self.sender_policy is not None:
            return self.sender_policy.values[key]
        return self.registry.coerce(key, self.registry.get(key).default)


class Check(Protocol):
    name: str
    phases: frozenset[Phase]
    exempt: frozenset[str]  # subset of {"trusted", "authenticated"}

    async def run(self, ctx: CheckContext, phase: Phase) -> CheckResult: ...
