# SPDX-License-Identifier: GPL-3.0-or-later
"""Runtime debug switch (spec 8.11): targeted self-expiring rules, per-session tap, log writer.

``DebugRules`` holds rules that switch debug logging on for matching connections or
envelopes and expire on their own. ``SessionTap`` keeps a small ring of recent lines for a
session and flushes it to ``DebugLog`` once a rule matches. ``DebugLog`` appends to the debug
log from a writer thread so the event loop never waits on disk I/O (spec 8.5).

Each line has a direction: the SMTP dialogue is ``C>P`` (client to proxy), ``P>C``, ``P>M``
(proxy to MTA) and ``M>P``; the session's events use the constants below.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import queue
import re
import secrets
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from asspng.log.redact import redact_text
from asspng.net.ipnet import network_key, parse_ip

_log = logging.getLogger("asspng.debug")

SES = "SES"  # session events: "connect ip=... ptr=... listener=..." and "TLS <version>"
CHK = "CHK"  # one line per check decision: phase, check, outcome, scores, duration
DNS = "DNS"  # DNS lookups: the client's PTR name
STATE = "STATE"  # the state store's mode at connect and on each change
_BAD_VALUE = re.compile(r"[\s\x00-\x1f\x7f]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class RuleKind(Enum):
    IP = "ip"
    FROM = "from"
    RCPT = "rcpt"
    USER = "user"
    LISTENER = "listener"
    ALL = "all"


@dataclass(frozen=True)
class DebugRule:
    id: str
    kind: RuleKind
    value: str
    expires_at: float
    headers: bool


def _normalise(kind: RuleKind, value: str) -> str:
    if kind is RuleKind.ALL:
        return ""
    if kind is RuleKind.IP:
        return network_key(parse_ip(value.strip()))
    if kind is RuleKind.LISTENER:
        if not value:
            raise ValueError("listener name must not be empty")
        return value
    cleaned = value.strip().lower()
    if not cleaned or _BAD_VALUE.search(cleaned):
        raise ValueError(f"invalid {kind.value} value")
    return cleaned


class DebugRules:
    """Active debug rules, persisted as JSON so they survive a restart."""

    def __init__(
        self,
        path: Path,
        clock: Callable[[], float] = time.time,
        *,
        default_s: int,
        max_s: int,
        max_all_s: int,
    ) -> None:
        self._path = path
        self._clock = clock
        self._default_s = default_s
        self._max_s = max_s
        self._max_all_s = max_all_s
        self._rules: list[DebugRule] = []
        self._load()

    def add(
        self, kind: RuleKind, value: str, duration_s: int | None, headers: bool
    ) -> DebugRule:
        seconds = self._default_s if duration_s is None else duration_s
        if seconds <= 0:
            raise ValueError("duration must be positive")
        limit = self._max_all_s if kind is RuleKind.ALL else self._max_s
        if seconds > limit:
            raise ValueError(f"duration exceeds the maximum of {limit} seconds")
        rule = DebugRule(
            secrets.token_hex(4), kind, _normalise(kind, value), self._clock() + seconds, headers
        )
        self._rules.append(rule)
        self._persist()
        return rule

    def remove(self, rule_id: str) -> bool:
        kept = [r for r in self._rules if r.id != rule_id]
        if len(kept) == len(self._rules):
            return False
        self._rules = kept
        self._persist()
        return True

    def clear(self) -> int:
        count = len(self._rules)
        self._rules = []
        self._persist()
        return count

    def active(self) -> list[DebugRule]:
        now = self._clock()
        live = [r for r in self._rules if r.expires_at > now]
        if len(live) != len(self._rules):
            self._rules = live
            self._persist()
        return list(live)

    def match_connect(self, net_key: str, listener: str) -> DebugRule | None:
        for rule in self.active():
            if rule.kind is RuleKind.ALL:
                return rule
            if rule.kind is RuleKind.IP and rule.value == net_key:
                return rule
            if rule.kind is RuleKind.LISTENER and rule.value == listener:
                return rule
        return None

    def match_envelope(
        self, mail_from: str | None, rcpts: Sequence[str], auth_user: str | None
    ) -> DebugRule | None:
        sender = (mail_from or "").lower()
        recipients = {r.lower() for r in rcpts}
        user = (auth_user or "").lower()
        for rule in self.active():
            if rule.kind is RuleKind.ALL:
                return rule
            if rule.kind is RuleKind.FROM:
                if sender == rule.value or (rule.value == "<>" and sender == ""):
                    return rule
            elif rule.kind is RuleKind.RCPT and rule.value in recipients:
                return rule
            elif rule.kind is RuleKind.USER and user and rule.value == user:
                return rule
        return None

    def _load(self) -> None:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except Exception as exc:
            _log.warning("cannot read debug rules file %s: %s", self._path, type(exc).__name__)
            return
        try:
            entries = json.loads(raw)
            if not isinstance(entries, list):
                raise ValueError("not a list")
        except Exception as exc:
            _log.warning("corrupt debug rules file %s: %s", self._path, type(exc).__name__)
            return
        now = self._clock()
        for entry in entries:
            try:
                rule = self._parse_entry(entry, now)
            except Exception as exc:
                _log.warning("skipping invalid debug rule entry: %s", type(exc).__name__)
                continue
            if rule.expires_at > now:
                self._rules.append(rule)

    def _parse_entry(self, entry: Any, now: float) -> DebugRule:
        kind = RuleKind[entry["kind"]]
        value = str(entry["value"])
        if kind is RuleKind.IP:
            net = ipaddress.ip_network(value, strict=True)
            if net.prefixlen != (32 if net.version == 4 else 64) or str(net) != value:
                raise ValueError("not a canonical network key")
        else:
            value = _normalise(kind, value)
        expires_at = float(entry["expires_at"])
        if not math.isfinite(expires_at):
            raise ValueError("expires_at is not finite")
        limit = self._max_all_s if kind is RuleKind.ALL else self._max_s
        return DebugRule(
            str(entry["id"]), kind, value, min(expires_at, now + limit), bool(entry["headers"])
        )

    def _persist(self) -> None:
        data = [
            {
                "id": r.id,
                "kind": r.kind.name,
                "value": r.value,
                "expires_at": r.expires_at,
                "headers": r.headers,
            }
            for r in self._rules
        ]
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(
                dir=self._path.parent, prefix=self._path.name + ".", suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self._path)
        except OSError as exc:
            _log.warning("cannot persist debug rules to %s: %s", self._path, exc)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass


_Item = tuple[float, str, str, str]


class DebugLog:
    """Append-only debug log written by one daemon thread.

    ``write`` only enqueues. The writer thread formats, checks rotation and the size cap and
    does all file I/O. ``on_full`` runs on the writer thread, so it must be thread-safe (the
    server wraps it with ``loop.call_soon_threadsafe``). Errors are logged without the line
    content and never stop the thread.
    """

    def __init__(self, path: Path, max_bytes: int, on_full: Callable[[], None]) -> None:
        self._path = path
        self._max_bytes = max_bytes
        self._on_full = on_full
        self._queue: queue.SimpleQueue[_Item | None] = queue.SimpleQueue()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._fh: Any = None
        self._inode: int | None = None
        self._full = False
        self._full_inode: int | None = None
        self._full_size = 0

    def write(
        self, session_id: str, direction: str, text: str, *, ts: float | None = None
    ) -> None:
        with self._lock:
            if self._closed:
                return
            if self._thread is None:
                thread = threading.Thread(target=self._run, name="asspng-debug-log", daemon=True)
                try:
                    thread.start()
                except Exception as exc:  # e.g. no thread can be started: drop the line
                    _log.warning("debug log writer thread cannot start: %s; line dropped",
                                 type(exc).__name__)
                    return
                self._thread = thread  # only a started thread: close() joins it
            self._queue.put((time.time() if ts is None else ts, session_id, direction, text))

    def close(self) -> None:
        """Flush queued lines, stop the writer thread and close the file. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            thread = self._thread
            if thread is not None:
                self._queue.put(None)
        if thread is not None:
            thread.join()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                break
            try:
                self._handle(item)
            except Exception as exc:  # the writer thread must survive any failure
                _log.warning("debug log write failed: %s", type(exc).__name__)
        self._close_file()

    def _close_file(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
            self._inode = None

    def _open(self) -> None:
        self._close_file()
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        self._fh = os.fdopen(fd, "ab")
        self._inode = os.fstat(fd).st_ino

    @staticmethod
    def _format(item: _Item) -> bytes:
        ts, session_id, direction, text = item
        iso = datetime.fromtimestamp(ts).astimezone().isoformat(timespec="milliseconds")
        safe = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", redact_text(text))
        return f"{iso} {session_id} {direction} {safe}\n".encode("utf-8", "replace")

    def _handle(self, item: _Item) -> None:
        data = self._format(item)
        try:
            st = os.stat(self._path)
        except FileNotFoundError:
            st = None
        if self._fh is None or st is None or st.st_ino != self._inode:
            self._open()
            st = os.stat(self._path)
        if self._full and (
            st.st_ino != self._full_inode or st.st_size < self._full_size
        ):
            self._full = False  # rotated or truncated
        if self._full:
            return
        if st.st_size + len(data) > self._max_bytes:
            self._full = True
            self._full_inode = st.st_ino
            self._full_size = st.st_size
            try:
                self._on_full()
            except Exception as exc:
                _log.warning("debug log on_full callback failed: %s", type(exc).__name__)
            return
        self._fh.write(data)
        self._fh.flush()


class SessionTap:
    """Per-session debug tap: buffers lines until a rule matches, then logs everything."""

    def __init__(
        self, session_id: str, rules: DebugRules, log: DebugLog, ring_lines: int
    ) -> None:
        self._session_id = session_id
        self._rules = rules
        self._log = log
        self._ring: deque[tuple[float, str, str]] = deque(maxlen=ring_lines)
        self.active = False
        self.headers = False

    def line(self, direction: str, text: str) -> None:
        if self.active:
            self._log.write(self._session_id, direction, text)
        else:
            self._ring.append((time.time(), direction, text))

    def on_connect(self, net_key: str, listener: str) -> None:
        self._apply(self._rules.match_connect(net_key, listener))

    def on_envelope(
        self, mail_from: str | None, rcpts: Sequence[str], auth_user: str | None
    ) -> None:
        self._apply(self._rules.match_envelope(mail_from, rcpts, auth_user))

    def _apply(self, rule: DebugRule | None) -> None:
        if rule is None:
            return
        self.headers = self.headers or rule.headers
        if not self.active:
            self.active = True
            for ts, direction, text in self._ring:
                self._log.write(self._session_id, direction, text, ts=ts)
            self._ring.clear()
