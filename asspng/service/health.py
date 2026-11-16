# SPDX-License-Identifier: GPL-3.0-or-later
"""Health counters, the ``/health`` JSON and its HTTP/1.0 endpoint (design 8.4)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Callable
from typing import Any

from asspng.state.controller import StateMode

log = logging.getLogger(__name__)

_MAX_REQUEST = 8192
_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
            500: "Internal Server Error", 503: "Service Unavailable"}


class HealthState:
    """Event counters and per-listener backend state; satisfies ``HealthCounters``."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._failures: dict[str, int] = {}

    def record(self, event: str) -> None:
        self._counters[event] = self._counters.get(event, 0) + 1

    def backend_result(self, listener: str, ok: bool) -> int:
        """Record a backend attempt; return the consecutive failures."""
        self._failures[listener] = 0 if ok else self._failures.get(listener, 0) + 1
        return self._failures[listener]

    def snapshot(
        self,
        *,
        instance: str,
        mode: StateMode | str,
        db_ok: bool,
        domains_origin: str,
        domains_count: int,
        sessions: int,
        rss_mb: float,
        uptime_s: int,
        debug_rules: int,
        cert_days: dict[str, int],
    ) -> dict[str, object]:
        mode_name = mode.name if isinstance(mode, StateMode) else str(mode).upper()
        backends = {name: "ok" if fails == 0 else "down"
                    for name, fails in sorted(self._failures.items())}
        all_down = bool(backends) and all(v == "down" for v in backends.values())
        if mode_name == "TEMPFAIL" or all_down:
            status = "failing"
        elif (mode_name == "DEGRADED" or not db_ok or domains_origin != "db"
              or "down" in backends.values()):
            status = "degraded"
        else:
            status = "ok"
        return {
            "status": status,
            "instance": instance,
            "mode": mode_name,
            "redis": "ok" if mode_name == "NORMAL" else "down",
            "db": "ok" if db_ok else "down",
            "domains": {"source": domains_origin, "count": domains_count},
            "backends": backends,
            "sessions": sessions,
            "rss_mb": rss_mb,
            "uptime_s": uptime_s,
            "debug_rules": debug_rules,
            "certificates": {name: {"days_left": days} for name, days in cert_days.items()},
            "counters": dict(self._counters),
        }

    def status_code(self, snapshot: dict[str, object]) -> int:
        return 503 if snapshot.get("status") == "failing" else 200


def _default_status(snapshot: dict[str, object]) -> int:
    return 503 if snapshot.get("status") == "failing" else 200


class HealthServer:
    """Read-only HTTP/1.0 server answering ``GET /health`` with the provider's JSON."""

    def __init__(
        self,
        host: str,
        port: int,
        provider: Callable[[], dict[str, Any]],
        *,
        status_code: Callable[[dict[str, Any]], int] = _default_status,
        read_timeout_s: float = 5.0,
    ) -> None:
        self._host = host
        self._port = port
        self._provider = provider
        self._status_code = status_code
        self._timeout = read_timeout_s
        self._server: asyncio.Server | None = None
        self._conns: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)

    @property
    def address(self) -> tuple[str, int]:
        assert self._server is not None
        sockname = self._server.sockets[0].getsockname()
        return str(sockname[0]), int(sockname[1])

    @property
    def port(self) -> int:
        return self.address[1]

    async def close(self) -> None:
        """Stop listening, end the open connections, then wait for the server: its
        ``wait_closed()`` waits for every connection, so they are cancelled first."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
        for task in list(self._conns):
            task.cancel()
        if self._conns:
            await asyncio.gather(*self._conns, return_exceptions=True)
        if server is not None:
            await server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._conns.add(task)
        try:
            await self._serve(reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("health connection error: %s", type(exc).__name__)
        finally:
            if task is not None:
                self._conns.discard(task)
            with contextlib.suppress(Exception):
                writer.close()

    async def _read_request(self, reader: asyncio.StreamReader) -> bytes | None:
        """Read up to 8 KiB until the end of the headers; ``None`` on timeout or EOF."""
        data = b""
        while b"\r\n\r\n" not in data and b"\n\n" not in data and len(data) < _MAX_REQUEST:
            chunk = await reader.read(_MAX_REQUEST - len(data))
            if not chunk:
                return None if not data else data
            data += chunk
        return data

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await asyncio.wait_for(self._read_request(reader), self._timeout)
        except TimeoutError:
            return
        if data is None:
            return
        code, body = self._respond(data)
        head = (f"HTTP/1.0 {code} {_REASONS.get(code, 'Error')}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n")
        if code == 405:
            head += "Allow: GET\r\n"
        writer.write(head.encode("ascii") + b"\r\n" + body)
        with contextlib.suppress(TimeoutError, ConnectionError, OSError):
            await asyncio.wait_for(writer.drain(), self._timeout)

    def _respond(self, data: bytes) -> tuple[int, bytes]:
        line = data.split(b"\n", 1)[0].decode("latin-1").strip()
        parts = line.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/") or not parts[1].startswith("/"):
            return 400, b'{"error": "bad request"}'
        method, target = parts[0], parts[1]
        if method != "GET":
            return 405, b'{"error": "method not allowed"}'
        if target.split("?", 1)[0] != "/health":
            return 404, b'{"error": "not found"}'
        try:
            snapshot = self._provider()
            return self._status_code(snapshot), json.dumps(snapshot).encode("utf-8")
        except Exception as exc:
            log.warning("health provider failed: %s", type(exc).__name__)
            return 500, b'{"error": "internal error"}'
