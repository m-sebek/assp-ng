# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import json
import time

import pytest

from asspng.proxy.session_deps import HealthCounters
from asspng.service.health import HealthServer, HealthState
from asspng.state.controller import StateMode


def _snap(state: HealthState, **kw: object) -> dict[str, object]:
    args: dict[str, object] = dict(
        instance="mx1", mode=StateMode.NORMAL, db_ok=True, domains_origin="db",
        domains_count=2, sessions=12, rss_mb=74.0, uptime_s=86400, debug_rules=1,
        cert_days={"mx1": 61},
    )
    args.update(kw)
    return state.snapshot(**args)  # type: ignore[arg-type]


def test_health_state_satisfies_counters() -> None:
    counters: HealthCounters = HealthState()
    counters.record("accepted")


def test_health_json_shape() -> None:
    st = HealthState()
    for ev in ("accepted", "accepted", "rejected", "tempfailed", "session_error", "backend_lost"):
        st.record(ev)
    assert st.backend_result("inbound", True) == 0
    snap = _snap(st)
    assert snap == {
        "status": "ok", "instance": "mx1", "mode": "NORMAL", "redis": "ok", "db": "ok",
        "domains": {"source": "db", "count": 2}, "backends": {"inbound": "ok"},
        "sessions": 12, "rss_mb": 74.0, "uptime_s": 86400, "debug_rules": 1,
        "certificates": {"mx1": {"days_left": 61}},
        "counters": {"accepted": 2, "rejected": 1, "tempfailed": 1, "session_error": 1,
                     "backend_lost": 1},
    }
    json.dumps(snap)
    assert _snap(st, mode=StateMode.DEGRADED, db_ok=False)["redis"] == "down"
    assert _snap(st, db_ok=False)["db"] == "down"


def test_backend_result_counts_consecutive_failures() -> None:
    st = HealthState()
    assert st.backend_result("a", False) == 1
    assert st.backend_result("a", False) == 2
    assert st.backend_result("a", True) == 0
    assert st.backend_result("a", False) == 1


def test_status_codes() -> None:
    st = HealthState()
    assert st.status_code(_snap(st)) == 200
    assert _snap(st)["status"] == "ok"
    # no backend results yet: backends count as ok
    assert _snap(st, mode=StateMode.TEMPFAIL)["status"] == "failing"
    assert st.status_code(_snap(st, mode=StateMode.TEMPFAIL)) == 503
    degraded = [_snap(st, mode=StateMode.DEGRADED), _snap(st, db_ok=False),
                _snap(st, domains_origin="snapshot")]
    for snap in degraded:
        assert snap["status"] == "degraded"
        assert st.status_code(snap) == 200
    st.backend_result("inbound", False)
    st.backend_result("submission", True)
    assert _snap(st)["status"] == "degraded"
    assert _snap(st)["backends"] == {"inbound": "down", "submission": "ok"}
    st.backend_result("submission", False)
    snap = _snap(st)
    assert snap["status"] == "failing"
    assert st.status_code(snap) == 503


async def _request(port: int, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 5)
    writer.close()
    return data


async def test_http_get_health_and_404() -> None:
    st = HealthState()
    snap = _snap(st)
    server = HealthServer("127.0.0.1", 0, lambda: snap, status_code=st.status_code)
    await server.start()
    try:
        data = await _request(server.port, b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        head, _, body = data.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.0 200 ")
        assert b"Content-Type: application/json" in head
        assert b"Connection: close" in head
        assert json.loads(body)["instance"] == "mx1"
        assert (await _request(server.port, b"GET /other HTTP/1.0\r\n\r\n")).startswith(
            b"HTTP/1.0 404 ")
    finally:
        await server.close()


async def test_status_line_follows_status_code() -> None:
    st = HealthState()
    snap = _snap(st, mode=StateMode.TEMPFAIL)
    server = HealthServer("127.0.0.1", 0, lambda: snap, status_code=st.status_code)
    await server.start()
    try:
        data = await _request(server.port, b"GET /health HTTP/1.0\r\n\r\n")
        assert data.startswith(b"HTTP/1.0 503 ")
    finally:
        await server.close()


async def test_405_400_and_500() -> None:
    def boom() -> dict[str, object]:
        raise RuntimeError("secret detail")

    server = HealthServer("127.0.0.1", 0, boom)
    await server.start()
    try:
        assert (await _request(server.port, b"POST /health HTTP/1.0\r\n\r\n")).startswith(
            b"HTTP/1.0 405 ")
        assert (await _request(server.port, b"garbage\r\n\r\n")).startswith(b"HTTP/1.0 400 ")
        assert (await _request(server.port, b"A" * 20000)).startswith(b"HTTP/1.0 400 ")
        data = await _request(server.port, b"GET /health HTTP/1.0\r\n\r\n")
        assert data.startswith(b"HTTP/1.0 500 ")
        assert b"secret detail" not in data
    finally:
        await server.close()


async def test_idle_client_closed_by_timeout() -> None:
    server = HealthServer("127.0.0.1", 0, lambda: {}, read_timeout_s=0.2)
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        data = await asyncio.wait_for(reader.read(), 3)
        assert data == b""
        writer.close()
    finally:
        await server.close()


async def test_close_with_an_idle_client_is_fast() -> None:
    """C5: close() cancels the connection tasks first; wait_closed() would wait for them."""
    server = HealthServer("127.0.0.1", 0, lambda: {}, read_timeout_s=30)
    await server.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:
        async with asyncio.timeout(2):
            while not server._conns:
                await asyncio.sleep(0.01)
        started = time.monotonic()
        await asyncio.wait_for(server.close(), 5)
        assert time.monotonic() - started < 1.0
        assert await asyncio.wait_for(reader.read(), 2) == b""
    finally:
        writer.close()


@pytest.mark.parametrize("host", ["127.0.0.1"])
async def test_binds_given_host_only(host: str) -> None:
    server = HealthServer(host, 0, lambda: {})
    await server.start()
    try:
        assert server.address[0] == host
    finally:
        await server.close()
