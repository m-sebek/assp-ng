# SPDX-License-Identifier: GPL-3.0-or-later
"""Abuse resistance end to end: over-long lines, slow clients, connection floods and relay
attempts (spec 9 and 10.2, security layer)."""

from __future__ import annotations

import asyncio
import contextlib
import time

import redis

from asspng.smtp.replies import (
    R_IDLE,
    R_LINE_TOO_LONG,
    R_RELAY_DENIED,
    R_TOO_MANY_CONN,
    R_TRY_LATER,
)
from tests.support.e2e import Env, serve_as
from tests.support.redis_server import RedisServer
from tests.support.smtp_client import smtp_dialog

ATTACKER = "93.184.216.34"  # a public address: private and loopback clients are never scored


def block_exists(redis_server: RedisServer, env: Env) -> bool:
    prefix = str(env.system["redis.key_prefix"])
    client = redis.Redis.from_url(redis_server.url)
    try:
        return bool(client.exists(f"{prefix}pb:block:{ATTACKER}/32"))
    finally:
        client.close()


async def test_overlong_command_500_then_continue(env: Env) -> None:
    await env.start()
    async with env.dialog() as c:
        await c.expect_banner()
        for size in (5_000, 300_000):  # beyond the line limit and beyond the reader buffer
            await c.send_raw(b"NOOP " + b"A" * size + b"\r\n")
            assert await c.reply() == R_LINE_TOO_LONG
            assert (await c.send("NOOP")).code == 250  # the session carries on in step
        assert (await c.send("QUIT")).code == 221
    assert not any(b"AAAA" in line for line in env.mta.lines)


async def test_slow_client_times_out(env: Env) -> None:
    env.system["timeouts.command"] = 1
    await env.start()

    async def silent() -> None:
        async with env.dialog() as c:
            await c.expect_banner()
            assert await c.reply(timeout=3) == R_IDLE
            await c.expect_closed()

    async def trickle() -> None:
        async with env.dialog() as c:  # a line that never ends: the timeout covers all of it
            await c.expect_banner()

            async def drip() -> None:  # one byte every 0.3 s, for well beyond the timeout
                with contextlib.suppress(OSError):
                    for _ in range(10):
                        await c.send_raw(b"N")
                        await asyncio.sleep(0.3)

            started = time.monotonic()
            dripping = asyncio.create_task(drip())
            try:
                assert await c.reply(timeout=3) == R_IDLE
                assert time.monotonic() - started < 1.6  # timeouts.command (1 s) plus margin
            finally:
                dripping.cancel()
            await c.expect_closed()

    await asyncio.gather(silent(), trickle())
    await env.stop()
    assert [result for result in map(_result, env.maillog())] == ["timeout", "timeout"]


def _result(line: str) -> str:
    return line.split(" result=", 1)[1].split(" ", 1)[0]


async def test_connection_flood_hits_per_minute_limit_and_penalty(
    env: Env, redis_server: RedisServer
) -> None:
    env.system["limits.net.connections_per_minute"] = 3
    env.system["checks.conn_limits.ip_score"] = 25  # two refusals reach the threshold of 50
    await env.start()
    async with serve_as(env, ATTACKER) as (host, port):
        for _ in range(3):
            async with smtp_dialog(host, port) as c:
                await c.expect_banner()
                assert (await c.send("QUIT")).code == 221
        for _ in range(2):
            async with smtp_dialog(host, port) as c:
                assert await c.reply() == R_TOO_MANY_CONN
                await c.expect_closed()
        assert block_exists(redis_server, env)
        async with smtp_dialog(host, port) as c:
            assert await c.reply() == R_TRY_LATER  # now refused by the penalty box
            await c.expect_closed()
        async with env.dialog() as c:  # a loopback client is not affected by the box
            await c.expect_banner()


async def test_relay_attempt_flood_penalised(env: Env, redis_server: RedisServer) -> None:
    env.system["abuse.relay_denied_ip_score"] = 25  # two attempts reach the threshold of 50
    await env.start()
    async with serve_as(env, ATTACKER) as (host, port):
        async with smtp_dialog(host, port) as c:
            await c.expect_banner()
            assert (await c.send("EHLO attacker.test")).code == 250
            assert (await c.send("MAIL FROM:<spam@attacker.test>")).code == 250
            for _ in range(2):
                assert await c.send("RCPT TO:<victim@remote.test>") == R_RELAY_DENIED
        assert block_exists(redis_server, env)
        async with smtp_dialog(host, port) as c:
            assert await c.reply() == R_TRY_LATER
            await c.expect_closed()
        async with smtp_dialog(host, port) as c:
            assert await c.reply() == R_TRY_LATER  # and it stays refused
    assert not any(b"remote.test" in line for line in env.mta.lines)  # nothing reached the MTA
