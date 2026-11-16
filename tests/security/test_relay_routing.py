# SPDX-License-Identifier: GPL-3.0-or-later
"""Routing syntax in recipient addresses (ruling R61, spec 4.6): a client that may not relay
must not reach a remote mailbox through a local domain with %-hacks, bang paths, quoted
'@' or a second unquoted '@'. End to end, with the real application and a public client."""

from __future__ import annotations

import redis
import pytest

from asspng.db.repository import DomainRepository
from asspng.smtp.replies import R_BAD_ARG, R_RELAY_DENIED, R_TOO_MANY_ERRORS, Reply
from tests.support.e2e import HOSTNAME, LOCAL_DOMAIN, Env, authenticate, serve_as
from tests.support.redis_server import RedisServer
from tests.support.smtp_client import SmtpDialog, client_tls_context, smtp_dialog

CLIENT = "93.184.216.34"  # public: private and loopback clients are never scored
SCORE = 7
DENIED = "denied"
ACCEPTED = "accepted"

CASES = [
    ("postmaster@remote.example", DENIED),
    (f"@{LOCAL_DOMAIN}:bob@remote.example", DENIED),  # source route to a remote mailbox
    (f"a%remote.example@{LOCAL_DOMAIN}", DENIED),
    (f"remote.example!a@{LOCAL_DOMAIN}", DENIED),
    (f'"a@remote.example"@{LOCAL_DOMAIN}', DENIED),
    (f'"a%remote.example"@{LOCAL_DOMAIN}', DENIED),
    (f'"remote.example!a"@{LOCAL_DOMAIN}', DENIED),
    ("bob@[192.0.2.1]", DENIED),  # an address literal that is not a local domain
    (f"a@remote.example@{LOCAL_DOMAIN}", "501"),
    ("Postmaster", ACCEPTED),
    (f"bob@{LOCAL_DOMAIN}", ACCEPTED),
]


def ip_score(redis_server: RedisServer, env: Env) -> int:
    prefix = str(env.system["redis.key_prefix"])
    client = redis.Redis.from_url(redis_server.url)
    try:
        value = client.hget(f"{prefix}pb:{CLIENT}/32", "score")
    finally:
        client.close()
    return int(value or 0)


def rcpt_lines(env: Env) -> list[bytes]:
    return [line for line in env.mta.lines if line.upper().startswith(b"RCPT")]


async def mail_from(c: SmtpDialog) -> None:
    await c.expect_banner()
    assert (await c.send("EHLO client.test")).code == 250
    assert (await c.send("MAIL FROM:<sender@remote.test>")).code == 250


@pytest.mark.parametrize("rcpt, expected", CASES, ids=[case[0] for case in CASES])
async def test_routing_syntax_from_a_client_without_relay_rights(
        env: Env, redis_server: RedisServer, rcpt: str, expected: str) -> None:
    env.system["abuse.relay_denied_ip_score"] = SCORE
    env.system["limits.session.protocol_errors"] = 2
    await env.start()
    async with serve_as(env, CLIENT) as (host, port):
        async with smtp_dialog(host, port) as c:
            await mail_from(c)
            reply = await c.send(f"RCPT TO:<{rcpt}>")
            if expected == ACCEPTED:
                assert reply.code == 250
                forwarded = "postmaster" if rcpt == "Postmaster" else rcpt  # RFC 5321 4.5.1
                assert rcpt_lines(env) == [f"RCPT TO:<{forwarded}>".encode()]
                assert ip_score(redis_server, env) == 0
                return
            assert reply == (R_BAD_ARG if expected == "501" else R_RELAY_DENIED)
            # Each refusal is a protocol error: the second one reaches the limit of 2.
            assert await c.send(f"RCPT TO:<{rcpt}>") == R_TOO_MANY_ERRORS
            await c.expect_closed()
    assert rcpt_lines(env) == []  # nothing reached the MTA
    if expected == DENIED:  # like any relay attempt: scored (twice) plus the error limit
        assert ip_score(redis_server, env) == 2 * SCORE + int(
            str(env.app.config.get("abuse.protocol_error_ip_score")) if env.app else 0)


async def test_listed_address_literal_is_local(env: Env, redis_server: RedisServer) -> None:
    repo = DomainRepository(str(env.system["database.url"]), "test")
    try:
        repo.add("[192.0.2.1]", include_subdomains=False, note=None, actor="test")
    finally:
        repo.close()
    await env.start()
    async with serve_as(env, CLIENT) as (host, port):
        async with smtp_dialog(host, port) as c:
            await mail_from(c)
            assert (await c.send("RCPT TO:<bob@[192.0.2.1]>")).code == 250
    assert rcpt_lines(env) == [b"RCPT TO:<bob@[192.0.2.1]>"]


async def test_trusted_client_may_use_routing_syntax(env: Env) -> None:
    (env.etc / "trusted-networks.txt").write_text(f"{CLIENT}/32\n", encoding="utf-8")
    await env.start()
    rcpt = f"a%remote.example@{LOCAL_DOMAIN}"
    async with serve_as(env, CLIENT) as (host, port):
        async with smtp_dialog(host, port) as c:
            await mail_from(c)
            assert (await c.send(f"RCPT TO:<{rcpt}>")).code == 250
    assert rcpt_lines(env) == [f"RCPT TO:<{rcpt}>".encode()]


async def test_authenticated_client_may_use_routing_syntax(env: Env) -> None:
    env.use_tls()
    env.listeners[0].update(name="submission", kind="submission")
    await env.start()
    rcpt = f"a%remote.example@{LOCAL_DOMAIN}"
    async with env.dialog() as c:
        await c.expect_banner()
        assert (await c.send("EHLO client.test")).code == 250
        assert (await c.send("STARTTLS")).code == 220
        await c.starttls(client_tls_context(), server_hostname=HOSTNAME)
        await authenticate(c)
        assert (await c.send("MAIL FROM:<test@example.com>")).code == 250
        reply: Reply = await c.send(f"RCPT TO:<{rcpt}>")
        assert reply.code == 250
    assert rcpt_lines(env) == [f"RCPT TO:<{rcpt}>".encode()]
