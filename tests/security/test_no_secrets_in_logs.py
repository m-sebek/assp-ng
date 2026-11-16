# SPDX-License-Identifier: GPL-3.0-or-later
"""The AUTH password must not reach any log, the debug log, stderr, the health endpoint or
the control socket, whatever the client does (spec 9)."""

from __future__ import annotations

import base64
import json
import logging

import pytest

from asspng.service.control import control_request
from tests.integration.test_end_to_end import health
from tests.support.e2e import BODY, Env, send_data
from tests.support.fake_mta import FakeMta

PASSWORD = "Tr0ub4dor&3-xyzzy"
USER = "alice"
WRONG_USER = "mallory"


def b64(data: bytes | str) -> str:
    raw = data.encode() if isinstance(data, str) else data
    return base64.b64encode(raw).decode()


def forbidden() -> list[str]:
    """The password and every base64 form of it that a log could hold."""
    forms = [PASSWORD, b64(PASSWORD)]  # alone, and as an AUTH LOGIN response
    for user in (USER, WRONG_USER):
        forms += [b64(f"\0{user}\0{PASSWORD}"), b64(f"{user}\0{PASSWORD}")]
    return forms


def leaked(text: str) -> list[str]:
    return [form for form in forbidden() if form in text]


async def test_no_secrets_in_logs(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(
        FakeMta, "_credentials_ok",
        staticmethod(lambda user, password: user == USER.encode()
                     and password == PASSWORD.encode()))
    env.use_tls()
    env.listeners[0].update(name="submissions", kind="submissions")
    app = await env.start()
    sock = env.run / "control.sock"
    rule = await control_request(sock, "debug.on", {"kind": "all", "value": "",
                                                    "duration_s": 600, "headers": True})
    assert isinstance(rule, dict) and rule["headers"] is True

    # AUTH PLAIN with an initial response succeeds, then a message whose header lines look
    # like credentials is sent (the debug rule logs its header lines).
    message = (f"Authorization: Basic {b64(f'{USER}:{PASSWORD}')}\r\n"
               f"Authorization: Bearer {PASSWORD}\r\n"
               f"Proxy-Authorization: AUTH PLAIN {b64(f'{chr(0)}{USER}{chr(0)}{PASSWORD}')}\r\n"
               f"X-Note: AUTH LOGIN {b64(PASSWORD)}\r\n"
               f"Authorization: Digest realm=x,\r\n\tresponse={PASSWORD}\r\n"  # folded
               "X-After-Fold: visible-1\r\n"
               f"COOKIE: session={PASSWORD}\r\n"  # upper case
               "X-After-Cookie: visible-2\r\n"
               f"Authorization : {PASSWORD}\r\n"  # RFC 5322 obs-syntax: space before the colon
               "X-After-Obs: visible-3\r\n").encode() + BODY
    async with env.dialog(tls=True) as c:
        await c.expect_banner()
        assert (await c.send("EHLO client.test")).code == 250
        plain = b64(f"\0{USER}\0{PASSWORD}")
        assert (await c.send(f"AUTH PLAIN {plain}")).code == 235
        assert (await c.send("MAIL FROM:<alice@example.com>")).code == 250
        assert (await c.send("RCPT TO:<friend@remote.test>")).code == 250
        assert (await send_data(c, message)).code == 250

    # AUTH LOGIN fails: user name first, then the password; and PLAIN with the wrong user.
    async with env.dialog(tls=True) as c:
        await c.expect_banner()
        assert (await c.send("EHLO client.test")).code == 250
        assert (await c.send("AUTH LOGIN")).code == 334
        assert (await c.send(b64(WRONG_USER))).code == 334
        assert (await c.send(b64(PASSWORD))).code == 535
        assert (await c.send(f"AUTH PLAIN {b64(f'{chr(0)}{WRONG_USER}{chr(0)}{PASSWORD}')}")
                ).code == 535
    assert [attempt[2] for attempt in env.mta.auth_attempts] == [True, False, False]

    # The password is not in the status JSON, the health JSON or the control replies.
    status = json.dumps(await control_request(sock, "status", {}))
    _, snapshot = await health(app)
    assert not leaked(status) and not leaked(json.dumps(snapshot))
    assert not leaked(json.dumps(await control_request(sock, "debug.list", {})))

    await env.stop()
    texts = {name: env.log_text(name) for name in ("assp-ng.log", "maillog.log", "debug.log")}
    out, err = capsys.readouterr()
    texts.update(stdout=out, stderr=err, caplog=caplog.text)
    assert "C>P EHLO client.test" in texts["debug.log"]  # the debug rule really logged
    assert "Authorization" in texts["debug.log"]  # ... including the header lines
    for name, marker in (("Fold", "visible-1"), ("Cookie", "visible-2"), ("Obs", "visible-3")):
        assert f"P>M X-After-{name}: {marker}" in texts["debug.log"]  # kept: only secrets go
    assert {name: leaked(text) for name, text in texts.items() if leaked(text)} == {}
