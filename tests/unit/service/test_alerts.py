# SPDX-License-Identifier: GPL-3.0-or-later
import json
from email.message import EmailMessage

import pytest

from asspng.service.alerts import Alerter
from tests.support.fake_mta import FakeMta


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Sink:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.emails: list[tuple[str, int, EmailMessage]] = []
        self.posts: list[tuple[str, bytes, float]] = []

    def send_email(self, host: str, port: int, msg: EmailMessage) -> None:
        self.emails.append((host, port, msg))
        if self.fail:
            raise OSError("smtp down")

    def post_webhook(self, url: str, body: bytes, timeout: float) -> None:
        self.posts.append((url, body, timeout))
        if self.fail:
            raise OSError("webhook down")


def _alerter(sink: Sink, clock: Clock, **kw: object) -> Alerter:
    args: dict[str, object] = dict(
        email="admin@example.org", webhook="", smtp_server="127.0.0.1:10125",
        min_interval_s=1800, clock=clock, instance="mx1", sender="assp-ng@mx1",
        send_email=sink.send_email, post_webhook=sink.post_webhook,
    )
    args.update(kw)
    return Alerter(**args)  # type: ignore[arg-type]


async def test_alert_rate_limited() -> None:
    sink, clock = Sink(), Clock()
    alerter = _alerter(sink, clock)
    assert await alerter.notify("reload-failed", "boom") is True
    assert await alerter.notify("reload-failed", "boom again") is False
    assert await alerter.notify("other", "x") is True
    assert len(sink.emails) == 2
    clock.now += 1800
    assert await alerter.notify("reload-failed", "later") is True
    msg = sink.emails[0][2]
    assert msg["Subject"] == "[ASSP-NG mx1] reload-failed"
    assert msg["From"] == "assp-ng@mx1"
    assert msg["To"] == "admin@example.org"
    assert msg["Date"] and msg["Message-ID"]
    assert msg.get_content().strip() == "boom"
    assert sink.emails[0][:2] == ("127.0.0.1", 10125)


async def test_alert_failure_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    sink, clock = Sink(fail=True), Clock()
    alerter = _alerter(sink, clock, webhook="http://hook.example/x?token=SECRET")
    assert await alerter.notify("ev", "m") is False
    assert "OSError" in caplog.text
    assert "SECRET" not in caplog.text
    # the failed attempt used up the slot
    assert await alerter.notify("ev", "m") is False
    assert len(sink.emails) == 1


async def test_partial_delivery_is_true() -> None:
    sink, clock = Sink(), Clock()

    def bad_email(host: str, port: int, msg: EmailMessage) -> None:
        raise OSError("no smtp")

    alerter = _alerter(sink, clock, webhook="https://hook.example/p", send_email=bad_email)
    assert await alerter.notify("ev", "m") is True
    url, body, timeout = sink.posts[0]
    assert url == "https://hook.example/p" and timeout == 10
    payload = json.loads(body)
    assert payload["instance"] == "mx1" and payload["event"] == "ev"
    assert payload["message"] == "m" and isinstance(payload["ts"], (int, float))


async def test_disabled_channels() -> None:
    sink, clock = Sink(), Clock()
    alerter = _alerter(sink, clock, email="", webhook="")
    assert await alerter.notify("ev", "m") is False
    assert not sink.emails and not sink.posts


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://h/x", "gopher://h"])
async def test_webhook_scheme_refused(url: str, caplog: pytest.LogCaptureFixture) -> None:
    sink, clock = Sink(), Clock()
    alerter = _alerter(sink, clock, email="", webhook=url)
    assert await alerter.notify("a", "m") is False
    assert await alerter.notify("b", "m") is False
    assert not sink.posts
    assert caplog.text.count("scheme") == 1


async def test_event_name_sanitised() -> None:
    sink, clock = Sink(), Clock()
    alerter = _alerter(sink, clock)
    evil = "x\r\nBcc: evil@example.net\r\n\r\nbody"
    assert await alerter.notify(evil, "msg") is True
    msg = sink.emails[0][2]
    assert "\n" not in msg["Subject"] and "\r" not in msg["Subject"]
    assert msg["Bcc"] is None
    assert msg["Subject"].startswith("[ASSP-NG mx1] x")
    long_name = "e" * 200
    await alerter.notify(long_name, "m")
    assert sink.emails[1][2]["Subject"] == "[ASSP-NG mx1] " + "e" * 64
    # the sanitised name is the rate-limit key
    assert await alerter.notify("e" * 64 + "!!!", "m") is False


async def test_email_uses_smtp_server() -> None:
    mta = FakeMta()
    host, port = await mta.start()
    try:
        alerter = Alerter(
            email="admin@example.org", webhook="", smtp_server=f"{host}:{port}",
            min_interval_s=60, clock=Clock(), instance="mx1", sender="assp-ng@mx1")
        assert await alerter.notify("memory-soft-limit", "RSS high") is True
    finally:
        await mta.stop()
    assert len(mta.messages) == 1
    mail_from, rcpts, body = mta.messages[0]
    assert mail_from == "assp-ng@mx1"
    assert rcpts == ["admin@example.org"]
    assert b"Subject: [ASSP-NG mx1] memory-soft-limit" in body
    assert b"RSS high" in body


def test_default_sender() -> None:
    import socket
    a = Alerter(email="a@b", webhook="", smtp_server="127.0.0.1:1", min_interval_s=1,
                clock=Clock(), instance="i")
    assert a.sender == f"assp-ng@{socket.getfqdn()}"


async def test_webhook_path_secret_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    sink, clock = Sink(fail=True), Clock()
    url = "https://user:PW@hooks.example:8443/services/T000/B000/SECRETPATH?k=QSECRET#frag"
    alerter = _alerter(sink, clock, email="", webhook=url)
    assert await alerter.notify("ev", "m") is False
    assert "hooks.example" in caplog.text
    for secret in ("SECRETPATH", "services", "QSECRET", "PW", "frag", "T000"):
        assert secret not in caplog.text


async def test_webhook_invalid_port_logged_safely(caplog: pytest.LogCaptureFixture) -> None:
    sink, clock = Sink(fail=True), Clock()
    alerter = _alerter(sink, clock, email="",
                       webhook="https://hooks.example:99999/SECRETPATH")
    assert await alerter.notify("ev", "m") is False
    assert "<invalid url>" in caplog.text
    assert "SECRETPATH" not in caplog.text


async def test_concurrent_notify_sends_once() -> None:
    import asyncio
    sink, clock = Sink(), Clock()
    alerter = _alerter(sink, clock)
    results = await asyncio.gather(*(alerter.notify("ev", "m") for _ in range(3)))
    assert sorted(results) == [False, False, True]
    assert len(sink.emails) == 1


async def test_delivery_does_not_block_loop() -> None:
    import asyncio
    import time
    sink, clock = Sink(), Clock()

    def slow(host: str, port: int, msg: EmailMessage) -> None:
        time.sleep(0.5)

    alerter = _alerter(sink, clock, send_email=slow)
    task = asyncio.create_task(alerter.notify("ev", "m"))
    ticks = 0
    while not task.done():
        await asyncio.sleep(0.02)
        ticks += 1
    assert ticks >= 10
    assert await task is True


@pytest.mark.parametrize("url", ["HTTP://h/x", " http://h/x"])
async def test_webhook_scheme_variants_accepted(url: str) -> None:
    sink, clock = Sink(), Clock()
    alerter = _alerter(sink, clock, email="", webhook=url)
    assert await alerter.notify("ev", "m") is True
    assert sink.posts[0][0].strip().lower().startswith("http://")
    assert not sink.posts[0][0].startswith(" ")


@pytest.mark.parametrize("url", ["hook.example/x", "//h/x"])
async def test_webhook_missing_scheme_refused(url: str) -> None:
    sink, clock = Sink(), Clock()
    alerter = _alerter(sink, clock, email="", webhook=url)
    assert await alerter.notify("ev", "m") is False
    assert not sink.posts
