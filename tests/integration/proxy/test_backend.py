# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import time
from ipaddress import ip_address

import pytest

from asspng.proxy import backend as backend_module
from asspng.proxy.backend import (
    BackendClosed,
    BackendError,
    BackendTimeout,
    SmtpBackend,
    XclientUnsupported,
)
from tests.support.fake_mta import FakeMta


async def _backend(fake: FakeMta) -> SmtpBackend:
    host, port = await fake.start()
    return SmtpBackend(host, port, connect_timeout_s=2, banner_timeout_s=2)


async def test_connect_banner():
    fake = FakeMta()
    backend = await _backend(fake)
    try:
        banner = await backend.connect()
        assert banner.code == 220
        assert banner.lines == ("fake.mta ESMTP",)
    finally:
        await backend.close()
        await fake.stop()


async def test_connect_returns_non_220_banner():
    fake = FakeMta(banner_code=554)
    backend = await _backend(fake)
    try:
        assert (await backend.connect()).code == 554
    finally:
        await backend.close()
        await fake.stop()


async def test_connect_refused_is_backend_error():
    backend = SmtpBackend("127.0.0.1", 1, connect_timeout_s=2, banner_timeout_s=2)
    with pytest.raises(BackendError) as info:
        await backend.connect()
    assert not isinstance(info.value, BackendTimeout)


async def test_xclient_new_greeting():
    fake = FakeMta()
    backend = await _backend(fake)
    try:
        await backend.connect()
        greeting = await backend.xclient(ip_address("198.51.100.9"), 5555, "h.example", "proxy")
        assert greeting.code == 220
        assert fake.lines[0] == b"EHLO proxy"
        assert fake.xclient_attrs == [
            {"ADDR": "198.51.100.9", "PORT": "5555", "NAME": "h.example"}
        ]
    finally:
        await backend.close()
        await fake.stop()


async def test_xclient_unsupported_raises():
    fake = FakeMta(xclient=False)
    backend = await _backend(fake)
    try:
        await backend.connect()
        with pytest.raises(XclientUnsupported):
            await backend.xclient(ip_address("198.51.100.9"), 5555, "h", "proxy")
        assert not fake.xclient_attrs
    finally:
        await backend.close()
        await fake.stop()


async def test_xclient_rejected_is_backend_error():
    fake = FakeMta(replies={"XCLIENT": "550 5.7.0 Denied"})
    backend = await _backend(fake)
    try:
        await backend.connect()
        with pytest.raises(BackendError) as info:
            await backend.xclient(ip_address("198.51.100.9"), 5555, "h", "proxy")
        assert "550" in str(info.value)
    finally:
        await backend.close()
        await fake.stop()


async def test_command_relays_reply():
    fake = FakeMta()
    backend = await _backend(fake)
    try:
        await backend.connect()
        await backend.command(b"EHLO c", 2)
        await backend.command(b"MAIL FROM:<a@example.org>", 2)
        reply = await backend.command(b"RCPT TO:<unknown@example.org>", 2)
        assert reply.code == 550
    finally:
        await backend.close()
        await fake.stop()


async def test_data_stuffs_and_returns_final():
    fake = FakeMta()
    backend = await _backend(fake)
    try:
        await backend.connect()
        await backend.command(b"EHLO c", 2)
        await backend.command(b"MAIL FROM:<a@example.org>", 2)
        await backend.command(b"RCPT TO:<b@example.org>", 2)
        reply = await backend.data([b"Subject: x\r\n\r\n.hidden\r\nli", b"ne2\r\n.\r\n"], 2, 2)
        assert reply.code == 250
        assert reply.lines == ("2.0.0 Ok: queued as FAKE1",)
        assert fake.messages == [
            ("a@example.org", ["b@example.org"], b"Subject: x\r\n\r\n.hidden\r\nline2\r\n.\r\n")
        ]
    finally:
        await backend.close()
        await fake.stop()


async def test_non_354_returned():
    fake = FakeMta(replies={"DATA": "451 4.3.0 Try later"})
    backend = await _backend(fake)
    try:
        await backend.connect()
        await backend.command(b"EHLO c", 2)
        await backend.command(b"MAIL FROM:<a@example.org>", 2)
        await backend.command(b"RCPT TO:<b@example.org>", 2)
        reply = await backend.data([b"x\r\n"], 2, 2)
        assert reply.code == 451
        assert not fake.messages
    finally:
        await backend.close()
        await fake.stop()


async def test_timeout_raises_backend_timeout():
    fake = FakeMta(hang_on="NOOP")
    backend = await _backend(fake)
    try:
        await backend.connect()
        with pytest.raises(BackendTimeout):
            await backend.command(b"NOOP", 0.2)
    finally:
        await backend.close()
        await fake.stop()


async def test_close_sends_quit_and_is_idempotent():
    fake = FakeMta()
    backend = await _backend(fake)
    await backend.connect()
    await backend.close()
    await backend.close()
    assert fake.lines == [b"QUIT"]
    await fake.stop()


async def test_close_after_failure_skips_quit_and_is_fast():
    fake = FakeMta(hang_on="NOOP")
    backend = await _backend(fake)
    try:
        await backend.connect()
        with pytest.raises(BackendTimeout):
            await backend.command(b"NOOP", 0.2)
        started = time.monotonic()
        await backend.close()
        assert time.monotonic() - started < 0.5
        assert b"QUIT" not in fake.lines
    finally:
        await fake.stop()


async def _ready(fake: FakeMta, **kwargs: float) -> SmtpBackend:
    host, port = await fake.start()
    params = {"connect_timeout_s": 2.0, "banner_timeout_s": 2.0} | kwargs
    backend = SmtpBackend(host, port, **params)
    await backend.connect()
    await backend.command(b"EHLO c", 2)
    await backend.command(b"MAIL FROM:<a@example.org>", 2)
    await backend.command(b"RCPT TO:<b@example.org>", 2)
    return backend


async def test_data_chunk_iterable_failure_marks_broken_and_skips_quit():
    def chunks():
        yield b"Subject: x\r\n"
        raise OSError("spool read failed")

    fake = FakeMta()
    backend = await _ready(fake)
    try:
        with pytest.raises(OSError):
            await backend.data(chunks(), 2, 2)
        await backend.close()
        await asyncio.sleep(0.1)
        assert b"QUIT" not in fake.lines
    finally:
        await fake.stop()


async def test_write_stall_raises_backend_timeout():
    fake = FakeMta(no_read_after_data=True)
    backend = await _ready(fake)
    try:
        big = [b"x" * 1000 + b"\r\n"] * 20000
        chunks = (b"".join(big) for _ in range(40))
        with pytest.raises(BackendTimeout):
            await backend.data(chunks, 0.3, 0.3)
        started = time.monotonic()
        await backend.close()
        assert time.monotonic() - started < 0.5
    finally:
        await fake.stop()


async def test_final_reply_hang_raises_backend_timeout():
    fake = FakeMta(hang_on="DATA_END")
    backend = await _ready(fake)
    try:
        with pytest.raises(BackendTimeout):
            await backend.data([b"x\r\n"], 2, 0.3)
    finally:
        await backend.close()
        await fake.stop()


async def test_close_quit_sequence_is_bounded(monkeypatch):
    monkeypatch.setattr(backend_module, "_QUIT_TIMEOUT_S", 0.3)
    fake = FakeMta(hang_on="QUIT")
    backend = await _ready(fake)
    try:
        started = time.monotonic()
        await backend.close()
        assert time.monotonic() - started < 1.0
    finally:
        await fake.stop()


async def test_close_mid_reply_is_backend_closed():
    fake = FakeMta(partial_close_on="NOOP")
    backend = await _ready(fake)
    try:
        with pytest.raises(BackendClosed):
            await backend.command(b"NOOP", 2)
    finally:
        await backend.close()
        await fake.stop()


async def test_close_without_reply_is_backend_closed():
    fake = FakeMta(close_on="NOOP")
    backend = await _ready(fake)
    try:
        with pytest.raises(BackendClosed):
            await backend.command(b"NOOP", 2)
    finally:
        await backend.close()
        await fake.stop()


async def test_malformed_reply_is_backend_error_not_closed():
    fake = FakeMta(garbage_on="NOOP")
    backend = await _ready(fake)
    try:
        with pytest.raises(BackendError) as info:
            await backend.command(b"NOOP", 2)
        assert not isinstance(info.value, BackendClosed)
    finally:
        await backend.close()
        await fake.stop()


async def test_banner_timeout():
    fake = FakeMta(banner_delay=2)
    host, port = await fake.start()
    backend = SmtpBackend(host, port, connect_timeout_s=2, banner_timeout_s=0.2)
    try:
        with pytest.raises(BackendTimeout):
            await backend.connect()
    finally:
        await backend.close()
        await fake.stop()


async def test_connect_timeout():
    backend = SmtpBackend("10.255.255.1", 25, connect_timeout_s=0.2, banner_timeout_s=1)
    try:
        await backend.connect()
    except BackendTimeout:
        return
    except BackendError:
        pytest.skip("network rejects the non-routable address immediately")
    pytest.skip("unexpectedly connected")


async def test_connect_twice_is_runtime_error():
    fake = FakeMta()
    backend = await _backend(fake)
    try:
        await backend.connect()
        with pytest.raises(RuntimeError):
            await backend.connect()
    finally:
        await backend.close()
        await fake.stop()


async def test_crlf_in_command_or_helo_rejected():
    fake = FakeMta()
    backend = await _ready(fake)
    try:
        with pytest.raises(ValueError):
            await backend.command(b"NOOP\r\nMAIL FROM:<x@y>", 2)
        with pytest.raises(ValueError):
            await backend.xclient(ip_address("192.0.2.1"), 1, "n", "a\r\nb")
    finally:
        await backend.close()
        await fake.stop()
