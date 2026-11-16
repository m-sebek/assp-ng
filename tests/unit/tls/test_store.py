# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from asspng.config.errors import ConfigError
from asspng.config.model import CertificateConfig
from asspng.tls.store import INTERMEDIATE_CIPHERS, CertificateStore, make_server_context
from tests.support.certs import make_cert


def entry(tmp: Path, name: str, *hostnames: str, days: int = 30) -> CertificateConfig:
    cert, key = make_cert(tmp, hostnames[0], days)
    return CertificateConfig(name=name, hostnames=hostnames, cert=cert, key=key)


def der(path: Path) -> bytes:
    return ssl.PEM_cert_to_DER_cert(path.read_text())


@asynccontextmanager
async def serve(ctx: ssl.SSLContext) -> AsyncIterator[int]:
    async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def served_der(port: int, sni: str) -> bytes:
    """DER of the certificate served for ``sni``; ``""`` sends no SNI at all."""
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=client, server_hostname=sni)
    try:
        obj = writer.get_extra_info("ssl_object")
        der_bytes = obj.getpeercert(binary_form=True)
        assert der_bytes is not None
        return bytes(der_bytes)
    finally:
        writer.close()


def test_min_tls12(tmp_path: Path) -> None:
    cert, key = make_cert(tmp_path, "mx.example.com")
    ctx = make_server_context(cert, key)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.options & ssl.OP_NO_COMPRESSION
    assert ctx.options & getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ":" in INTERMEDIATE_CIPHERS


async def test_sni_selects_matching_cert(tmp_path: Path) -> None:
    a = entry(tmp_path, "a", "a.example.com")
    b = entry(tmp_path, "b", "b.example.com")
    store = CertificateStore([a, b])
    ctx = store.front_context()
    assert ctx is not None
    async with serve(ctx) as port:
        assert await served_der(port, "b.example.com") == der(b.cert)
        assert await served_der(port, "A.Example.COM") == der(a.cert)
        assert await served_der(port, "unknown.example.org") == der(a.cert)


async def test_no_sni_uses_first(tmp_path: Path) -> None:
    a = entry(tmp_path, "a", "a.example.com")
    b = entry(tmp_path, "b", "b.example.com")
    ctx = CertificateStore([a, b]).front_context()
    assert ctx is not None
    async with serve(ctx) as port:
        assert await served_der(port, "") == der(a.cert)


async def test_wildcard(tmp_path: Path) -> None:
    a = entry(tmp_path, "a", "a.example.com")
    w = entry(tmp_path, "w", "*.wild.example")
    ctx = CertificateStore([a, w]).front_context()
    assert ctx is not None
    async with serve(ctx) as port:
        assert await served_der(port, "x.wild.example") == der(w.cert)
        # only one label deep, and the bare parent does not match
        assert await served_der(port, "y.x.wild.example") == der(a.cert)
        assert await served_der(port, "wild.example") == der(a.cert)


async def test_reload_swaps_without_new_front_context(tmp_path: Path) -> None:
    old = entry(tmp_path, "a", "a.example.com")
    store = CertificateStore([old])
    ctx = store.front_context()
    assert ctx is not None
    sub = tmp_path / "new"
    sub.mkdir()
    new = entry(sub, "a", "a.example.com")
    async with serve(ctx) as port:
        assert await served_der(port, "a.example.com") == der(old.cert)
        store.reload([new])
        assert store.front_context() is ctx
        assert await served_der(port, "a.example.com") == der(new.cert)
        assert await served_der(port, "") == der(new.cert)


async def test_reload_failure_keeps_old(tmp_path: Path) -> None:
    old = entry(tmp_path, "a", "a.example.com")
    store = CertificateStore([old])
    ctx = store.front_context()
    assert ctx is not None
    good = entry(tmp_path, "b", "b.example.com")
    broken_cert = tmp_path / "broken.crt"
    broken_cert.write_text("not a certificate")
    bad = CertificateConfig("bad", ("c.example.com",), broken_cert, old.key)
    missing = CertificateConfig("gone", ("d.example.com",), tmp_path / "nope", tmp_path / "nope")
    with pytest.raises(ConfigError) as exc:
        store.reload([good, bad, missing])
    assert len(exc.value.errors) == 2
    assert "bad" in exc.value.errors[0] and "gone" in exc.value.errors[1]
    assert store.front_context() is ctx
    async with serve(ctx) as port:
        assert await served_der(port, "a.example.com") == der(old.cert)
        assert await served_der(port, "b.example.com") == der(old.cert)
    assert list(store.days_left()) == ["a"]


def test_constructor_raises_config_error(tmp_path: Path) -> None:
    bad = CertificateConfig("bad", ("x.example.com",), tmp_path / "x", tmp_path / "y")
    with pytest.raises(ConfigError, match="bad"):
        CertificateStore([bad])


async def test_reload_empty_fails_handshakes(tmp_path: Path) -> None:
    store = CertificateStore([entry(tmp_path, "a", "a.example.com")])
    ctx = store.front_context()
    assert ctx is not None
    store.reload([])
    assert store.front_context() is ctx
    async with serve(ctx) as port:
        with pytest.raises((ssl.SSLError, ConnectionError)):
            await served_der(port, "a.example.com")


def test_empty_store_has_no_front_context() -> None:
    assert CertificateStore([]).front_context() is None


def test_days_left(tmp_path: Path) -> None:
    a = entry(tmp_path, "a", "a.example.com", days=30)
    b = entry(tmp_path, "b", "b.example.com", days=-3)
    now = datetime.now(UTC)
    store = CertificateStore([a, b], clock=lambda: now)
    left = store.days_left()
    assert left["a"] == 29 or left["a"] == 30
    assert left["b"] == -3 or left["b"] == -4
    later = CertificateStore([a], clock=lambda: now + timedelta(days=10))
    assert later.days_left()["a"] in (19, 20)


async def test_reload_adds_certificates_to_empty_store(tmp_path: Path) -> None:
    store = CertificateStore([])
    assert store.front_context() is None
    a = entry(tmp_path, "a", "a.example.com")
    store.reload([a])
    ctx = store.front_context()
    assert ctx is not None
    async with serve(ctx) as port:
        assert await served_der(port, "a.example.com") == der(a.cert)
        assert await served_der(port, "") == der(a.cert)
    store.reload([a])
    assert store.front_context() is ctx


async def test_unicode_hostname_matches_punycode_sni(tmp_path: Path) -> None:
    a = entry(tmp_path, "a", "a.example.com")
    cert, key = make_cert(tmp_path, "xn--mnchen-3ya.example")
    m = CertificateConfig("m", ("M\u00fcnchen.example",), cert, key)
    ctx = CertificateStore([a, m]).front_context()
    assert ctx is not None
    async with serve(ctx) as port:
        assert await served_der(port, "xn--mnchen-3ya.example") == der(m.cert)


async def test_configured_trailing_dot_matches(tmp_path: Path) -> None:
    a = entry(tmp_path, "a", "a.example.com")
    b = entry(tmp_path, "b", "b.example.com.")
    ctx = CertificateStore([a, b]).front_context()
    assert ctx is not None
    async with serve(ctx) as port:
        assert await served_der(port, "b.example.com") == der(b.cert)


def test_invalid_hostname_is_config_error(tmp_path: Path) -> None:
    cert, key = make_cert(tmp_path, "a.example.com")
    bad = CertificateConfig("bad", ("a..example.com",), cert, key)
    with pytest.raises(ConfigError, match="bad"):
        CertificateStore([bad])


async def test_reload_reaches_a_listener_through_its_unchanged_front_context(
        tmp_path: Path) -> None:
    """A listener keeps the front context it got at start; after a reload a client with SNI
    gets the new certificate through it, also for a name the reload added."""
    a = entry(tmp_path, "a", "a.example.com")
    store = CertificateStore([a])
    listener_ctx = store.front_context()
    assert listener_ctx is not None
    sub = tmp_path / "n"
    sub.mkdir()
    renewed, added = entry(sub, "a", "a.example.com"), entry(sub, "b", "b.example.com")
    store.reload([renewed, added])
    assert store.front_context() is listener_ctx
    async with serve(listener_ctx) as port:
        assert await served_der(port, "a.example.com") == der(renewed.cert)
        assert await served_der(port, "b.example.com") == der(added.cert)
        assert await served_der(port, "") == der(renewed.cert)


async def test_sni_callback_failure_aborts_only_that_handshake(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    a = entry(tmp_path, "a", "a.example.com")
    store = CertificateStore([a])
    ctx = store.front_context()
    assert ctx is not None
    selection = store._selection

    class Broken:
        def pick(self, server_name: str | None) -> ssl.SSLContext | None:
            raise RuntimeError("selection broke")

    async with serve(ctx) as port:
        store._selection = Broken()  # type: ignore[assignment]
        with caplog.at_level("ERROR", logger="asspng.tls.store"):
            with pytest.raises((ssl.SSLError, ConnectionError)):
                await served_der(port, "a.example.com")
        assert "TLS certificate selection failed" in caplog.text
        store._selection = selection
        assert await served_der(port, "a.example.com") == der(a.cert)  # the server lives on


def test_wildcard_lookup_skips_empty_parent(tmp_path: Path) -> None:
    w = entry(tmp_path, "w", "*.example.com")
    sel = CertificateStore([w])._selection
    assert sel.wildcard["example.com"] is sel.first
    assert sel.exact == {}
