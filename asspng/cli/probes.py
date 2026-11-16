# SPDX-License-Identifier: GPL-3.0-or-later
"""The live checks of ``assp-ng config check``.

Each probe returns a short detail text or raises. Failures are reported by exception type
(and the message of ``ProbeError``/``BackendError``/``StateError``, which are fixed texts);
the database and Redis URLs carry passwords and are never printed.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

import sqlalchemy as sa

from asspng.config.errors import ConfigError
from asspng.config.model import CertificateConfig, ListenerConfig
from asspng.db.schema import make_engine
from asspng.proxy.backend import SmtpBackend
from asspng.state.redis_store import RedisStore
from asspng.tls.store import CertificateStore

_PROBE_TIMEOUT_S = 5.0


class ProbeError(Exception):
    """A probe failed; the message is a fixed text that is safe to print."""


def probe_database(url: str) -> str:
    engine = make_engine(url)
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
    finally:
        engine.dispose()
    return "connected"


def probe_redis(url: str, prefix: str) -> str:
    async def run() -> None:
        store = RedisStore(url, prefix, _PROBE_TIMEOUT_S)
        try:
            await store.ping()
        finally:
            await store.close()

    asyncio.run(run())
    return "ping ok"


def probe_backend(listener: ListenerConfig, connect_s: float, banner_s: float) -> str:
    async def run() -> str:
        backend = SmtpBackend(listener.backend_host, listener.backend_port,
                              connect_timeout_s=connect_s, banner_timeout_s=banner_s)
        try:
            banner = await backend.connect()
            if banner.code != 220:
                raise ProbeError(f"unexpected banner {banner.code}")
            ehlo = await backend.command(b"EHLO assp-ng-check", _PROBE_TIMEOUT_S * 6)
            if not 200 <= ehlo.code < 300:
                raise ProbeError(f"EHLO rejected with {ehlo.code}")
            offered = {line.split(" ", 1)[0].upper() for line in ehlo.lines[1:]}
            if listener.xclient and "XCLIENT" not in offered:
                raise ProbeError("backend does not advertise XCLIENT")
            return "banner and EHLO ok" + (", XCLIENT offered" if listener.xclient else "")
        finally:
            await backend.close()

    return asyncio.run(run())


def probe_certificate(cert: CertificateConfig) -> str:
    try:
        days = CertificateStore([cert]).days_left()[cert.name]
    except (ConfigError, OSError):
        raise ProbeError("cannot load the certificate and key") from None
    if days < 0:
        raise ProbeError(f"expired {-days} days ago")
    return f"valid, {days} days left"


@dataclass
class Probes:
    """The injectable probes; tests replace them with fakes."""

    database: Callable[[str], str] = probe_database
    redis: Callable[[str, str], str] = probe_redis
    backend: Callable[[ListenerConfig, float, float], str] = probe_backend
    certificate: Callable[[CertificateConfig], str] = probe_certificate
