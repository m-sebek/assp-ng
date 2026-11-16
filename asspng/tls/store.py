# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate store: SNI selection and atomic reload of server TLS contexts.

Listeners are created once with ``front_context()``.  Its ``sni_callback`` swaps
in the per-certificate context for the requested name, so a reload only has to
replace the selection table; no listener is restarted.
"""
from __future__ import annotations

import logging
import math
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509

from asspng.config.errors import ConfigError
from asspng.config.model import CertificateConfig

log = logging.getLogger(__name__)

INTERMEDIATE_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
)

_SECONDS_PER_DAY = 86400


def make_server_context(cert: Path, key: Path) -> ssl.SSLContext:
    """Build a TLS >= 1.2 server context for one certificate/key pair.

    TLS 1.3 suites keep the OpenSSL defaults; ``INTERMEDIATE_CIPHERS`` applies to
    TLS 1.2.  No client certificate is requested.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION | getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    ctx.set_ciphers(INTERMEDIATE_CIPHERS)
    ctx.load_cert_chain(cert, key)
    return ctx


@dataclass(frozen=True)
class _Selection:
    """Immutable lookup table; replaced as a whole on reload."""

    exact: dict[str, ssl.SSLContext]
    wildcard: dict[str, ssl.SSLContext]  # parent domain -> context for ``*.parent``
    first: ssl.SSLContext | None
    not_after: dict[str, datetime]

    def pick(self, server_name: str | None) -> ssl.SSLContext | None:
        if server_name:
            name = server_name.lower().rstrip(".")
            found = self.exact.get(name)
            if found is not None:
                return found
            _, _, parent = name.partition(".")
            if parent:
                found = self.wildcard.get(parent)
                if found is not None:
                    return found
        return self.first


def _not_after(cert: Path) -> datetime:
    return x509.load_pem_x509_certificate(cert.read_bytes()).not_valid_after_utc


def _normalize_host(host: str) -> str:
    """Lowercase A-label form of a configured hostname, keeping a ``*.`` prefix.

    Raises ValueError (UnicodeError) when the name cannot be IDNA-encoded.
    """
    host = host.rstrip(".").lower()
    prefix = "*." if host.startswith("*.") else ""
    return prefix + host[len(prefix):].encode("idna").decode("ascii")


def _build(certs: Sequence[CertificateConfig]) -> _Selection:
    exact: dict[str, ssl.SSLContext] = {}
    wildcard: dict[str, ssl.SSLContext] = {}
    not_after: dict[str, datetime] = {}
    first: ssl.SSLContext | None = None
    errors: list[str] = []
    for cfg in certs:
        try:
            ctx = make_server_context(cfg.cert, cfg.key)
            not_after[cfg.name] = _not_after(cfg.cert)
        except (ssl.SSLError, OSError, ValueError) as exc:
            errors.append(f"certificate {cfg.name!r}: cannot load: {exc}")
            continue
        try:
            hosts = [_normalize_host(h) for h in cfg.hostnames]
        except ValueError as exc:
            errors.append(f"certificate {cfg.name!r}: invalid hostname: {exc}")
            continue
        first = first or ctx
        for host in hosts:
            if host.startswith("*."):
                wildcard.setdefault(host[2:], ctx)
            else:
                exact.setdefault(host, ctx)
    if errors:
        raise ConfigError(errors)
    return _Selection(exact, wildcard, first, not_after)


class CertificateStore:
    """Holds the configured certificates and one stable front context.

    The front context is loaded once (at construction, or on the first non-empty
    reload of an empty store) and never mutated afterwards; its ``sni_callback``
    decides the certificate of every handshake.  ``reload()`` only builds new
    contexts and swaps the selection table in a single assignment, so it may run
    off the event-loop thread.
    """

    def __init__(
        self,
        certs: Sequence[CertificateConfig],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._clock = clock
        self._selection = _build(certs)
        self._front: ssl.SSLContext | None = None
        if certs:
            self._front = self._make_front(certs[0])

    def _make_front(self, first: CertificateConfig) -> ssl.SSLContext:
        try:
            front = make_server_context(first.cert, first.key)
        except (ssl.SSLError, OSError) as exc:
            raise ConfigError([f"certificate {first.name!r}: cannot load: {exc}"]) from exc
        front.sni_callback = self._on_sni
        return front

    def _on_sni(
        self, ssl_obj: ssl.SSLObject | ssl.SSLSocket, server_name: str | None,
        _ctx: ssl.SSLContext,
    ) -> int | None:
        # Runs for every handshake, with server_name None when the client sent no SNI.
        try:
            chosen = self._selection.pick(server_name)
            if chosen is None:
                return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE
            ssl_obj.context = chosen
        except Exception:
            log.exception("TLS certificate selection failed")
            return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
        return None

    def front_context(self) -> ssl.SSLContext | None:
        """The context to give listeners; ``None`` until a certificate has been loaded."""
        return self._front

    def reload(self, certs: Sequence[CertificateConfig]) -> None:
        """Rebuild all contexts; on any failure raise ConfigError and keep the old state.

        A store created empty gets its front context on the first non-empty reload.

        Reloading with an empty list is allowed: ``front_context()`` keeps returning
        the same object (never reset to ``None`` once created), but the selection
        table is empty, so every handshake is aborted with a handshake_failure
        alert.  The application refuses such configs before getting here.
        """
        new = _build(certs)  # raises before anything is touched
        front = self._make_front(certs[0]) if certs and self._front is None else None
        if front is not None:
            self._front = front
        self._selection = new
        log.info("certificate store reloaded: %d certificates", len(certs))

    def days_left(self) -> dict[str, int]:
        """Whole days until each certificate expires (negative when expired)."""
        now = self._clock()
        return {
            name: math.floor((end - now).total_seconds() / _SECONDS_PER_DAY)
            for name, end in self._selection.not_after.items()
        }
