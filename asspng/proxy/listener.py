# SPDX-License-Identifier: GPL-3.0-or-later
"""Listening sockets (spec 4.1): one asyncio server per enabled address family of a listener.

Sockets are created here rather than by asyncio, so that the IPv6 one is IPv6-only
(``IPV6_V6ONLY``). IPv4 clients then always arrive on the IPv4 socket, with their plain address,
whatever the system default for dual-stack sockets is.

``submissions`` listeners speak TLS from the first byte, but they accept plain TCP: the session
starts TLS itself once its limits admitted the client (spec 4.2, ruling R59), so the limits
also bound the pending handshakes. Until then such a connection reads nothing, so the client's
TLS ClientHello waits in the socket for the TLS layer instead of reaching the plaintext reader.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Awaitable, Callable, Sequence
from functools import partial
from typing import Any, cast

from asspng.config.errors import ConfigError
from asspng.config.model import ListenerConfig, ListenerKind
from asspng.tls.store import CertificateStore

_log = logging.getLogger(__name__)

READ_LIMIT = 64 * 1024  # StreamReader buffer limit of a client connection
# Accept-queue length of a listening socket; the kernel caps it at net.core.somaxconn. asyncio's
# default of 100 overflows on connection bursts: the kernel then falls back to SYN cookies and
# drops connections it cannot queue, which the clients still see as open, waiting for a
# greeting until their own timeout.
LISTEN_BACKLOG = socket.SOMAXCONN

ConnectionHandler = Callable[
    [ListenerConfig, asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]
StreamHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class _PausedStreamProtocol(asyncio.StreamReaderProtocol):
    """A stream connection that reads nothing until ``StreamWriter.start_tls`` resumes it."""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # The transport starts reading only after this call, and never while paused.
        cast(asyncio.ReadTransport, transport).pause_reading()
        super().connection_made(transport)


async def start_server(handler: StreamHandler, *, implicit_tls: bool,
                       **kwargs: Any) -> asyncio.Server:
    """``asyncio.start_server`` with ``READ_LIMIT``; ``kwargs`` go to ``create_server``.

    With ``implicit_tls`` a connection reads nothing until ``handler`` calls ``start_tls``
    on its writer (see the module docstring).
    """
    loop = asyncio.get_running_loop()
    protocol = _PausedStreamProtocol if implicit_tls else asyncio.StreamReaderProtocol

    def factory() -> asyncio.StreamReaderProtocol:
        reader = asyncio.StreamReader(limit=READ_LIMIT, loop=loop)
        return protocol(reader, handler, loop=loop)

    return await loop.create_server(factory, **kwargs)


def _bind(family: socket.AddressFamily, host: str, port: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        sock.setblocking(False)
    except BaseException:
        sock.close()
        raise
    return sock


class ListenerManager:
    """Starts and stops the servers of the configured listeners."""

    def __init__(
        self,
        listeners: Sequence[ListenerConfig],
        handler: ConnectionHandler,
        tls: CertificateStore,
    ) -> None:
        self._listeners = tuple(listeners)
        self._handler = handler
        self._tls = tls
        self._servers: list[tuple[ListenerConfig, asyncio.Server]] = []

    async def start(self) -> None:
        """Bind and serve every enabled family. On an error the servers already started stay
        registered, so ``close()`` stops them."""
        for listener in self._listeners:
            implicit_tls = listener.kind is ListenerKind.SUBMISSIONS
            if implicit_tls and self._tls.front_context() is None:
                raise ConfigError(f"listener {listener.name!r}: submissions needs a TLS "
                                  "certificate")
            families = ((socket.AF_INET, listener.bind4, listener.ipv4),
                        (socket.AF_INET6, listener.bind6, listener.ipv6))
            for family, host, enabled in families:
                if enabled:
                    await self._serve(listener, family, host, implicit_tls)

    async def _serve(self, listener: ListenerConfig, family: socket.AddressFamily, host: str,
                     implicit_tls: bool) -> None:
        sock = _bind(family, host, listener.port)
        callback = partial(self._handler, listener)
        try:
            server = await start_server(callback, implicit_tls=implicit_tls, sock=sock,
                                        backlog=LISTEN_BACKLOG)
        except BaseException:
            sock.close()
            raise
        self._servers.append((listener, server))
        _log.info("listener %s (%s) on %s port %d", listener.name, listener.kind.value, host,
                  server.sockets[0].getsockname()[1])

    async def close(self) -> None:
        """Stop accepting connections; open connections are left to their handlers.

        ``Server.wait_closed()`` is not awaited: since Python 3.12 it also waits for every
        open connection, which the application drains itself (spec 8.3).
        """
        servers, self._servers = self._servers, []
        for _, server in servers:
            server.close()

    def addresses(self) -> list[tuple[str, str, int]]:
        """``(listener, host, port)`` of every bound socket, with the real port."""
        result: list[tuple[str, str, int]] = []
        for listener, server in self._servers:
            for sock in server.sockets:
                host, port = sock.getsockname()[:2]
                result.append((listener.name, str(host), int(port)))
        return result
