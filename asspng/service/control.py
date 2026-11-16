# SPDX-License-Identifier: GPL-3.0-or-later
"""Local control socket for the ``assp-ng`` CLI (design 8.11, 9).

A Unix socket (mode 0660, group ``assp-ng``) is used instead of a localhost HTTP endpoint so
that other local users cannot read mail dialogues. Protocol: one JSON object per line,
``{"cmd": str, "args": {...}}``, answered by ``{"ok": true, "result": ...}`` or
``{"ok": false, "error": str}``.
"""

from __future__ import annotations

import asyncio
import contextlib
import grp
import json
import logging
import os
import stat
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path

log = logging.getLogger(__name__)

Handler = Callable[[dict[str, object]], Awaitable[object]]

_REQUEST_LIMIT = 64 * 1024
_REPLY_LIMIT = 1024 * 1024
_PROBE_TIMEOUT_S = 1.0
_CLOSE_TIMEOUT_S = 1.0


def _encode(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode() + b"\n"


def _error(message: str) -> bytes:
    return _encode({"ok": False, "error": message})


class ControlServer:
    """Serves the registered command handlers on a Unix socket."""

    IDLE_TIMEOUT_S = 30.0

    def __init__(self, path: Path, handlers: Mapping[str, Handler],
                 group: str | None = "assp-ng") -> None:
        self._path = path
        self._handlers = handlers
        self._group = group
        self._server: asyncio.Server | None = None
        self._ident: tuple[int, int] | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        await self._clear_stale()
        old_umask = os.umask(0o117)
        try:
            self._server = await asyncio.start_unix_server(
                self._serve, path=str(self._path), limit=_REQUEST_LIMIT)
        finally:
            os.umask(old_umask)
        os.chmod(self._path, 0o660)
        self._chown_group()
        st = os.lstat(self._path)
        self._ident = (st.st_dev, st.st_ino)

    def _chown_group(self) -> None:
        if self._group is None:
            return
        try:
            gid = grp.getgrnam(self._group).gr_gid
        except KeyError:
            log.warning("control socket group %r does not exist; keeping current group",
                        self._group)
            return
        try:
            os.chown(self._path, -1, gid)
        except PermissionError:
            log.warning("cannot chown control socket to group %r; keeping mode 0660",
                        self._group)

    async def _clear_stale(self) -> None:
        try:
            st = os.lstat(self._path)
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError(f"{self._path} exists and is not a socket; refusing to remove it")
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self._path)), _PROBE_TIMEOUT_S)
        except (ConnectionRefusedError, FileNotFoundError):
            pass  # nothing listens: stale
        except (TimeoutError, OSError) as exc:
            raise RuntimeError(f"cannot probe existing socket {self._path}: {exc}") from exc
        else:
            writer.close()
            raise RuntimeError(f"another instance is already listening on {self._path}")
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._path)

    async def close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for writer in list(self._writers):
            writer.transport.abort()
        if server is not None:
            await server.wait_closed()
        ident, self._ident = self._ident, None
        if ident is not None:
            try:
                st = os.lstat(self._path)
            except FileNotFoundError:
                return
            if (st.st_dev, st.st_ino) == ident and stat.S_ISSOCK(st.st_mode):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self._path)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self._writers.add(writer)
        graceful = False
        try:
            graceful = await self._loop(reader, writer)
        except (TimeoutError, ConnectionError):
            pass
        finally:
            # Only a clean EOF is closed gracefully; anything else may have unsent data
            # that a stalled peer will never read, so the transport is aborted.
            if graceful:
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), _CLOSE_TIMEOUT_S)
            writer.transport.abort()
            self._writers.discard(writer)
            if task is not None:
                self._tasks.discard(task)

    async def _loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """Serve requests; return True on a clean EOF, False when the peer must be dropped."""
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), self.IDLE_TIMEOUT_S)
            except ValueError:  # line over the stream limit
                writer.write(_error("request too large"))
                await asyncio.wait_for(writer.drain(), self.IDLE_TIMEOUT_S)
                return False
            if not line:
                return True
            writer.write(await self._dispatch(line))
            await asyncio.wait_for(writer.drain(), self.IDLE_TIMEOUT_S)

    async def _dispatch(self, line: bytes) -> bytes:
        try:
            req = json.loads(line)
        except (ValueError, RecursionError):
            return _error("invalid JSON")
        if not isinstance(req, dict):
            return _error("request must be a JSON object")
        cmd = req.get("cmd")
        args = req.get("args", {})
        if not isinstance(cmd, str):
            return _error("cmd must be a string")
        if not isinstance(args, dict):
            return _error("args must be an object")
        handler = self._handlers.get(cmd)
        if handler is None:
            return _error(f"unknown command: {cmd}")
        try:
            result = await handler(args)
        except (ValueError, KeyError, TypeError) as exc:
            return _error(str(exc))
        except Exception as exc:  # noqa: BLE001 - never leak internals to the client
            log.error("control command %r failed: %s", cmd, type(exc).__name__)
            return _error("internal error")
        try:
            return _encode({"ok": True, "result": result})
        except (TypeError, ValueError, OverflowError, RecursionError):
            log.error("control command %r returned an unserializable result", cmd)
            return _error("internal error")


async def control_request(path: Path, cmd: str, args: dict[str, object],
                          timeout_s: float = 5.0) -> object:
    """Send one command and return its result; ``RuntimeError`` carries a server error."""

    async def exchange() -> bytes:
        reader, writer = await asyncio.open_unix_connection(str(path), limit=_REPLY_LIMIT)
        try:
            writer.write(_encode({"cmd": cmd, "args": args}))
            await writer.drain()
            return await reader.readline()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    line = await asyncio.wait_for(exchange(), timeout_s)
    try:
        reply = json.loads(line)
    except (ValueError, RecursionError):
        raise RuntimeError("malformed reply") from None
    if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
        raise RuntimeError("malformed reply")
    if not reply["ok"]:
        raise RuntimeError(str(reply.get("error", "unknown error")))
    return reply.get("result")
