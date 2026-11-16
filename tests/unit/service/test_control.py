# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the local control socket (design 8.11, 9)."""

from __future__ import annotations

import asyncio
import contextlib
import grp
import json
import os
import shutil
import socket
import stat
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest

from asspng.service.control import ControlServer, control_request


@pytest.fixture
def sock_path() -> Iterator[Path]:
    d = tempfile.mkdtemp(dir="/tmp", prefix="asspc")
    yield Path(d) / "control.sock"
    shutil.rmtree(d, ignore_errors=True)


async def _echo(args: dict[str, object]) -> object:
    return {"echo": args}


async def _bad_value(args: dict[str, object]) -> object:
    raise ValueError("bad value here")


async def _bad_runtime(args: dict[str, object]) -> object:
    raise RuntimeError("secret detail")


async def _unserializable(args: dict[str, object]) -> object:
    return {1, 2, 3}


@pytest.fixture
async def server(sock_path: Path) -> AsyncIterator[ControlServer]:
    srv = ControlServer(sock_path, {"echo": _echo, "val": _bad_value, "rt": _bad_runtime,
                                    "ser": _unserializable}, group=None)
    await srv.start()
    yield srv
    await srv.close()


async def _raw(path: Path, data: bytes, lines: int = 1) -> list[Any]:
    reader, writer = await asyncio.open_unix_connection(str(path))
    writer.write(data)
    await writer.drain()
    out = [json.loads(await asyncio.wait_for(reader.readline(), 5)) for _ in range(lines)]
    writer.close()
    return out


async def test_roundtrip(server: ControlServer, sock_path: Path) -> None:
    assert await control_request(sock_path, "echo", {"a": 1}) == {"echo": {"a": 1}}


async def test_unknown_command_error(server: ControlServer, sock_path: Path) -> None:
    with pytest.raises(RuntimeError, match="unknown command"):
        await control_request(sock_path, "nope", {})


@pytest.mark.parametrize("group", [None, grp.getgrgid(os.getgid()).gr_name])
async def test_socket_mode_0660(sock_path: Path, group: str | None) -> None:
    srv = ControlServer(sock_path, {}, group=group)
    await srv.start()
    try:
        st = os.lstat(sock_path)
        assert stat.S_ISSOCK(st.st_mode)
        assert stat.S_IMODE(st.st_mode) == 0o660
        if group is not None:
            assert st.st_gid == os.getgid()
    finally:
        await srv.close()


async def test_umask_restored(sock_path: Path) -> None:
    old = os.umask(0o022)
    try:
        srv = ControlServer(sock_path, {}, group=None)
        await srv.start()
        await srv.close()
        assert os.umask(0o022) == 0o022
    finally:
        os.umask(old)


async def test_unknown_group_is_ignored(sock_path: Path) -> None:
    srv = ControlServer(sock_path, {}, group="no-such-group-xyz")
    await srv.start()
    try:
        assert stat.S_IMODE(os.lstat(sock_path).st_mode) == 0o660
    finally:
        await srv.close()


async def test_stale_socket_replaced(sock_path: Path) -> None:
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(sock_path))
    s.close()  # leaves a stale socket file behind
    assert stat.S_ISSOCK(os.lstat(sock_path).st_mode)
    srv = ControlServer(sock_path, {"echo": _echo}, group=None)
    await srv.start()
    try:
        assert await control_request(sock_path, "echo", {}) == {"echo": {}}
    finally:
        await srv.close()


async def test_live_listener_refuses_start(server: ControlServer, sock_path: Path) -> None:
    other = ControlServer(sock_path, {}, group=None)
    with pytest.raises(RuntimeError):
        await other.start()
    assert await control_request(sock_path, "echo", {}) == {"echo": {}}


async def test_regular_file_never_deleted(sock_path: Path) -> None:
    sock_path.write_text("precious")
    srv = ControlServer(sock_path, {}, group=None)
    with pytest.raises(RuntimeError):
        await srv.start()
    assert sock_path.read_text() == "precious"


async def test_symlink_never_followed(sock_path: Path) -> None:
    target = sock_path.parent / "target.txt"
    target.write_text("keep")
    sock_path.symlink_to(target)
    srv = ControlServer(sock_path, {}, group=None)
    with pytest.raises(RuntimeError):
        await srv.start()
    assert sock_path.is_symlink()
    assert target.read_text() == "keep"


async def test_directory_never_deleted(sock_path: Path) -> None:
    sock_path.mkdir()
    srv = ControlServer(sock_path, {}, group=None)
    with pytest.raises(RuntimeError):
        await srv.start()
    assert sock_path.is_dir()


async def test_close_removes_own_socket(sock_path: Path) -> None:
    srv = ControlServer(sock_path, {}, group=None)
    await srv.start()
    await srv.close()
    assert not os.path.lexists(sock_path)


async def test_close_leaves_replaced_path_alone(sock_path: Path) -> None:
    srv = ControlServer(sock_path, {}, group=None)
    await srv.start()
    os.unlink(sock_path)
    sock_path.write_text("someone else")
    await srv.close()
    assert sock_path.read_text() == "someone else"


async def test_close_cancels_active_connections(sock_path: Path) -> None:
    srv = ControlServer(sock_path, {}, group=None)
    await srv.start()
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    await asyncio.sleep(0.05)
    await asyncio.wait_for(srv.close(), 5)
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()


async def test_oversized_request_rejected(server: ControlServer, sock_path: Path) -> None:
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    writer.write(b'{"cmd":"echo","args":{"x":"' + b"a" * 70000 + b'"}}\n')
    await writer.drain()
    reply = json.loads(await asyncio.wait_for(reader.readline(), 5))
    assert reply["ok"] is False
    assert await asyncio.wait_for(reader.read(), 5) == b""  # connection closed
    writer.close()


async def test_idle_timeout_closes(
    sock_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ControlServer, "IDLE_TIMEOUT_S", 0.2)
    srv = ControlServer(sock_path, {}, group=None)
    await srv.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(sock_path))
        assert await asyncio.wait_for(reader.read(), 5) == b""
        writer.close()
    finally:
        await srv.close()


async def test_handler_value_error_returns_message(
    server: ControlServer, sock_path: Path
) -> None:
    with pytest.raises(RuntimeError, match="bad value here"):
        await control_request(sock_path, "val", {})


async def test_handler_other_error_is_internal(
    server: ControlServer, sock_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with pytest.raises(RuntimeError) as ei:
        await control_request(sock_path, "rt", {})
    assert str(ei.value) == "internal error"
    assert "secret detail" not in str(ei.value)
    assert "RuntimeError" in caplog.text


async def test_unserializable_result_is_internal(
    server: ControlServer, sock_path: Path
) -> None:
    with pytest.raises(RuntimeError, match="^internal error$"):
        await control_request(sock_path, "ser", {})


@pytest.mark.parametrize("line", [
    b'[1,2]\n', b'"x"\n', b'{"cmd":5}\n', b'{"cmd":"echo","args":[1]}\n',
    b'{"args":{}}\n', b'not json\n', b"[" * 60000 + b"\n",
])
async def test_bad_requests_error_and_continue(
    server: ControlServer, sock_path: Path, line: bytes
) -> None:
    first, second = await _raw(sock_path, line + b'{"cmd":"echo","args":{"k":1}}\n', 2)
    assert first["ok"] is False
    assert second == {"ok": True, "result": {"echo": {"k": 1}}}


async def test_args_default_empty(server: ControlServer, sock_path: Path) -> None:
    (reply,) = await _raw(sock_path, b'{"cmd":"echo"}\n')
    assert reply == {"ok": True, "result": {"echo": {}}}


async def test_several_requests_in_order(server: ControlServer, sock_path: Path) -> None:
    data = b"".join(json.dumps({"cmd": "echo", "args": {"n": i}}).encode() + b"\n"
                    for i in range(5))
    replies = await _raw(sock_path, data, 5)
    assert [r["result"]["echo"]["n"] for r in replies] == [0, 1, 2, 3, 4]


async def test_reply_is_compact_single_line(server: ControlServer, sock_path: Path) -> None:
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    writer.write(b'{"cmd":"echo","args":{"a":1}}\n')
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), 5)
    writer.close()
    assert line == b'{"ok":true,"result":{"echo":{"a":1}}}\n'


async def test_control_request_malformed_reply(sock_path: Path) -> None:
    async def cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()
        writer.write(b"garbage\n")
        await writer.drain()
        writer.close()

    srv = await asyncio.start_unix_server(cb, path=str(sock_path))
    try:
        with pytest.raises(RuntimeError, match="malformed reply"):
            await control_request(sock_path, "x", {})
    finally:
        srv.close()
        await srv.wait_closed()


async def test_control_request_timeout(sock_path: Path) -> None:
    async def cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(5)

    srv = await asyncio.start_unix_server(cb, path=str(sock_path))
    try:
        with pytest.raises(TimeoutError):
            await control_request(sock_path, "x", {}, timeout_s=0.2)
    finally:
        srv.close()


async def test_control_request_missing_socket(sock_path: Path) -> None:
    with pytest.raises(OSError):
        await control_request(sock_path, "x", {})


async def test_control_request_nested_reply_is_malformed(sock_path: Path) -> None:
    async def cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()
        writer.write(b"[" * 60000 + b"\n")
        await writer.drain()
        writer.close()

    srv = await asyncio.start_unix_server(cb, path=str(sock_path))
    try:
        with pytest.raises(RuntimeError, match="malformed reply"):
            await control_request(sock_path, "x", {})
    finally:
        srv.close()
        await srv.wait_closed()


async def test_non_reading_client_is_dropped(
    sock_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def big(args: dict[str, object]) -> object:
        return "x" * (16 * 1024 * 1024)

    monkeypatch.setattr(ControlServer, "IDLE_TIMEOUT_S", 0.5)
    srv = ControlServer(sock_path, {"big": big, "echo": _echo}, group=None)
    await srv.start()
    loop = asyncio.get_running_loop()
    s = socket.socket(socket.AF_UNIX)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.setblocking(False)
    try:
        await loop.sock_connect(s, str(sock_path))
        await loop.sock_sendall(s, b'{"cmd":"big"}\n')  # never read during the timeout
        await asyncio.sleep(0.2)
        assert await control_request(sock_path, "echo", {}) == {"echo": {}}
        await asyncio.sleep(1.0)  # timeout plus margin
        assert not [t for t in asyncio.all_tasks() if "_serve" in repr(t.get_coro())]

        async def drain_to_end() -> None:
            while await loop.sock_recv(s, 1 << 20):
                pass

        with contextlib.suppress(ConnectionError):  # EOF or reset both prove the drop
            await asyncio.wait_for(drain_to_end(), 3)
        await asyncio.wait_for(srv.close(), 2)
    finally:
        s.close()
