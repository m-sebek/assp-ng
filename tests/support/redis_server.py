# SPDX-License-Identifier: GPL-3.0-or-later
"""A private, throw-away ``redis-server`` for integration tests (never the system Redis)."""

import ctypes
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import redis

_PR_SET_PDEATHSIG = 1


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _die_with_parent() -> Callable[[], None] | None:
    """A ``preexec_fn`` that kills the child when pytest dies (Linux only, else ``None``)."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
    except (OSError, AttributeError):
        return None

    def preexec() -> None:
        try:
            prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        except Exception:  # best effort only
            pass

    return preexec


class RedisServer:
    """A ``redis-server`` child process on a free loopback port; can be stopped and restarted."""

    def __init__(self, workdir: Path) -> None:
        self._dir = workdir
        self.port = _free_port()
        self._proc: subprocess.Popen[bytes] | None = None

    @property
    def url(self) -> str:
        return f"redis://127.0.0.1:{self.port}/0"

    def _alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _ping(self) -> bool:
        client = redis.Redis(host="127.0.0.1", port=self.port, socket_timeout=1)
        try:
            return bool(client.ping())
        except redis.exceptions.RedisError:
            return False
        finally:
            client.close()

    def start(self) -> None:
        if self._alive():
            return
        binary = shutil.which("redis-server")
        if binary is None:
            raise RuntimeError("redis-server binary not found in PATH (install redis-server)")
        for attempt in range(3):
            if attempt:
                self.port = _free_port()  # the previous port may have been taken meanwhile
            self._proc = subprocess.Popen(
                [binary, "--port", str(self.port), "--bind", "127.0.0.1",
                 "--save", "", "--appendonly", "no", "--dir", str(self._dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=_die_with_parent(),
            )
            deadline = time.monotonic() + 10
            while self._alive() and time.monotonic() < deadline:
                if self._ping() and self._alive():
                    return
                time.sleep(0.05)
            self.stop()
        raise RuntimeError("redis-server did not start after 3 attempts")

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="session")
def redis_server() -> Iterator[RedisServer]:
    workdir = Path(tempfile.mkdtemp(prefix="asspng-redis-"))
    server = RedisServer(workdir)
    try:
        server.start()
        yield server
    finally:
        server.stop()
        shutil.rmtree(workdir, ignore_errors=True)
