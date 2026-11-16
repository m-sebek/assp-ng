# SPDX-License-Identifier: GPL-3.0-or-later
"""Message buffer with a global RAM budget and a private on-disk spool."""
from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

log = logging.getLogger(__name__)


class BufferBudget:
    """A global pool of bytes that in-memory buffers reserve from."""

    def __init__(self, total: int) -> None:
        self.total = total
        self.used = 0

    def try_reserve(self, n: int) -> bool:
        if n < 0 or self.used + n > self.total:
            return False
        self.used += n
        return True

    def release(self, n: int) -> None:
        self.used = max(0, self.used - n)


class MessageBuffer:
    """Holds one message: in RAM while small, in a 0600 spool file otherwise.

    At most ``max_size`` bytes are stored. Further bytes are discarded and
    ``oversize`` becomes True; ``size`` never exceeds ``max_size``.

    If writing to the spool file fails (``OSError``), the buffer is marked
    failed: later ``write``/read calls raise ``ValueError``; call ``close()``.
    A failure while creating the spool file leaves the buffer intact in memory.
    """

    def __init__(self, budget: BufferBudget, spool_dir: Path, memory_limit: int,
                 max_size: int) -> None:
        self._budget = budget
        self._spool_dir = spool_dir
        self._memory_limit = memory_limit
        self._max_size = max_size
        self._mem = bytearray()
        self._reserved = 0
        self._file: BinaryIO | None = None
        self._path: Path | None = None
        self._closed = False
        self._failed = False
        self.size = 0
        self.oversize = False

    @property
    def spooled(self) -> bool:
        return self._file is not None

    def write(self, data: bytes) -> None:
        self._check_usable("write to")
        room = self._max_size - self.size
        if len(data) > room:
            self.oversize = True
            data = data[:room]
        if not data:
            return
        if self._file is None:
            if (self.size + len(data) <= self._memory_limit
                    and self._budget.try_reserve(len(data))):
                self._reserved += len(data)
                self._mem += data
                self.size += len(data)
                return
            self._spill()
        assert self._file is not None
        try:
            self._file.seek(0, os.SEEK_END)
            self._file.write(data)
        except OSError:
            self._failed = True
            raise
        self.size += len(data)

    def _check_usable(self, what: str) -> None:
        if self._closed:
            raise ValueError(f"{what} a closed MessageBuffer")
        if self._failed:
            raise ValueError(f"{what} a failed MessageBuffer")

    def _spill(self) -> None:
        fd, name = tempfile.mkstemp(dir=self._spool_dir)
        path = Path(name)
        f: BinaryIO | None = None
        try:
            os.fchmod(fd, 0o600)
            f = os.fdopen(fd, "w+b")
            f.write(self._mem)
            f.flush()
        except BaseException:
            try:
                if f is not None:
                    f.close()
                else:
                    os.close(fd)
            except OSError:
                pass
            path.unlink(missing_ok=True)
            raise
        self._path = path
        self._file = f
        self._mem = bytearray()
        self._budget.release(self._reserved)
        self._reserved = 0

    def read_head(self, limit: int) -> bytes:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        for part in self.iter_chunks(0, max(1, limit)):
            return part[:limit]
        return b""

    def iter_chunks(self, start: int = 0, chunk: int = 65536) -> Iterator[bytes]:
        self._check_usable("read from")
        if chunk <= 0:
            raise ValueError("chunk must be > 0")
        return self._iter_chunks(max(0, start), chunk)

    def _iter_chunks(self, pos: int, chunk: int) -> Iterator[bytes]:
        if self._file is None:
            while pos < self.size:
                yield bytes(self._mem[pos:pos + chunk])
                pos += chunk
            return
        f = self._file
        while pos < self.size:
            f.seek(pos)
            data = f.read(min(chunk, self.size - pos))
            if not data:
                return
            pos += len(data)
            yield data

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._budget.release(self._reserved)
        self._reserved = 0
        self._mem = bytearray()
        file, self._file = self._file, None
        path, self._path = self._path, None
        try:
            if file is not None:
                file.close()
        finally:  # the message never stays on disk, even when closing the file fails
            if path is not None:
                path.unlink(missing_ok=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None,
                 exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


def purge_spool(spool_dir: Path) -> int:
    """Delete leftover files (and symlinks, not their targets) directly in spool_dir."""
    count = 0
    try:
        entries = list(spool_dir.iterdir())
    except FileNotFoundError:
        return 0
    for entry in entries:
        if entry.is_symlink() or entry.is_file():
            try:
                entry.unlink(missing_ok=True)
            except OSError as exc:
                log.warning("cannot remove spool leftover %s: %s", entry, exc)
                continue
            count += 1
    return count
