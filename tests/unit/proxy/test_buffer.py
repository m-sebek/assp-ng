# SPDX-License-Identifier: GPL-3.0-or-later
import os
import stat
from pathlib import Path
from typing import BinaryIO

import pytest

from asspng.proxy.buffer import BufferBudget, MessageBuffer, purge_spool


def make(tmp_path: Path, budget: BufferBudget | None = None, memory_limit: int = 100,
         max_size: int = 1000) -> tuple[BufferBudget, MessageBuffer]:
    b = budget or BufferBudget(10_000)
    return b, MessageBuffer(b, tmp_path, memory_limit, max_size)


def test_small_stays_in_memory(tmp_path: Path) -> None:
    budget, buf = make(tmp_path)
    buf.write(b"hello ")
    buf.write(b"world")
    assert buf.size == 11
    assert not buf.spooled and not buf.oversize
    assert budget.used == 11
    assert list(tmp_path.iterdir()) == []
    assert buf.read_head(5) == b"hello"
    assert b"".join(buf.iter_chunks(chunk=4)) == b"hello world"
    assert b"".join(buf.iter_chunks(start=6)) == b"world"
    buf.close()


def test_spills_over_memory_limit(tmp_path: Path) -> None:
    budget, buf = make(tmp_path, memory_limit=10)
    buf.write(b"12345")
    buf.write(b"6789012345")
    assert buf.spooled
    assert budget.used == 0
    files = list(tmp_path.iterdir())
    assert len(files) == 1
    assert stat.S_IMODE(os.stat(files[0]).st_mode) == 0o600
    buf.write(b"tail")
    assert buf.size == 19
    assert buf.read_head(7) == b"1234567"
    assert b"".join(buf.iter_chunks(chunk=6)) == b"123456789012345tail"
    assert b"".join(buf.iter_chunks(start=15)) == b"tail"
    buf.close()


def test_spills_when_budget_exhausted(tmp_path: Path) -> None:
    budget = BufferBudget(8)
    _, buf = make(tmp_path, budget, memory_limit=100)
    buf.write(b"abcdef")
    assert not buf.spooled and budget.used == 6
    buf.write(b"ghijkl")
    assert buf.spooled
    assert budget.used == 0
    assert b"".join(buf.iter_chunks()) == b"abcdefghijkl"
    buf.close()


def test_oversize_discards(tmp_path: Path) -> None:
    budget, buf = make(tmp_path, memory_limit=1000, max_size=10)
    buf.write(b"0123456")
    buf.write(b"789abcdef")
    assert buf.oversize
    assert buf.size == 10
    assert b"".join(buf.iter_chunks()) == b"0123456789"
    buf.write(b"more")
    assert buf.size == 10
    buf.close()
    assert budget.used == 0


def test_oversize_in_spool(tmp_path: Path) -> None:
    _, buf = make(tmp_path, memory_limit=4, max_size=10)
    buf.write(b"0123456789abc")
    assert buf.spooled and buf.oversize and buf.size == 10
    assert b"".join(buf.iter_chunks()) == b"0123456789"
    buf.close()


def test_close_deletes_and_releases(tmp_path: Path) -> None:
    budget, mem = make(tmp_path)
    mem.write(b"abc")
    mem.close()
    assert budget.used == 0
    _, spooled = make(tmp_path, budget, memory_limit=2)
    spooled.write(b"abcdef")
    assert len(list(tmp_path.iterdir())) == 1
    spooled.close()
    assert list(tmp_path.iterdir()) == []
    assert budget.used == 0


def test_close_deletes_the_spool_file_when_closing_it_fails(tmp_path: Path) -> None:
    """C9: a failing file close (e.g. EIO on flush) must not leave the message on disk."""
    budget, buf = make(tmp_path, memory_limit=2)
    buf.write(b"spooled message")
    assert len(list(tmp_path.iterdir())) == 1
    real_file = buf._file
    assert real_file is not None

    class FailingClose:
        def close(self) -> None:
            real_file.close()
            raise OSError(5, "Input/output error")
    buf._file = FailingClose()  # type: ignore[assignment]
    with pytest.raises(OSError):
        buf.close()
    assert list(tmp_path.iterdir()) == []
    assert budget.used == 0


def test_close_idempotent(tmp_path: Path) -> None:
    budget, buf = make(tmp_path, memory_limit=2)
    buf.write(b"abcdef")
    buf.close()
    buf.close()
    assert budget.used == 0


def test_context_manager(tmp_path: Path) -> None:
    budget = BufferBudget(100)
    with MessageBuffer(budget, tmp_path, 50, 100) as buf:
        buf.write(b"xyz")
        assert budget.used == 3
    assert budget.used == 0


def test_two_buffers_share_budget(tmp_path: Path) -> None:
    budget = BufferBudget(10)
    _, a = make(tmp_path, budget)
    _, b = make(tmp_path, budget)
    a.write(b"aaaaaa")
    b.write(b"bbbb")
    assert budget.used == 10
    a.write(b"a")           # budget exhausted: a spills, releasing 6
    assert a.spooled and budget.used == 4
    b.write(b"b")           # 4 + 1 now fits in the released budget
    assert not b.spooled and budget.used == 5
    b.close()
    assert budget.used == 0
    a.close()
    assert budget.used == 0


def test_budget_primitives() -> None:
    budget = BufferBudget(5)
    assert budget.try_reserve(5)
    assert not budget.try_reserve(1)
    budget.release(5)
    assert budget.used == 0


def test_purge_spool_removes_leftovers(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"1")
    (tmp_path / "b").write_bytes(b"2")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "keep").write_bytes(b"3")
    target = tmp_path.parent / (tmp_path.name + "-target")
    target.write_bytes(b"t")
    (tmp_path / "link").symlink_to(target)
    assert purge_spool(tmp_path) == 3
    assert sorted(p.name for p in tmp_path.iterdir()) == ["sub"]
    assert (sub / "keep").exists()
    assert target.exists()


def test_purge_spool_missing_dir(tmp_path: Path) -> None:
    assert purge_spool(tmp_path / "nope") == 0


def test_write_after_read_memory(tmp_path: Path) -> None:
    _, buf = make(tmp_path)
    buf.write(b"abcdef")
    assert buf.read_head(2) == b"ab"
    buf.write(b"XYZ")
    assert b"".join(buf.iter_chunks()) == b"abcdefXYZ"
    buf.close()


def test_write_after_read_spool(tmp_path: Path) -> None:
    _, buf = make(tmp_path, memory_limit=2)
    buf.write(b"abcdef")
    assert buf.read_head(2) == b"ab"
    buf.write(b"XYZ")
    assert b"".join(buf.iter_chunks()) == b"abcdefXYZ"
    assert buf.size == 9
    buf.close()


def test_failed_spill_is_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    budget, buf = make(tmp_path, memory_limit=4)
    buf.write(b"abc")
    real = os.fdopen

    class Boom:
        def __init__(self, f: BinaryIO) -> None:
            self.f = f

        def write(self, data: bytes) -> int:
            raise OSError(28, "No space left")

        def close(self) -> None:
            self.f.close()

    monkeypatch.setattr(os, "fdopen", lambda fd, mode: Boom(real(fd, mode)))
    for _ in range(2):
        with pytest.raises(OSError):
            buf.write(b"defgh")
        assert list(tmp_path.iterdir()) == []
        assert budget.used == 3
        assert not buf.spooled and buf.size == 3
    monkeypatch.undo()
    buf.write(b"de")
    assert b"".join(buf.iter_chunks()) == b"abcde"
    buf.close()
    assert budget.used == 0 and list(tmp_path.iterdir()) == []


def test_failed_file_write_marks_buffer_failed(tmp_path: Path) -> None:
    budget, buf = make(tmp_path, memory_limit=2)
    buf.write(b"abcdef")
    assert buf._file is not None
    buf._file = _FailingFile()             # type: ignore[assignment]
    with pytest.raises(OSError):
        buf.write(b"x")
    with pytest.raises(ValueError):
        buf.write(b"y")
    with pytest.raises(ValueError):
        buf.read_head(1)
    with pytest.raises(ValueError):
        buf.iter_chunks()
    buf.close()
    assert list(tmp_path.iterdir()) == [] and budget.used == 0


class _FailingFile:
    def seek(self, *a: int) -> int:
        return 0

    def write(self, data: bytes) -> int:
        raise OSError(28, "No space left")

    def close(self) -> None:
        pass


def test_invalid_read_arguments(tmp_path: Path) -> None:
    _, buf = make(tmp_path)
    buf.write(b"abc")
    with pytest.raises(ValueError):
        buf.iter_chunks(chunk=0)
    with pytest.raises(ValueError):
        buf.read_head(-1)
    assert buf.read_head(0) == b""
    buf.close()


def test_iter_chunks_closed_check_is_eager(tmp_path: Path) -> None:
    _, buf = make(tmp_path)
    buf.close()
    with pytest.raises(ValueError):
        buf.iter_chunks()


def test_purge_spool_continues_after_unlink_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture) -> None:
    (tmp_path / "a").write_bytes(b"1")
    (tmp_path / "b").write_bytes(b"2")
    real = Path.unlink

    def flaky(self: Path, missing_ok: bool = False) -> None:
        if self.name == "a":
            raise PermissionError("nope")
        real(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", flaky)
    with caplog.at_level("WARNING"):
        assert purge_spool(tmp_path) == 1
    assert (tmp_path / "a").exists() and not (tmp_path / "b").exists()
    assert "cannot remove" in caplog.text
