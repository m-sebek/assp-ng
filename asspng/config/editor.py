# SPDX-License-Identifier: GPL-3.0-or-later
"""Comment-preserving, atomic editing of one TOML configuration file (spec 7.6).

Every write goes through a temporary file in the same directory that is fsynced and then
renamed over the target. A previous version of the file is kept as ``<file>.bak`` with the
original mode. New files are created with mode 0640. Error messages never quote file content,
because assp-ng.toml holds credentials.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import sys
import tempfile
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit.exceptions import TOMLKitError

from asspng.config.errors import ConfigError

NEW_FILE_MODE = 0o640
NEW_DIR_MODE = 0o750
LOCK_NAME = ".assp-ng.lock"


def _load(path: Path) -> tuple[Any, int | None]:
    """Return the parsed document and the mode of the existing file (None when new)."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return tomlkit.document(), None
    mode = path.stat().st_mode & 0o7777
    try:
        return tomlkit.parse(raw.decode("utf-8")), mode
    except (UnicodeDecodeError, TOMLKitError):
        raise ConfigError(f"{path}: is not valid TOML; fix it by hand first") from None


def _warn_group(path: Path) -> None:
    print(f"warning: cannot give {path} the group of its directory; fix it with chgrp",
          file=sys.stderr)


def ensure_dir(directory: Path) -> None:
    """Create ``directory`` (0750) and missing parents; new ones get their parent's group."""
    missing: list[Path] = []
    node = directory
    while not node.exists() and node != node.parent:
        missing.append(node)
        node = node.parent
    for new in reversed(missing):
        new.mkdir(mode=NEW_DIR_MODE, exist_ok=True)
        new.chmod(NEW_DIR_MODE)
        try:
            os.chown(new, -1, new.parent.stat().st_gid)
        except PermissionError:
            _warn_group(new)


@contextlib.contextmanager
def locked(directory: Path) -> Iterator[None]:
    """Hold an exclusive lock on ``<directory>/.assp-ng.lock`` for a whole edit."""
    ensure_dir(directory)
    lock = directory / LOCK_NAME
    new = not lock.exists()
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, NEW_FILE_MODE)
    try:
        if new:
            try:
                os.fchown(fd, -1, directory.stat().st_gid)
            except PermissionError:
                _warn_group(lock)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the lock


def _write_atomic(path: Path, data: bytes, mode: int, like: Path | None = None) -> None:
    """Write ``data`` to ``path`` through a fsynced temporary file and a rename."""
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            if like is not None:
                st = like.stat()
                with contextlib.suppress(PermissionError):
                    os.fchown(handle.fileno(), st.st_uid, st.st_gid)
            else:
                try:
                    os.fchown(handle.fileno(), -1, path.parent.stat().st_gid)
                except PermissionError:
                    _warn_group(path)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def write_text(path: Path, text: str) -> None:
    """Atomically write ``text``; keep ``<path>.bak`` and the mode of an existing file."""
    ensure_dir(path.parent)
    mode = NEW_FILE_MODE
    like: Path | None = None
    if path.is_file():
        mode = path.stat().st_mode & 0o7777
        like = path
        bak = path.with_name(path.name + ".bak")
        _write_atomic(bak, path.read_bytes(), mode, like)
    _write_atomic(path, text.encode("utf-8"), mode, like)


def set_value(path: Path, key: str, value: object) -> None:
    """Set the dotted ``key`` to ``value`` (already typed for TOML), creating the file."""
    doc, _ = _load(path)
    *tables, leaf = key.split(".")
    node: Any = doc
    for name in tables:
        if name not in node:
            node[name] = tomlkit.table(is_super_table=True)
        node = node[name]
        if not hasattr(node, "keys"):
            raise ConfigError(f"{path}: {name} is not a table")
    node[leaf] = value
    write_text(path, tomlkit.dumps(doc))


def unset_value(path: Path, key: str) -> bool:
    """Remove the dotted ``key``; return False (and write nothing) when it was not set."""
    if not path.is_file():
        return False
    doc, _ = _load(path)
    *tables, leaf = key.split(".")
    chain: list[Any] = [doc]
    for name in tables:
        child = chain[-1].get(name)
        if child is None or not hasattr(child, "keys"):
            return False
        chain.append(child)
    if leaf not in chain[-1]:
        return False
    del chain[-1][leaf]
    pairs = zip(reversed(tables), reversed(chain[:-1]), reversed(chain[1:]))
    for name, parent, node in pairs:
        if len(node) == 0:
            del parent[name]
    write_text(path, tomlkit.dumps(doc))
    return True


def keys_in(path: Path) -> set[str]:
    """Dotted names of the plain values in ``path`` (arrays of tables are skipped)."""
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return set()
    found: set[str] = set()

    def walk(table: dict[str, Any], prefix: str) -> None:
        for name, value in table.items():
            if isinstance(value, dict):
                walk(value, f"{prefix}{name}.")
            elif not (isinstance(value, list) and value
                      and all(isinstance(v, dict) for v in value)):
                found.add(f"{prefix}{name}")

    walk(data, "")
    return found
