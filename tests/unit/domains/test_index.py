# SPDX-License-Identifier: GPL-3.0-or-later
import json
import logging
import os
import stat
from pathlib import Path

import pytest

from asspng.domains.index import DomainEntry, DomainIndex, load_snapshot, save_snapshot


def test_exact_and_subdomains() -> None:
    index = DomainIndex([
        DomainEntry("example.com", include_subdomains=False),
        DomainEntry("corp.test", include_subdomains=True),
    ])
    assert len(index) == 2
    assert index.is_local("example.com")
    assert not index.is_local("sub.example.com")
    assert index.is_local("corp.test")
    assert index.is_local("sub.corp.test")
    assert index.is_local("a.b.corp.test")
    assert not index.is_local("badcorp.test")
    assert not index.is_local("other.org")


def test_case_and_idn() -> None:
    index = DomainIndex([DomainEntry("xn--bcher-kva.example", False)])
    assert index.is_local("BÜCHER.example")
    assert DomainIndex([DomainEntry("example.com", False)]).is_local("EXAMPLE.com.")
    entry_idn = DomainIndex([DomainEntry("BÜCHER.Example.", False)])
    assert entry_idn.is_local("xn--bcher-kva.example")


def test_empty_domain_is_local() -> None:
    assert DomainIndex([]).is_local("")
    assert DomainIndex.unavailable().is_local("")


def test_disabled_ignored() -> None:
    index = DomainIndex([
        DomainEntry("off.example", True, enabled=False),
        DomainEntry("on.example", True),
    ])
    assert not index.is_local("off.example")
    assert not index.is_local("x.off.example")
    assert index.is_local("on.example")


def test_invalid_input_not_local() -> None:
    index = DomainIndex([DomainEntry("example.com", True)])
    assert index.is_local("a..example.com") is False
    assert index.is_local("[bad") is False
    assert index.is_local(".example.com") is False


def test_dot_is_not_local() -> None:
    assert DomainIndex([DomainEntry("example.com", True)]).is_local(".") is False
    assert DomainIndex.unavailable().is_local(".") is False


def test_degenerate_entries_skipped() -> None:
    index = DomainIndex([
        DomainEntry(".", True), DomainEntry("", True), DomainEntry(".example.com", True),
    ])
    assert len(index) == 0
    assert not index.is_local("example.com")
    assert index.is_local("")


def test_address_literals() -> None:
    index = DomainIndex([DomainEntry("[192.0.2.1]", True)])
    assert index.is_local("[192.0.2.1]")
    assert not index.is_local("[192.0.2.2]")
    assert not index.is_local("x.[192.0.2.1]")
    assert not DomainIndex([DomainEntry("example.com", True)]).is_local("[192.0.2.1]")
    odd = DomainIndex([DomainEntry("2.1]", True), DomainEntry("a[b", True)])
    assert len(odd) == 0
    assert not odd.is_local("[192.0.2.1]")


def test_invalid_entries_skipped_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="asspng.domains.index"):
        index = DomainIndex([DomainEntry("a..b", False), DomainEntry("ok.example", False)])
    assert len(index) == 1
    assert index.is_local("ok.example")
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_unavailable() -> None:
    index = DomainIndex.unavailable()
    assert index.available is False
    assert len(index) == 0
    assert not index.is_local("example.com")
    assert DomainIndex([]).available is True


def test_snapshot_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "domains.json"
    entries = [DomainEntry("example.com", True), DomainEntry("off.test", False, False)]
    old_umask = os.umask(0o077)
    try:
        save_snapshot(path, entries)
    finally:
        os.umask(old_umask)
    assert load_snapshot(path) == entries
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert json.loads(path.read_text())["version"] == 1
    assert [p.name for p in tmp_path.iterdir()] == ["domains.json"]
    save_snapshot(path, [])
    assert load_snapshot(path) == []


@pytest.mark.parametrize("content", [
    "{not json",
    "[]",
    '{"version": 2, "entries": []}',
    '{"version": true, "entries": []}',
    '{"version": 1}',
    '{"version": 1, "entries": [{"domain": "a.b"}]}',
    '{"version": 1, "entries": [{"domain": 1, "include_subdomains": true, "enabled": true}]}',
    '{"version": 1, "entries": [{"domain": "a.b", "include_subdomains": "yes", "enabled": true}]}',
    '{"version": 1, "entries": ["x"]}',
])
def test_corrupt_snapshot_none(tmp_path: Path, content: str) -> None:
    path = tmp_path / "domains.json"
    path.write_text(content)
    assert load_snapshot(path) is None


def test_missing_snapshot_none(tmp_path: Path) -> None:
    assert load_snapshot(tmp_path / "nope.json") is None


def test_unreadable_snapshot_none(tmp_path: Path) -> None:
    assert load_snapshot(tmp_path) is None


def _boom(*args: object, **kwargs: object) -> None:
    raise OSError("boom")


@pytest.mark.parametrize("target", ["json.dump", "os.fsync", "os.replace"])
def test_save_failure_keeps_old_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    path = tmp_path / "domains.json"
    old = [DomainEntry("old.example", True)]
    save_snapshot(path, old)
    module, name = target.split(".")
    monkeypatch.setattr(f"{module}.{name}", _boom)
    with pytest.raises(OSError, match="boom"):
        save_snapshot(path, [DomainEntry("new.example", False)])
    monkeypatch.undo()
    assert [p.name for p in tmp_path.iterdir()] == ["domains.json"]
    assert load_snapshot(path) == old
