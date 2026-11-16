# SPDX-License-Identifier: GPL-3.0-or-later
import os
import re
import stat
from pathlib import Path

import pytest

from asspng.config import editor
from asspng.config.docgen import render_default_toml, render_reference
from asspng.config.errors import ConfigError
from asspng.config.loader import load_config
from asspng.config.settings import REGISTRY


def test_set_preserves_comments(tmp_path: Path) -> None:
    path = tmp_path / "default.toml"
    path.write_text('# top comment\ntestmode = false  # inline\n\n[scoring]\n# why\nlimit = 50\n')
    editor.set_value(path, "scoring.limit", 60)
    text = path.read_text()
    assert "# top comment" in text and "# inline" in text and "# why" in text
    assert "limit = 60" in text


def test_set_creates_nested_tables_and_missing_dir(tmp_path: Path) -> None:
    path = tmp_path / "user.d" / "a@example.com.toml"
    editor.set_value(path, "limits.user.messages_per_hour", 5000)
    assert path.read_text() == "[limits.user]\nmessages_per_hour = 5000\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_bak_written(tmp_path: Path) -> None:
    path = tmp_path / "default.toml"
    path.write_text("testmode = false\n")
    path.chmod(0o600)
    editor.set_value(path, "testmode", True)
    bak = tmp_path / "default.toml.bak"
    assert bak.read_text() == "testmode = false\n"
    assert stat.S_IMODE(bak.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_new_file_has_no_bak(tmp_path: Path) -> None:
    editor.set_value(tmp_path / "default.toml", "testmode", True)
    assert not (tmp_path / "default.toml.bak").exists()


def test_atomic_write_leaves_old_file_on_failure(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "default.toml"
    path.write_text("testmode = false\n")

    def boom(src: object, dst: object) -> None:
        raise OSError("disk")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        editor.set_value(path, "testmode", True)
    assert path.read_text() == "testmode = false\n"
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_set_on_invalid_toml_is_refused_without_quoting(tmp_path: Path) -> None:
    path = tmp_path / "assp-ng.toml"
    path.write_text("url = 'mysql://u:hunter2@h/d'\nbroken = = 1\n")
    with pytest.raises(ConfigError) as info:
        editor.set_value(path, "testmode", True)
    assert "hunter2" not in str(info.value)
    assert "hunter2" in path.read_text()


def test_unset(tmp_path: Path) -> None:
    path = tmp_path / "default.toml"
    path.write_text("# keep\ntestmode = true\n\n[scoring]\nlimit = 60\nwarn = 40\n")
    assert editor.unset_value(path, "scoring.limit") is True
    assert "limit" not in path.read_text() and "warn = 40" in path.read_text()
    assert editor.unset_value(path, "scoring.warn") is True
    assert "[scoring]" not in path.read_text() and "# keep" in path.read_text()
    assert editor.unset_value(path, "scoring.warn") is False
    assert editor.unset_value(tmp_path / "missing.toml", "testmode") is False
    assert (tmp_path / "default.toml.bak").exists()


def test_unset_missing_key_does_not_touch_file(tmp_path: Path) -> None:
    path = tmp_path / "default.toml"
    path.write_text("testmode = true\n")
    assert editor.unset_value(path, "scoring.limit") is False
    assert not (tmp_path / "default.toml.bak").exists()


def test_init_output_loads(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text(render_default_toml(REGISTRY))
    snap = load_config(etc_dir)
    assert snap.default_layer == {}


def test_init_output_documents_every_policy_key_and_uncomments_cleanly(etc_dir: Path) -> None:
    text = render_default_toml(REGISTRY)
    for s in REGISTRY.all():
        if s.level.value != "system":
            assert f"# {s.key.rpartition('.')[2]} = " in text
    # Uncommenting every assignment and table header must give a valid file.
    live = "\n".join(re.sub(r"^# (\[[a-z_.]+\]|[a-z_]+ = .*)$", r"\1", line)
                     for line in text.splitlines())
    (etc_dir / "default.toml").write_text(live)
    snap = load_config(etc_dir)
    assert snap.default_layer["scoring.limit"] == 50
    assert snap.default_layer["limits.user.messages_per_hour"] == 300


def test_doc_contains_every_key() -> None:
    doc = render_reference(REGISTRY)
    for s in REGISTRY.all():
        assert f"| `{s.key}` |" in doc
    assert "| Key | Type | Default | Level | Description |" in doc


def test_reference_document_is_current() -> None:
    path = Path(__file__).resolve().parents[3] / "docs" / "configuration.md"
    assert path.read_text(encoding="utf-8") == render_reference(REGISTRY)


def test_new_file_and_dirs_inherit_parent_group(tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    fchowns: list[tuple[int, int]] = []
    chowns: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: fchowns.append((uid, gid)))
    monkeypatch.setattr(os, "chown", lambda p, uid, gid: chowns.append((str(p), uid, gid)))
    gid = tmp_path.stat().st_gid
    editor.set_value(tmp_path / "domain.d" / "x.example.toml", "testmode", True)
    assert (-1, gid) in fchowns
    assert (str(tmp_path / "domain.d"), -1, gid) in chowns
    assert stat.S_IMODE((tmp_path / "domain.d").stat().st_mode) == 0o750


def test_chown_failure_warns_instead_of_crashing(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch,
                                                 capsys: pytest.CaptureFixture[str]) -> None:
    def deny(*args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(os, "fchown", deny)
    monkeypatch.setattr(os, "chown", deny)
    editor.set_value(tmp_path / "user.d" / "a@x.example.toml", "testmode", True)
    assert (tmp_path / "user.d" / "a@x.example.toml").read_text() == "testmode = true\n"
    assert "warning" in capsys.readouterr().err
