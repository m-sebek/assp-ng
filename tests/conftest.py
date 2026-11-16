# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared pytest fixtures."""

import asyncio
import importlib.util
import os
import site
from collections.abc import Callable
from pathlib import Path

import pytest

# Runtime dependencies that must come from Debian packages (docs/development.md).
_DEPENDENCIES = (
    "dns", "redis", "pymysql", "sqlalchemy", "alembic", "systemd", "cryptography", "tomlkit",
)


def _user_site_shadows(user_site: str, names: tuple[str, ...] = _DEPENDENCIES) -> list[str]:
    """Dependencies that Python would import from the per-user site directory (pip --user)
    instead of the Debian package, as ``"name (path)"``."""
    prefix = os.path.join(user_site, "")
    shadowed = []
    for name in names:
        spec = importlib.util.find_spec(name)
        if spec is not None and spec.origin and spec.origin.startswith(prefix):
            shadowed.append(f"{name} ({spec.origin})")
    return shadowed


def pytest_configure(config: pytest.Config) -> None:
    """Stop at once when a dependency would not be the Debian version CI uses."""
    if not site.ENABLE_USER_SITE:
        return
    shadowed = _user_site_shadows(site.getusersitepackages())
    if shadowed:
        pytest.exit(
            "these dependencies come from the per-user site directory, not from Debian: "
            + ", ".join(shadowed)
            + ". Run the checks with PYTHONNOUSERSITE=1 (see docs/development.md).",
            returncode=4,
        )


class FakeClock:
    """A manually advanced clock for deterministic time-dependent tests."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


def make_reader(data: bytes) -> asyncio.StreamReader:
    """Return a StreamReader (64 KiB limit) fed with ``data`` and then EOF."""
    reader = asyncio.StreamReader(limit=65536)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


@pytest.fixture
def reader_from() -> Callable[[bytes], asyncio.StreamReader]:
    """Factory fixture: ``reader_from(b"...")`` gives a finished StreamReader."""
    return make_reader


MINIMAL_SYSTEM_TOML = """\
[[listener]]
name = "inbound"
kind = "smtp"
port = 0
backend = "127.0.0.1:1"
"""


@pytest.fixture
def etc_dir(tmp_path: Path) -> Path:
    """A minimal valid configuration directory (one smtp listener, empty default.toml)."""
    (tmp_path / "assp-ng.toml").write_text(MINIMAL_SYSTEM_TOML, encoding="utf-8")
    (tmp_path / "default.toml").write_text("", encoding="utf-8")
    return tmp_path


pytest_plugins = ["tests.support.redis_server", "tests.support.e2e"]
