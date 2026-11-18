# SPDX-License-Identifier: GPL-3.0-or-later
"""Programmatic Alembic entry points; no ini file.

Alembic is imported only by ``upgrade()``: the proxy reads the applied revision at startup, and
importing Alembic for that would keep about 10 MB of RSS for the life of the service.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import sqlalchemy as sa

from asspng.db.schema import make_engine

if TYPE_CHECKING:
    from alembic.config import Config

HEAD_REVISION = "0001"

_SCRIPT_LOCATION = Path(__file__).resolve().parent / "migrations"
_VERSION_TABLE = "alembic_version"  # Alembic's default, which env.py keeps


def _config(url: str) -> Config:
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(_SCRIPT_LOCATION))
    # Not set_main_option: ConfigParser interpolation breaks on "%" in encoded passwords.
    config.attributes["url"] = url
    return config


def upgrade(url: str) -> None:
    """Upgrade the database to the head revision."""
    from alembic import command

    command.upgrade(_config(url), "head")


def current_revision(url: str) -> str | None:
    """Return the applied revision, or None for a database that was never migrated."""
    engine: sa.Engine = make_engine(url)
    try:
        with engine.connect() as conn:
            if not sa.inspect(conn).has_table(_VERSION_TABLE):
                return None
            version = sa.table(_VERSION_TABLE, sa.column("version_num", sa.String))
            # Several rows would mean several heads, which a linear history never has.
            revision: str | None = conn.execute(
                sa.select(version.c.version_num)).scalar_one_or_none()
            return revision
    finally:
        engine.dispose()
