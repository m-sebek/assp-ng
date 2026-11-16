# SPDX-License-Identifier: GPL-3.0-or-later
"""Programmatic Alembic entry points; no ini file."""

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext

from asspng.db.schema import make_engine

HEAD_REVISION = "0001"

_SCRIPT_LOCATION = Path(__file__).resolve().parent / "migrations"


def _config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(_SCRIPT_LOCATION))
    # Not set_main_option: ConfigParser interpolation breaks on "%" in encoded passwords.
    config.attributes["url"] = url
    return config


def upgrade(url: str) -> None:
    """Upgrade the database to the head revision."""
    command.upgrade(_config(url), "head")


def current_revision(url: str) -> str | None:
    """Return the applied revision, or None for a database that was never migrated."""
    engine: sa.Engine = make_engine(url)
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()
