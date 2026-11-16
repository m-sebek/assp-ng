# SPDX-License-Identifier: GPL-3.0-or-later
"""Alembic environment; the URL arrives through config.attributes["url"]."""

from alembic import context

from asspng.db.schema import make_engine, metadata

config = context.config

if context.is_offline_mode():
    raise RuntimeError("offline migrations are not supported")

engine = make_engine(config.attributes["url"])
try:
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=metadata)
        with context.begin_transaction():
            context.run_migrations()
finally:
    engine.dispose()
