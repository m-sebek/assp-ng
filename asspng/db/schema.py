# SPDX-License-Identifier: GPL-3.0-or-later
"""Table definitions (spec 5.9) and the engine factory shared by repository and migrations."""

import sqlalchemy as sa
from sqlalchemy.engine import Engine

metadata = sa.MetaData()

local_domain = sa.Table(
    "local_domain",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("domain", sa.String(253), nullable=False, unique=True),
    sa.Column("include_subdomains", sa.Boolean, nullable=False, server_default=sa.text("0")),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("1")),
    sa.Column("note", sa.String(255), nullable=True),
    sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    sa.Column(
        "updated_at",
        sa.DateTime,
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    ),
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)

audit_log = sa.Table(
    "audit_log",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("ts", sa.DateTime, nullable=False, server_default=sa.func.now()),
    sa.Column("instance", sa.String(64), nullable=False),
    sa.Column("actor", sa.String(64), nullable=False),
    sa.Column("action", sa.String(64), nullable=False),
    sa.Column("target", sa.String(255), nullable=False),
    sa.Column("details", sa.JSON, nullable=True),
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)


def make_engine(url: str) -> Engine:
    """Create an engine that survives stale connections and never hangs on a dead server."""
    if sa.engine.make_url(url).drivername.endswith("+pymysql"):
        return sa.create_engine(
            url,
            pool_pre_ping=True,
            pool_recycle=3600,
            connect_args={"connect_timeout": 5, "read_timeout": 10, "write_timeout": 10},
        )
    return sa.create_engine(url, pool_pre_ping=True, pool_recycle=3600)
