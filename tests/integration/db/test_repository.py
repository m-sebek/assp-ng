# SPDX-License-Identifier: GPL-3.0-or-later
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa

from asspng.db.migrate import HEAD_REVISION, current_revision, upgrade
from asspng.db.repository import (
    DatabaseDomainSource,
    DomainExistsError,
    DomainRepository,
    write_audit,
)
from asspng.db.schema import audit_log
from asspng.domains.index import DomainEntry

MYSQL_URL = os.environ.get("ASSPNG_TEST_DB_URL", "")


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "mysql",
            marks=pytest.mark.skipif(not MYSQL_URL, reason="set ASSPNG_TEST_DB_URL"),
        ),
    ]
)
def db_url(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    """A clean database per test: every table, alembic_version included, is dropped."""
    url = f"sqlite:///{tmp_path / 'test.db'}" if request.param == "sqlite" else MYSQL_URL
    engine = sa.create_engine(url)
    try:
        meta = sa.MetaData()
        meta.reflect(engine)
        meta.drop_all(engine)
    finally:
        engine.dispose()
    yield url


@pytest.fixture
def migrated_url(db_url: str) -> str:
    upgrade(db_url)
    return db_url


def _audit_rows(url: str) -> list[sa.Row[tuple[object, ...]]]:
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            return list(conn.execute(sa.select(audit_log).order_by(audit_log.c.id)))
    finally:
        engine.dispose()


def test_upgrade_creates_tables_and_revision(db_url: str) -> None:
    assert current_revision(db_url) is None
    upgrade(db_url)
    assert current_revision(db_url) == HEAD_REVISION == "0001"
    engine = sa.create_engine(db_url)
    try:
        names = set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert {"local_domain", "audit_log", "alembic_version"} <= names
    upgrade(db_url)  # idempotent
    assert current_revision(db_url) == "0001"


def test_add_normalizes_idn(migrated_url: str) -> None:
    repo = DomainRepository(migrated_url, "mx1")
    repo.add("Bücher.Example.", include_subdomains=True, note="n", actor="cli")
    assert repo.list() == [DomainEntry("xn--bcher-kva.example", True, True)]
    repo.close()


def test_remove_and_audit(migrated_url: str) -> None:
    repo = DomainRepository(migrated_url, "mx1")
    repo.add("example.com", include_subdomains=False, note="hello", actor="alice")
    assert repo.remove("EXAMPLE.com", actor="bob") is True
    assert repo.remove("example.com", actor="bob") is False
    assert repo.list() == []
    rows = _audit_rows(migrated_url)
    assert [(r.action, r.target, r.actor, r.instance) for r in rows] == [
        ("domain.add", "example.com", "alice", "mx1"),
        ("domain.remove", "example.com", "bob", "mx1"),
    ]
    assert rows[0].details == {"include_subdomains": False, "note": "hello"}
    repo.close()


def test_source_loads_enabled(migrated_url: str) -> None:
    repo = DomainRepository(migrated_url, "mx1")
    repo.add("a.example", include_subdomains=True, note=None, actor="cli")
    repo.add("b.example", include_subdomains=False, note=None, actor="cli")
    engine = sa.create_engine(migrated_url)
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE local_domain SET enabled = 0 WHERE domain = 'b.example'"))
    engine.dispose()
    source = DatabaseDomainSource(migrated_url)
    assert sorted(source.load(), key=lambda e: e.domain) == [
        DomainEntry("a.example", True, True),
        DomainEntry("b.example", False, False),
    ]
    source.close()
    assert len(source.load()) == 2  # a closed source reconnects on demand
    source.close()
    repo.close()


def test_duplicate_add_raises(migrated_url: str) -> None:
    repo = DomainRepository(migrated_url, "mx1")
    repo.add("example.com", include_subdomains=False, note=None, actor="cli")
    with pytest.raises(DomainExistsError) as info:
        repo.add("EXAMPLE.com.", include_subdomains=True, note=None, actor="cli")
    assert migrated_url not in str(info.value)
    assert len(repo.list()) == 1
    assert len(_audit_rows(migrated_url)) == 1  # failed add rolled back its audit row
    repo.close()


def test_write_audit_standalone(migrated_url: str) -> None:
    write_audit(
        migrated_url, instance="mx1", actor="cli", action="x.y", target="t", details={"k": 1}
    )
    rows = _audit_rows(migrated_url)
    assert len(rows) == 1 and rows[0].details == {"k": 1}
