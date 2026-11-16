# SPDX-License-Identifier: GPL-3.0-or-later
"""Local-domain repository and audit log writer (synchronous; callers use asyncio.to_thread)."""

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from asspng.db.schema import audit_log, local_domain, make_engine
from asspng.domains.index import DomainEntry
from asspng.smtp.address import normalize_domain

_Entries = list[DomainEntry]


class DomainExistsError(ValueError):
    """The domain is already in local_domain."""


def _insert_audit(
    conn: Connection,
    *,
    instance: str,
    actor: str,
    action: str,
    target: str,
    details: dict[str, object],
) -> None:
    conn.execute(
        sa.insert(audit_log).values(
            instance=instance, actor=actor, action=action, target=target, details=details
        )
    )


def _load(engine: Engine) -> _Entries:
    stmt = sa.select(
        local_domain.c.domain, local_domain.c.include_subdomains, local_domain.c.enabled
    ).order_by(local_domain.c.domain)
    with engine.connect() as conn:
        return [DomainEntry(r.domain, bool(r.include_subdomains), bool(r.enabled))
                for r in conn.execute(stmt)]


class DomainRepository:
    def __init__(self, url: str, instance: str) -> None:
        self._engine = make_engine(url)
        self._instance = instance

    def close(self) -> None:
        self._engine.dispose()

    def add(self, domain: str, *, include_subdomains: bool, note: str | None, actor: str) -> None:
        name = normalize_domain(domain)
        try:
            with self._engine.begin() as conn:
                conn.execute(
                    sa.insert(local_domain).values(
                        domain=name, include_subdomains=include_subdomains, note=note
                    )
                )
                _insert_audit(
                    conn,
                    instance=self._instance,
                    actor=actor,
                    action="domain.add",
                    target=name,
                    details={"include_subdomains": include_subdomains, "note": note},
                )
        except IntegrityError:
            raise DomainExistsError(f"domain already exists: {name}") from None

    def remove(self, domain: str, *, actor: str) -> bool:
        name = normalize_domain(domain)
        with self._engine.begin() as conn:
            result = conn.execute(sa.delete(local_domain).where(local_domain.c.domain == name))
            if result.rowcount == 0:
                return False
            _insert_audit(
                conn,
                instance=self._instance,
                actor=actor,
                action="domain.remove",
                target=name,
                details={},
            )
        return True

    def list(self) -> _Entries:
        return _load(self._engine)


class DatabaseDomainSource:
    """DomainSource backed by local_domain; load() is blocking."""

    def __init__(self, url: str) -> None:
        self._engine = make_engine(url)

    def close(self) -> None:
        self._engine.dispose()

    def load(self) -> _Entries:
        return _load(self._engine)


def write_audit(
    url: str,
    *,
    instance: str,
    actor: str,
    action: str,
    target: str,
    details: dict[str, object],
) -> None:
    engine = make_engine(url)
    try:
        with engine.begin() as conn:
            _insert_audit(
                conn, instance=instance, actor=actor, action=action, target=target, details=details
            )
    finally:
        engine.dispose()
