# SPDX-License-Identifier: GPL-3.0-or-later
"""Everything the Postfix commands touch outside their arguments, injectable for tests."""
from __future__ import annotations

import datetime as dt
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from asspng.postfix.apply import Backend, Probe, Target, make_verifier
from asspng.postfix.inspect import Run

VerifyFactory = Callable[[Sequence[Target], Sequence[Backend]], Callable[[], bool]]


def _ask(question: str) -> bool:
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def _verify_factory(targets: Sequence[Target], backends: Sequence[Backend]
                    ) -> Callable[[], bool]:
    return make_verifier(targets, backends)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@dataclass
class PostfixEnv:
    run: Run = subprocess.run
    etc: Path = Path("/etc/postfix")
    # Root-owned 0700 (ruling R58): never under /var/lib/assp-ng, which the service user owns.
    backup_root: Path = Path("/var/backups/assp-ng")
    ispconfig_dir: Path = Path("/usr/local/ispconfig")
    rspamd_dir: Path = Path("/etc/rspamd")
    amavis_dir: Path = Path("/etc/amavis")
    isatty: Callable[[], bool] = field(default=lambda: sys.stdin.isatty())
    confirm: Callable[[str], bool] = _ask
    verify_factory: VerifyFactory = _verify_factory
    now: Callable[[], dt.datetime] = _now
    probe: Probe | None = None  # None: EHLO to the restored public ports
