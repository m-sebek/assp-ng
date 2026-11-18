# SPDX-License-Identifier: GPL-3.0-or-later
"""What the proxy process loads: every import stays resident for the life of the service."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_the_proxy_does_not_load_alembic() -> None:
    # Alembic costs about 10 MB of RSS for good; the proxy only needs the applied revision,
    # which current_revision() reads with SQLAlchemy alone. Alembic is for "db upgrade".
    code = (
        "import sys\n"
        "import asspng.proxy.__main__\n"
        "from asspng.db.migrate import current_revision\n"
        "assert current_revision('sqlite://') is None\n"
        "print(sorted(name for name in sys.modules if name.split('.')[0] == 'alembic'))\n"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True,
                            text=True, timeout=60, check=True)
    assert result.stdout.strip() == "[]"
