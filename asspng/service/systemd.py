# SPDX-License-Identifier: GPL-3.0-or-later
"""systemd readiness and watchdog notifications; a no-op outside systemd."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable

log = logging.getLogger(__name__)

_daemon_notify: Callable[[str], object] | None = None
try:
    from systemd.daemon import notify as _systemd_notify

    _daemon_notify = _systemd_notify
except ImportError:  # python3-systemd not installed
    pass


def notify(message: str) -> None:
    """Send ``message`` (e.g. ``READY=1``) to systemd. Never raises."""
    if _daemon_notify is None or not os.environ.get("NOTIFY_SOCKET"):
        return
    try:
        _daemon_notify(message)
    except Exception as exc:
        log.debug("systemd notify failed: %s", type(exc).__name__)
