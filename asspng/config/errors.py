# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration errors."""
from __future__ import annotations


class ConfigError(Exception):
    """Raised when configuration is invalid; ``errors`` lists every problem found."""

    def __init__(self, errors: list[str] | str) -> None:
        self.errors: list[str] = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))
