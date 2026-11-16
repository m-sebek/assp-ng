# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed settings registry: every setting is defined once, in code."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from asspng.config.errors import ConfigError

KINDS = ("int", "float", "bool", "str", "duration", "list[duration]", "list[str]")

_DURATION_RE = re.compile(r"([0-9]+)([smhd]?)")
_INT_RE = re.compile(r"[+-]?[0-9]+")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_TRUE = frozenset({"true", "yes", "on", "1"})
_FALSE = frozenset({"false", "no", "off", "0"})


class Level(Enum):
    """The most specific layer at which a setting may be overridden."""

    SYSTEM = "system"
    RECIPIENT = "recipient"
    SENDER = "sender"


@dataclass(frozen=True)
class Setting:
    """Definition of one configuration setting.

    ``default`` is the raw file form (durations are strings such as "15m").
    ``minimum``/``maximum`` apply to numbers, durations (in seconds) and to every
    element of a list. ``fingerprint`` says whether the setting takes part in
    recipient grouping (RECIPIENT level only).
    """

    key: str
    kind: str
    default: object
    level: Level
    description: str
    choices: tuple[str, ...] | None = None
    minimum: float | None = None
    maximum: float | None = None
    fingerprint: bool = True
    non_empty: bool = False


def parse_duration(text: str | int) -> int:
    """Return seconds for an int or a string like "90", "30s", "15m", "24h", "7d"."""
    if isinstance(text, bool):
        raise ValueError("duration must not be a boolean")
    if isinstance(text, int):
        if text < 0:
            raise ValueError(f"negative duration: {text}")
        return text
    match = _DURATION_RE.fullmatch(text)
    if match is None:
        raise ValueError(f"invalid duration {text!r}: use digits with an optional s, m, h or d")
    return int(match.group(1)) * _UNITS[match.group(2)]


class Registry:
    """Collection of Setting definitions with value coercion and validation."""

    def __init__(self) -> None:
        self._settings: dict[str, Setting] = {}

    def register(self, s: Setting) -> None:
        if s.key in self._settings:
            raise ValueError(f"setting {s.key!r} is already registered")
        if s.kind not in KINDS:
            raise ValueError(f"setting {s.key!r} has unknown kind {s.kind!r}")
        self._settings[s.key] = s

    def get(self, key: str) -> Setting:
        return self._settings[key]

    def all(self) -> list[Setting]:
        return list(self._settings.values())

    def coerce(self, key: str, value: object) -> object:
        """Return the typed, normalised value or raise ConfigError naming the key."""
        s = self.get(key)
        try:
            return self._coerce(s, value)
        except ValueError as exc:
            raise ConfigError(f"{key}: {exc}") from None

    def _coerce(self, s: Setting, value: object) -> object:
        if s.kind.startswith("list["):
            items = self._as_list(value)
            if s.non_empty and not items:
                raise ValueError("must not be empty")
            elem = s.kind[5:-1]
            return [self._check(s, self._scalar(s, elem, item)) for item in items]
        return self._check(s, self._scalar(s, s.kind, value))

    @staticmethod
    def _as_list(value: object) -> list[object]:
        if isinstance(value, list):
            return list(value)
        if isinstance(value, str):
            return [p.strip() for p in value.split(",")] if value.strip() else []
        raise ValueError(f"expected a list, got {type(value).__name__}")

    @staticmethod
    def _scalar(s: Setting, kind: str, value: object) -> object:
        if kind == "bool":
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in _TRUE:
                return True
            if isinstance(value, str) and value.lower() in _FALSE:
                return False
            raise ValueError("expected true/false/yes/no/on/off/1/0")
        if kind == "int":
            if isinstance(value, bool):
                raise ValueError("expected an integer, got a boolean")
            if isinstance(value, int):
                return value
            if isinstance(value, str) and _INT_RE.fullmatch(value):
                return int(value)
            raise ValueError("expected an integer")
        if kind == "float":
            if isinstance(value, bool):
                raise ValueError("expected a number, got a boolean")
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value)
                except ValueError:
                    pass
            raise ValueError("expected a number")
        if kind == "duration":
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError("expected a duration such as 90, 30s, 15m, 24h or 7d")
            return parse_duration(value)
        if not isinstance(value, str):
            raise ValueError(f"expected a string, got {type(value).__name__}")
        return value

    @staticmethod
    def _check(s: Setting, value: object) -> object:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if s.minimum is not None and value < s.minimum:
                raise ValueError(f"{value} is below the minimum {s.minimum:g}")
            if s.maximum is not None and value > s.maximum:
                raise ValueError(f"{value} is above the maximum {s.maximum:g}")
        if s.choices is not None and value not in s.choices:
            raise ValueError(f"{value!r} is not one of {', '.join(s.choices)}")
        return value
