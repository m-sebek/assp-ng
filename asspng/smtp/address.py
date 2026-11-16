# SPDX-License-Identifier: GPL-3.0-or-later
"""SMTP path and address parsing (RFC 5321 with Postfix-level leniency)."""

from __future__ import annotations

from dataclasses import dataclass

_BAD_DOMAIN_CHARS = frozenset(' \t\r\n\0<>@",:;()\\')
_MAX_DOMAIN = 253


class AddressError(ValueError):
    """Raised when a path or address cannot be parsed."""


class AtSignInLocalPart(AddressError):
    """An unquoted ``@`` in the local part (``a@b@c``): routing syntax, never accepted."""


@dataclass(frozen=True)
class Address:
    """A mailbox. ``local`` keeps its original case and quoting.

    ``str(addr)`` is ``local@domain``, or just ``postmaster`` when the domain is
    empty. ``key`` is the lowercase local part, ``@`` and the normalized domain;
    for the bare postmaster address it is ``postmaster@``.
    """

    local: str
    domain: str

    def __str__(self) -> str:
        return f"{self.local}@{self.domain}" if self.domain else self.local

    @property
    def key(self) -> str:
        return f"{self.local.lower()}@{normalize_domain(self.domain)}"


def normalize_domain(domain: str) -> str:
    """Lowercase, convert labels to IDNA A-labels and drop a trailing dot.

    Address literals such as ``[192.0.2.1]`` are only lowercased.
    """
    domain = domain.lower()
    if domain.startswith("["):
        if not domain.endswith("]") or len(domain) < 3:
            raise AddressError("malformed address literal")
        return domain
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain:
        return ""
    try:
        labels = [label.encode("idna").decode("ascii") for label in domain.split(".")]
    except UnicodeError as exc:
        raise AddressError("invalid domain label") from exc
    result = ".".join(labels)
    if any(not label for label in labels) or len(result) > _MAX_DOMAIN:
        raise AddressError("invalid domain")
    return result


def split_path(text: str) -> tuple[str, str]:
    """Split ``<path>rest`` into ``("<path>", "rest")``.

    The closing ``>`` is the first one outside a quoted string.
    Raises AddressError if ``text`` does not start with ``<`` or has no closing ``>``.
    """
    if not text.startswith("<"):
        raise AddressError("path must start with '<'")
    quoted = False
    i = 1
    while i < len(text):
        ch = text[i]
        if quoted and ch == "\\":
            i += 1
        elif ch == '"':
            quoted = not quoted
        elif ch == ">" and not quoted:
            return text[: i + 1], text[i + 1:]
        i += 1
    raise AddressError("unbalanced angle brackets")


def _split_at_sign(inner: str) -> tuple[str, str] | None:
    """Split at the ``@`` outside quotes; None if there is none.

    A second unquoted ``@`` raises ``AtSignInLocalPart``: ``a@remote@local`` is routing
    syntax, and splitting at either sign would let one side decide the relay check and the
    other side the delivery.
    """
    quoted = False
    at = -1
    i = 0
    while i < len(inner):
        ch = inner[i]
        if quoted and ch == "\\":
            i += 1
        elif ch == '"':
            quoted = not quoted
        elif ch == "@" and not quoted:
            if at >= 0:
                raise AtSignInLocalPart("unquoted '@' in the local part")
            at = i
        i += 1
    if quoted:
        raise AddressError("unterminated quoted string")
    return None if at < 0 else (inner[:at], inner[at + 1:])


def _check_local(local: str) -> None:
    if not local:
        raise AddressError("empty local part")
    if local.startswith('"'):
        i = 1
        while i < len(local):
            if local[i] == "\\":
                i += 1
            elif local[i] == '"':
                break
            i += 1
        if i != len(local) - 1:
            raise AddressError("malformed quoted local part")
        body = local[1:-1]
        if any(ord(c) < 32 and c != "\t" or c in "\r\n\0" for c in body):
            raise AddressError("control character in local part")
        return
    if any(c.isspace() or ord(c) < 32 or c in '<>"' for c in local):
        raise AddressError("invalid character in local part")


def _strip_source_route(inner: str) -> str:
    if not inner.startswith("@"):
        return inner
    colon = inner.find(":")
    if colon < 0:
        raise AddressError("source route without ':'")
    return inner[colon + 1:]


def parse_path(text: str) -> Address | None:
    """Parse ``<…>``. Returns None for the null path ``<>``.

    A source route is dropped, quoted local parts and UTF-8 are accepted, and
    ``<postmaster>`` without a domain is allowed (stored as ``postmaster``).
    """
    text = text.strip()
    if len(text) < 2 or text[0] != "<" or text[-1] != ">":
        raise AddressError("path must be enclosed in angle brackets")
    path, rest = split_path(text)
    if rest:
        raise AddressError("unbalanced angle brackets")
    inner = path[1:-1]
    if not inner:
        return None
    inner = _strip_source_route(inner)
    parts = _split_at_sign(inner)
    if parts is None:
        if inner.lower() == "postmaster":
            return Address("postmaster", "")
        raise AddressError("missing domain")
    local, domain = parts
    _check_local(local)
    if not domain:
        raise AddressError("missing domain")
    if domain.startswith("["):
        bad = any(c.isspace() or ord(c) < 32 or c in '<>@"' for c in domain)
    else:
        bad = any(c in _BAD_DOMAIN_CHARS or ord(c) < 32 for c in domain)
    if bad:
        raise AddressError("invalid domain")
    if not normalize_domain(domain):
        raise AddressError("empty domain")
    return Address(local, domain)
