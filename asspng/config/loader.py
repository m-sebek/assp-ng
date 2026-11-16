# SPDX-License-Identifier: GPL-3.0-or-later
"""Layered configuration loader (spec 7.1-7.4).

Reads ``assp-ng.toml``, ``default.toml``, ``domain.d/*.toml`` and ``user.d/*.toml``,
validates them against the settings registry, collects every problem and raises a
single ConfigError, or returns one immutable ConfigSnapshot.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import tomllib
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit
from typing import Protocol, TypeVar

from sqlalchemy.engine import make_url

from asspng.config.errors import ConfigError
from asspng.config.model import (
    CertificateConfig,
    ConfigSnapshot,
    ListenerConfig,
    ListenerKind,
)
from asspng.config.registry import Level, Registry
from asspng.config.settings import REGISTRY
from asspng.net.ipnet import NetworkSet, load_network_file
from asspng.smtp.address import AddressError, normalize_domain, parse_path


class _Named(Protocol):
    @property
    def name(self) -> str: ...


_T = TypeVar("_T", bound=_Named)
_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")
_ARRAYS = ("listener", "tls.certificate")
_LISTENER_FIELDS = frozenset({
    "name", "kind", "port", "ipv4", "ipv6", "bind4", "bind6", "backend", "xclient", "auth"})
_CERT_FIELDS = frozenset({"name", "hostnames", "cert", "key"})
_POLICY_LEVELS = (Level.RECIPIENT, Level.SENDER)


def _flatten(table: Mapping[str, object], prefix: str,
             values: dict[str, object], arrays: dict[str, list[dict[str, object]]],
             empty: list[str]) -> None:
    for key, value in table.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            if not value:
                empty.append(path)
            _flatten(value, f"{path}.", values, arrays, empty)
        elif isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            arrays[path] = value
        else:
            values[path] = value


def _read_toml(path: Path, errors: list[str]) -> dict[str, object] | None:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        errors.append(f"{path}: invalid TOML: {exc}")
    except UnicodeDecodeError:
        errors.append(f"{path}: not valid UTF-8")
    except OSError as exc:
        errors.append(f"{path}: cannot read: {exc.strerror or exc}")
    return None


def _load_values(path: Path, allowed: tuple[Level, ...], registry: Registry, errors: list[str]
                 ) -> tuple[dict[str, object], dict[str, list[dict[str, object]]] | None]:
    """Read one file, flatten it and coerce every key; problems go to ``errors``.

    The arrays are None when the file could not be read or parsed.
    """
    data = _read_toml(path, errors)
    if data is None:
        return {}, None
    raw: dict[str, object] = {}
    arrays: dict[str, list[dict[str, object]]] = {}
    empty: list[str] = []
    _flatten(data, "", raw, arrays, empty)
    system_file = Level.SYSTEM in allowed
    known_tables = {"tls"} if system_file else set()
    for name in empty:
        if name not in known_tables and not any(k.startswith(f"{name}.") for k in
                                                (s.key for s in registry.all())):
            errors.append(f"{path}: unknown setting table [{name}]")
    for name in arrays:
        if not system_file or name not in _ARRAYS:
            errors.append(f"{path}: array of tables [[{name}]] is not allowed here")
    arrays = {k: v for k, v in arrays.items() if system_file and k in _ARRAYS}
    values: dict[str, object] = {}
    for key, value in raw.items():
        if system_file and key in _ARRAYS:
            errors.append(f"{path}: {key} must be an array of tables ([[{key}]])")
            continue
        try:
            setting = registry.get(key)
        except KeyError:
            errors.append(f"{path}: unknown setting {key!r}")
            continue
        if setting.level not in allowed:
            where = "assp-ng.toml" if setting.level is Level.SYSTEM else "the policy files"
            errors.append(f"{path}: {key} is a {setting.level.value} setting and is only "
                          f"allowed in {where}")
            continue
        try:
            values[key] = registry.coerce(key, value)
        except ConfigError as exc:
            errors.append(f"{path}: {exc}")
    return values, arrays


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _database_url_problem(text: str) -> str | None:
    """Why ``database.url`` is unusable, or None. Never quotes the URL: it holds a password.

    A remote database (spec 3.4, ruling R66) needs TLS (an ``ssl*`` query parameter, such as
    pymysql's ``ssl_ca``) and a password; a loopback host or a Unix socket needs neither.
    """
    if not text:
        return None
    try:
        url = make_url(text)
    except Exception:  # ArgumentError or ValueError; their messages quote the URL
        return "is not a valid database URL (dialect+driver://user:password@host/database)"
    if not url.host or _is_loopback(url.host) or "unix_socket" in url.query:
        return None
    if not any(key.startswith("ssl") for key in url.query) or not url.password:
        return ("must use TLS (an ssl_* query parameter such as ssl_ca) and a password for a "
                "database that is not on a loopback address")
    return None


def _redis_url_problem(text: str) -> str | None:
    """Why ``redis.url`` is unusable, or None; never quotes the URL. A remote Redis (spec 3.4,
    ruling R66) needs ``rediss://`` (TLS) and a password; loopback and ``unix://`` do not."""
    try:
        parts = urlsplit(text)
        host, password = parts.hostname, parts.password
    except ValueError:
        return "is not a valid Redis URL"
    if parts.scheme == "unix" or not host or _is_loopback(host):
        return None
    if parts.scheme != "rediss" or not password:
        return ("must use rediss:// (TLS) with a password for a Redis that is not on a "
                "loopback address")
    return None


def _health_listen_problem(text: str) -> str | None:
    """Why ``health.listen`` is unusable, or None: a loopback host and a port (spec 8.4, 9)."""
    if text.startswith("["):
        host, sep, port = text[1:].partition("]:")
    else:
        host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isascii() or not port.isdigit() or int(port) > 65535:
        return "must look like host:port or [ipv6]:port with a port in 0..65535"
    if not _is_loopback(host):
        return "must use a loopback address (127.0.0.1, ::1 or localhost)"
    return None


# SYSTEM values checked beyond their type; the messages never quote the value.
_SYSTEM_CHECKS: dict[str, Callable[[str], str | None]] = {
    "database.url": _database_url_problem,
    "redis.url": _redis_url_problem,
    "health.listen": _health_listen_problem,
}


def _check_system_values(path: Path, values: Mapping[str, object], errors: list[str]) -> None:
    for key, check in _SYSTEM_CHECKS.items():
        value = values.get(key)
        problem = check(value) if isinstance(value, str) else None
        if problem is not None:
            errors.append(f"{path}: {key} {problem}")


def _split_backend(text: str) -> tuple[str, int]:
    if text.startswith("["):
        host, sep, port = text[1:].partition("]:")
    else:
        host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isascii() or not port.isdigit():
        raise ValueError(f"backend {text!r} must look like host:port or [ipv6]:port")
    number = int(port)
    if not 1 <= number <= 65535:
        raise ValueError(f"backend port {number} is out of range 1..65535")
    return host, number


def _field(entry: Mapping[str, object], key: str, kind: type, default: object = None) -> object:
    value = entry.get(key, default)
    if value is None:
        raise ValueError(f"{key} is required")
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise ValueError(f"{key} must be of type {kind.__name__}")
    return value


def _unknown(entry: Mapping[str, object], known: frozenset[str]) -> None:
    extra = sorted(set(entry) - known)
    if extra:
        raise ValueError(f"unknown field(s): {', '.join(extra)}")


def _listener(entry: Mapping[str, object], has_cert: bool) -> ListenerConfig:
    _unknown(entry, _LISTENER_FIELDS)
    name = str(_field(entry, "name", str))
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"name {name!r} must be non-empty and match [A-Za-z0-9_-]+")
    kind_text = str(_field(entry, "kind", str))
    try:
        kind = ListenerKind(kind_text)
    except ValueError:
        raise ValueError(f"kind {kind_text!r} is not one of smtp, submission, submissions") \
            from None
    port = _field(entry, "port", int)
    assert isinstance(port, int)
    if not 0 <= port <= 65535:
        raise ValueError(f"port {port} is out of range 0..65535")
    ipv4 = _field(entry, "ipv4", bool, True)
    ipv6 = _field(entry, "ipv6", bool, True)
    if not (ipv4 or ipv6):
        raise ValueError("at least one of ipv4 and ipv6 must be true")
    bind4 = str(_field(entry, "bind4", str, "0.0.0.0"))
    bind6 = str(_field(entry, "bind6", str, "::"))
    for key, text, version in (("bind4", bind4, 4), ("bind6", bind6, 6)):
        try:
            if ipaddress.ip_address(text).version != version:
                raise ValueError
        except ValueError:
            raise ValueError(f"{key} {text!r} must be an IPv{version} address literal") from None
    host, backend_port = _split_backend(str(_field(entry, "backend", str)))
    submission = kind is not ListenerKind.SMTP
    auth = _field(entry, "auth", bool, submission)
    if submission:
        if not auth:
            raise ValueError("auth = false is not allowed on a submission listener")
        if not has_cert:
            raise ValueError("a submission listener requires a configured [[tls.certificate]]")
        if not _is_loopback(host):
            raise ValueError(f"backend host {host!r} must be loopback for a submission listener")
    if auth and not _is_loopback(host):
        # Ruling R65: AUTH credentials cross the backend connection in plain text.
        raise ValueError(f"listener {name!r}: auth = true requires a loopback backend host "
                         "(127.0.0.1, ::1 or localhost)")
    return ListenerConfig(
        name=name, kind=kind, port=port, ipv4=bool(ipv4), ipv6=bool(ipv6),
        bind4=bind4, bind6=bind6,
        backend_host=host, backend_port=backend_port,
        xclient=bool(_field(entry, "xclient", bool, True)), auth=bool(auth))


def _certificate(entry: Mapping[str, object]) -> CertificateConfig:
    _unknown(entry, _CERT_FIELDS)
    name = str(_field(entry, "name", str))
    hostnames = _field(entry, "hostnames", list)
    assert isinstance(hostnames, list)
    if not hostnames or not all(isinstance(h, str) and h for h in hostnames):
        raise ValueError("hostnames must be a non-empty list of strings")
    paths: list[Path] = []
    for key in ("cert", "key"):
        path = Path(str(_field(entry, key, str)))
        if not path.is_absolute():
            raise ValueError(f"{key} must be an absolute path")
        paths.append(path)
    return CertificateConfig(name, tuple(hostnames), paths[0], paths[1])


def _build_table(path: Path, entries: list[dict[str, object]], what: str,
                 errors: list[str], build: Callable[[dict[str, object]], _T]) -> list[_T]:
    result: list[_T] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        label = f"{path}: {what} #{index}"
        try:
            item = build(entry)
        except ValueError as exc:
            errors.append(f"{label}: {exc}")
            continue
        if item.name in seen:
            errors.append(f"{label}: duplicate name {item.name!r}")
            continue
        seen.add(item.name)
        result.append(item)
    return result


def _load_networks(path: Path, errors: list[str]) -> NetworkSet:
    if not path.exists():
        return NetworkSet([])
    try:
        return NetworkSet(load_network_file(path))
    except ValueError as exc:
        text = str(exc)
        errors.append(text if text.startswith(f"{path}:") else f"{path}: {text}")
    except OSError as exc:
        errors.append(f"{path}: cannot read: {exc.strerror or exc}")
    return NetworkSet([])


def _policy_files(directory: Path, errors: list[str]) -> list[Path]:
    if not directory.is_dir():
        return []
    try:
        return sorted(p for p in directory.iterdir() if p.name.endswith(".toml") and p.is_file())
    except OSError as exc:
        errors.append(f"{directory}: cannot read: {exc.strerror or exc}")
        return []


def _stem_ok(path: Path, kind: str) -> str | None:
    """Return the layer key for a domain.d / user.d file, or None when the name is wrong."""
    stem = path.name[:-len(".toml")]
    try:
        key = normalize_domain(stem) if kind == "domain" else _user_key(stem)
    except AddressError:
        return None
    return stem if key == stem and stem else None


def _user_key(stem: str) -> str:
    address = parse_path(f"<{stem}>")
    if address is None:
        raise AddressError("empty address")
    return address.key


def _check_warn(path: Path, registry: Registry, layers: list[Mapping[str, object]],
                errors: list[str]) -> None:
    """``layers`` is ordered most specific first; the registry default comes last."""
    def effective(key: str) -> float:
        for layer in layers:
            if key in layer:
                return float(layer[key])  # type: ignore[arg-type]
        return float(registry.coerce(key, registry.get(key).default))  # type: ignore[arg-type]

    warn, limit = effective("scoring.warn"), effective("scoring.limit")
    if warn > limit:
        errors.append(f"{path}: scoring.warn ({warn:g}) must not exceed scoring.limit ({limit:g})")


def _check_penalty_cap(path: Path, registry: Registry, values: Mapping[str, object],
                       errors: list[str]) -> None:
    """With the score cap below the threshold a network could never be blocked."""
    def effective(key: str) -> int:
        value = values[key] if key in values else registry.coerce(key, registry.get(key).default)
        return int(str(value))

    threshold, cap = effective("penalty_box.threshold"), effective("penalty_box.score_cap")
    if threshold > cap:
        errors.append(f"{path}: penalty_box.threshold ({threshold}) must not exceed "
                      f"penalty_box.score_cap ({cap})")


def _freeze(values: Mapping[str, object]) -> dict[str, object]:
    """Copy ``values`` turning every list into a tuple, so a snapshot cannot be mutated."""
    return {k: tuple(v) if isinstance(v, list) else v for k, v in values.items()}


def read_system_lenient(etc_dir: Path, keys: Iterable[str], registry: Registry = REGISTRY
                        ) -> dict[str, object]:
    """The SYSTEM settings ``keys`` from ``assp-ng.toml``, without validating anything else.

    For the commands that must work while the configuration is broken (ruling R60): the alert
    CLI and the control-socket clients. A missing or unreadable file, invalid TOML, a missing
    key or an invalid value gives the built-in default. Never raises ``ConfigError``.
    """
    try:
        with (etc_dir / "assp-ng.toml").open("rb") as handle:
            data: object = tomllib.load(handle)
    except (OSError, ValueError):  # TOMLDecodeError and UnicodeDecodeError are ValueErrors
        data = {}
    values: dict[str, object] = {}
    for key in keys:
        default = registry.coerce(key, registry.get(key).default)
        value = data
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        try:
            values[key] = default if value is None else registry.coerce(key, value)
        except ConfigError:
            values[key] = default
    return values


def load_config(etc_dir: Path, registry: Registry = REGISTRY) -> ConfigSnapshot:
    errors: list[str] = []
    system_path = etc_dir / "assp-ng.toml"
    default_path = etc_dir / "default.toml"

    system_values: dict[str, object] = {}
    arrays: dict[str, list[dict[str, object]]] = {}
    system_parsed = False
    if system_path.is_file():
        system_values, parsed = _load_values(system_path, (Level.SYSTEM,), registry, errors)
        _check_system_values(system_path, system_values, errors)
        _check_penalty_cap(system_path, registry, system_values, errors)
        system_parsed = parsed is not None
        arrays = parsed or {}
    else:
        errors.append(f"{system_path}: file is missing")

    default_layer: dict[str, object] = {}
    if default_path.is_file():
        default_layer, _ = _load_values(default_path, _POLICY_LEVELS, registry, errors)
    else:
        errors.append(f"{default_path}: file is missing; create it with 'assp-ng config init'")

    domains: dict[str, dict[str, object]] = {}
    domain_paths: dict[str, Path] = {}
    for path in _policy_files(etc_dir / "domain.d", errors):
        stem = _stem_ok(path, "domain")
        if stem is None:
            errors.append(f"{path}: file name must be the lowercase normalized domain "
                          "followed by .toml")
            continue
        domains[stem], _ = _load_values(path, _POLICY_LEVELS, registry, errors)
        domain_paths[stem] = path

    users: dict[str, dict[str, object]] = {}
    user_paths: dict[str, Path] = {}
    for path in _policy_files(etc_dir / "user.d", errors):
        stem = _stem_ok(path, "user")
        if stem is None:
            errors.append(f"{path}: file name must be the normalized mailbox address "
                          "(lowercase local part, normalized domain) followed by .toml")
            continue
        users[stem], _ = _load_values(path, _POLICY_LEVELS, registry, errors)
        user_paths[stem] = path

    _check_warn(default_path, registry, [default_layer], errors)
    for stem, layer in domains.items():
        _check_warn(domain_paths[stem], registry, [layer, default_layer], errors)
    for stem, layer in users.items():
        domain = domains.get(stem.rpartition("@")[2], {})
        _check_warn(user_paths[stem], registry, [layer, domain, default_layer], errors)

    has_cert = bool(arrays.get("tls.certificate"))
    certificates = tuple(_build_table(
        system_path, arrays.get("tls.certificate", []), "[[tls.certificate]]", errors,
        _certificate))
    listeners = tuple(_build_table(
        system_path, arrays.get("listener", []), "[[listener]]", errors,
        lambda entry: _listener(entry, has_cert)))
    if system_parsed and not arrays.get("listener"):
        errors.append(f"{system_path}: at least one [[listener]] is required")

    trusted = _load_networks(etc_dir / "trusted-networks.txt", errors)
    exempt = _load_networks(etc_dir / "exempt-networks.txt", errors)

    if errors:
        raise ConfigError(errors)

    system: dict[str, object] = {}
    for setting in registry.all():
        if setting.level is Level.SYSTEM:
            system[setting.key] = system_values[setting.key] if setting.key in system_values \
                else registry.coerce(setting.key, setting.default)
    if not system["hostname"]:
        system["hostname"] = socket.getfqdn()
    if not system["instance"]:
        system["instance"] = system["hostname"]

    system = _freeze(system)
    default_layer = _freeze(default_layer)
    domains = {k: _freeze(v) for k, v in domains.items()}
    users = {k: _freeze(v) for k, v in users.items()}
    return ConfigSnapshot(
        system=MappingProxyType(system),
        listeners=listeners,
        certificates=certificates,
        default_layer=MappingProxyType(default_layer),
        domain_layers=MappingProxyType(
            {k: MappingProxyType(v) for k, v in domains.items()}),
        user_layers=MappingProxyType({k: MappingProxyType(v) for k, v in users.items()}),
        trusted=trusted,
        exempt=exempt,
        etc_dir=etc_dir,
    )
