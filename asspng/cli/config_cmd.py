# SPDX-License-Identifier: GPL-3.0-or-later
"""``assp-ng config init | check | show | set | unset | doc`` (spec 7.6, 8.8).

A change is validated on a temporary copy of the configuration directory before the real
file is touched. No path prints the database URL or any password: messages carry fixed
texts or exception type names, and URL values are masked.
"""
from __future__ import annotations

import argparse
import getpass
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from urllib.parse import quote, urlsplit

from sqlalchemy.engine import make_url

from asspng.cli.probes import Probes, ProbeError
from asspng.proxy.backend import BackendError
from asspng.service.alerts import _safe_url
from asspng.state.base import StateError
from asspng.cli.scope import Scope, ScopeError, looks_like_scope, parse_scope
from asspng.config import editor
from asspng.config.docgen import render_default_toml, render_reference, toml_value
from asspng.config.errors import ConfigError
from asspng.config.loader import load_config
from asspng.config.model import ConfigSnapshot
from asspng.config.registry import Level, Setting
from asspng.config.settings import REGISTRY
from asspng.db.migrate import upgrade
from asspng.db.repository import DomainRepository, write_audit
from asspng.postfix.env import PostfixEnv
from asspng.service.alerts import Alerter
from asspng.service.control import control_request
from asspng.state.base import StateStore
from asspng.state.redis_store import RedisStore

DEFAULT_DIR = Path("/etc/assp-ng")
SERVICE = "assp-ng-proxy"
_POLICY = (Level.RECIPIENT, Level.SENDER)
_URL_KEYS = frozenset({"database.url", "redis.url"})
_SECRET_KEYS = frozenset({"database.url", "redis.url", "alerts.webhook"})
_SAFE_MESSAGES = (ProbeError, BackendError, StateError)


class CliError(Exception):
    """A failure to report as ``error: <message>`` with an exit code (1 operational, 2 usage)."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _run_command(cmd: Sequence[str]) -> int:
    try:
        return subprocess.run(list(cmd), check=False, timeout=30).returncode
    except (OSError, subprocess.SubprocessError):
        return 127


@dataclass
class Deps:
    """Everything with side effects outside the configuration directory, injectable."""

    probes: Probes = field(default_factory=Probes)
    runner: Callable[[Sequence[str]], int] = _run_command
    audit: Callable[..., None] = write_audit
    geteuid: Callable[[], int] = os.geteuid
    actor: Callable[[], str] = lambda: os.environ.get("SUDO_USER") or getpass.getuser()
    # operations commands (ops_cmd)
    upgrade: Callable[[str], None] = upgrade
    repo_factory: Callable[[str, str], DomainRepository] = DomainRepository
    store_factory: Callable[[str, str, float], StateStore] = RedisStore
    control: Callable[..., Awaitable[object]] = control_request
    alerter_factory: Callable[..., Alerter] = Alerter
    # Root-owned directory of the notify rate-limit stamps (systemd RuntimeDirectory=).
    notify_stamp_dir: Path = Path("/run/assp-ng-notify")
    # Postfix integration assistant (postfix_cmd)
    postfix: PostfixEnv = field(default_factory=PostfixEnv)


# --- helpers -----------------------------------------------------------------------------

def _etc(args: argparse.Namespace) -> Path:
    return Path(os.path.abspath(args.config_dir))


def _require_root(etc: Path, deps: Deps) -> None:
    if etc.resolve() == DEFAULT_DIR.resolve() and deps.geteuid() != 0:
        raise CliError(1, f"this command needs root: it writes to {DEFAULT_DIR}")


def _require_dir(etc: Path) -> None:
    if not etc.is_dir():
        raise CliError(1, f"configuration directory {etc} does not exist")


def _scope(text: str) -> Scope:
    try:
        return parse_scope(text)
    except ScopeError as exc:
        raise CliError(2, f"invalid scope: {exc}") from None


def _setting(key: str, scope: Scope) -> Setting:
    try:
        setting = REGISTRY.get(key)
    except KeyError:
        raise CliError(2, f"unknown setting {key!r}") from None
    system = setting.level is Level.SYSTEM
    if system != scope.system:
        where = ("assp-ng.toml (scope sys)" if system
                 else "the policy files (scope default, domain:<d> or user:<a>)")
        raise CliError(2, f"{key} is a {setting.level.value} setting and belongs in {where}")
    return setting


def _fmt_duration(seconds: int) -> str:
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{suffix}"
    return f"{seconds}s" if seconds else "0"


# Query parameters of database.url (pymysql) and redis.url (redis-py) whose values are shown.
# Both drivers also take secrets as query parameters (password, ssl_key_password,
# ssl_password, ...), so every parameter not listed here is shown as ***.
_SHOWN_QUERY_KEYS = frozenset({
    # pymysql through SQLAlchemy
    "charset", "connect_timeout", "read_timeout", "write_timeout", "unix_socket",
    "local_infile", "binary_prefix", "autocommit", "program_name",
    "ssl_ca", "ssl_capath", "ssl_cert", "ssl_key", "ssl_cipher", "ssl_check_hostname",
    "ssl_verify_cert", "ssl_verify_identity", "ssl_disabled",
    # redis-py
    "db", "protocol", "client_name", "decode_responses", "max_connections",
    "socket_timeout", "socket_connect_timeout", "socket_keepalive", "health_check_interval",
    "retry_on_timeout", "ssl_cert_reqs", "ssl_ca_certs", "ssl_ca_path", "ssl_certfile",
    "ssl_keyfile", "ssl_min_version",
})


def _mask_url(text: str) -> str:
    """The URL with its password and the values of all unlisted query parameters as ***."""
    if not text:
        return text
    try:
        url = make_url(text)
        base = url.set(query={}).render_as_string(hide_password=True)
    except Exception:  # the message of the parser quotes the URL
        return "***"
    pairs = []
    for key in sorted(url.query):
        raw = url.query[key]
        for value in (raw,) if isinstance(raw, str) else raw:
            shown = quote(value, safe="/:,") if key in _SHOWN_QUERY_KEYS else "***"
            pairs.append(f"{quote(key, safe='')}={shown}")
    return base + ("?" + "&".join(pairs) if pairs else "")


def _mask_webhook(text: str) -> str:
    """Only scheme://host[:port]; paths, queries and userinfo can carry secrets."""
    if not text:
        return text
    try:
        parts = urlsplit(text)
        if parts.scheme and parts.hostname:
            _ = parts.port
            return _safe_url(text)
    except ValueError:
        pass
    return "<invalid url>"


def format_value(setting: Setting, value: object) -> str:
    """Render an effective value for ``config show``; URLs are masked."""
    if setting.key in _URL_KEYS and isinstance(value, str):
        value = _mask_url(value)
    elif setting.key == "alerts.webhook" and isinstance(value, str):
        value = _mask_webhook(value)
    elif setting.kind == "duration" and isinstance(value, int):
        value = _fmt_duration(value)
    elif setting.kind == "list[duration]" and isinstance(value, (list, tuple)):
        value = [_fmt_duration(int(v)) for v in value]
    elif isinstance(value, tuple):
        value = list(value)
    return toml_value(value)


def _toml_value(setting: Setting, raw: str, coerced: object) -> object:
    """The value to write: durations keep the form the admin typed."""
    if setting.kind == "duration":
        return raw.strip()
    if setting.kind == "list[duration]":
        return [p.strip() for p in raw.split(",") if p.strip()]
    return coerced


def _load(etc: Path) -> ConfigSnapshot:
    try:
        return load_config(etc)
    except ConfigError as exc:
        raise CliError(1, "the configuration is invalid:\n  " + "\n  ".join(exc.errors)) from None


# --- init, doc ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace, deps: Deps) -> int:
    etc = _etc(args)
    _require_root(etc, deps)
    target = etc / "default.toml"
    if target.exists() and not args.force:
        raise CliError(1, f"{target} already exists; use --force to replace it "
                          "(the old content is kept in default.toml.bak)")
    with editor.locked(etc):
        if target.exists() and not args.force:
            raise CliError(1, f"{target} already exists; use --force to replace it")
        editor.write_text(target, render_default_toml(REGISTRY))
    print(f"wrote {target}")
    return 0


def cmd_doc(args: argparse.Namespace, deps: Deps) -> int:
    text = render_reference(REGISTRY)
    if args.output is None:
        sys.stdout.write(text)
    else:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    return 0


# --- check -------------------------------------------------------------------------------

def _describe(exc: Exception) -> str:
    name = type(exc).__name__
    return f"{name}: {exc}" if isinstance(exc, _SAFE_MESSAGES) and str(exc) else name


def cmd_check(args: argparse.Namespace, deps: Deps) -> int:
    failed = False

    def report(ok: bool, item: str, detail: str) -> None:
        nonlocal failed
        failed = failed or not ok
        print(f"{'OK  ' if ok else 'FAIL'} {item}: {detail}")

    def probe(item: str, call: Callable[[], str]) -> None:
        try:
            report(True, item, call())
        except Exception as exc:  # any failure is a FAIL line, never a traceback
            report(False, item, _describe(exc))

    try:
        snap = load_config(_etc(args))
    except ConfigError as exc:
        for error in exc.errors:
            report(False, "config", error)
        return 1
    report(True, "config", f"{len(snap.listeners)} listeners, "
                           f"{len(snap.certificates)} certificates")
    url = str(snap.get("database.url"))
    if url:
        probe("database", partial(deps.probes.database, url))
    else:
        report(True, "database", "not configured")
    redis_url, prefix = str(snap.get("redis.url")), str(snap.get("redis.key_prefix"))
    probe("redis", partial(deps.probes.redis, redis_url, prefix))
    connect_s = float(str(snap.get("timeouts.backend_connect")))
    banner_s = float(str(snap.get("timeouts.backend_banner")))
    for listener in snap.listeners:
        probe(f"backend {listener.name} ({listener.backend_host}:{listener.backend_port})",
              partial(deps.probes.backend, listener, connect_s, banner_s))
    for cert in snap.certificates:
        probe(f"certificate {cert.name}", partial(deps.probes.certificate, cert))
    return 1 if failed else 0


# --- show --------------------------------------------------------------------------------

def _layers(snap: ConfigSnapshot, scope: Scope) -> list[tuple[str, Mapping[str, object]]]:
    default = ("default", snap.default_layer)
    if scope.kind == "default":
        return [default]
    if scope.kind == "domain":
        return [("domain", snap.domain_layers.get(scope.name, {})), default]
    domain = scope.name.rpartition("@")[2]
    return [("user", snap.user_layers.get(scope.name, {})),
            ("domain", snap.domain_layers.get(domain, {})), default]


def _effective(setting: Setting, layers: list[tuple[str, Mapping[str, object]]]
               ) -> tuple[object, str]:
    for name, layer in layers:
        if setting.key in layer:
            return layer[setting.key], name
    return REGISTRY.coerce(setting.key, setting.default), "built-in"


def cmd_show(args: argparse.Namespace, deps: Deps) -> int:
    words: list[str] = args.words
    if len(words) > 2:
        raise CliError(2, "show takes at most a key and a scope")
    key: str | None = None
    scope_text: str | None = None
    if len(words) == 2:
        key, scope_text = words
    elif words and looks_like_scope(words[0]):
        scope_text = words[0]
    elif words:
        key = words[0]
    setting = None
    if key is not None:
        try:
            setting = REGISTRY.get(key)
        except KeyError:
            raise CliError(2, f"unknown setting {key!r}") from None
    if scope_text is None:
        scope_text = "sys" if setting is not None and setting.level is Level.SYSTEM \
            else "default"
    scope = _scope(scope_text)
    if setting is not None:
        _setting(setting.key, scope)
    snap = _load(_etc(args))
    if scope.system:
        in_file = editor.keys_in(scope.path(_etc(args)))
        rows = [(s, snap.get(s.key), "system" if s.key in in_file else "built-in")
                for s in REGISTRY.all() if s.level is Level.SYSTEM]
    else:
        layers = _layers(snap, scope)
        rows = [(s, *_effective(s, layers)) for s in REGISTRY.all() if s.level in _POLICY]
    for s, value, source in rows:
        if setting is None or s.key == setting.key:
            print(f"{s.key} = {format_value(s, value)}  ({source})")
    return 0


# --- set, unset --------------------------------------------------------------------------

def _validated_copy(etc: Path, target: Path, mutate: Callable[[Path], bool]
                    ) -> tuple[bool, ConfigSnapshot]:
    """Apply ``mutate`` to a temporary copy of ``etc`` and load the result."""
    if not etc.is_dir():
        raise CliError(1, f"configuration directory {etc} does not exist")
    with tempfile.TemporaryDirectory(prefix="assp-ng-config-") as tmp:
        copy = Path(tmp) / "etc"
        try:
            shutil.copytree(etc, copy, symlinks=False,
                            ignore=shutil.ignore_patterns("*.bak", editor.LOCK_NAME))
        except shutil.Error as exc:
            broken = [src for src, _, _ in exc.args[0]
                      if os.path.islink(src) and not os.path.exists(src)]
            if broken:
                raise CliError(2, "cannot validate: dangling symbolic link: "
                               + ", ".join(broken)) from None
            raise CliError(1, "cannot copy the configuration for validation: "
                           + ", ".join(src for src, _, _ in exc.args[0])) from None
        try:
            changed = mutate(copy / target.relative_to(etc))
            snap = load_config(copy)
        except ConfigError as exc:
            lines = [e.replace(str(copy), str(etc)) for e in exc.errors]
            raise CliError(2, "the change is invalid, nothing was written:\n  "
                           + "\n  ".join(lines)) from None
    return changed, snap


def _finish(etc: Path, deps: Deps, snap: ConfigSnapshot, action: str, scope: Scope, key: str,
            value: str | None) -> int:
    url = str(snap.get("database.url"))
    if url:
        details: dict[str, object] = {"key": key, "scope": scope.text}
        if value is not None:
            details["value"] = "***" if key in _SECRET_KEYS else value
        try:
            deps.audit(url, instance=str(snap.get("instance")), actor=deps.actor(),
                       action=action, target=f"{scope.text}:{key}", details=details)
        except Exception as exc:  # the change stays; never print the error text (URL)
            print(f"warning: the audit log entry was not written ({type(exc).__name__})",
                  file=sys.stderr)
    if etc.resolve() != DEFAULT_DIR.resolve():
        return 0  # only the system directory is read by the service
    if deps.runner(["systemctl", "is-active", "--quiet", SERVICE]) != 0:
        print(f"{SERVICE} is not running: no reload needed")
        return 0
    if deps.runner(["systemctl", "reload", SERVICE]) != 0:
        print(f"warning: the change is written but 'systemctl reload {SERVICE}' failed",
              file=sys.stderr)
        return 1
    print(f"reloaded {SERVICE}")
    return 0


def cmd_set(args: argparse.Namespace, deps: Deps) -> int:
    etc = _etc(args)
    scope = _scope(args.scope)
    setting = _setting(args.key, scope)
    try:
        coerced = REGISTRY.coerce(setting.key, args.value)
    except ConfigError as exc:
        raise CliError(2, exc.errors[0]) from None
    value = _toml_value(setting, args.value, coerced)
    _require_root(etc, deps)
    _require_dir(etc)
    target = scope.path(etc)

    def apply(path: Path) -> bool:
        editor.set_value(path, setting.key, value)
        return True

    with editor.locked(etc):
        _, snap = _validated_copy(etc, target, apply)
        editor.set_value(target, setting.key, value)
    print(f"set {setting.key} in {target}")
    return _finish(etc, deps, snap, "config.set", scope, setting.key,
                   format_value(setting, coerced))


def cmd_unset(args: argparse.Namespace, deps: Deps) -> int:
    etc = _etc(args)
    scope = _scope(args.scope)
    setting = _setting(args.key, scope)
    _require_root(etc, deps)
    _require_dir(etc)
    target = scope.path(etc)
    with editor.locked(etc):
        changed, snap = _validated_copy(
            etc, target, lambda path: editor.unset_value(path, setting.key))
        if changed:
            editor.unset_value(target, setting.key)
    if not changed:
        print(f"{setting.key} is not set in {target}")
        return 0
    print(f"unset {setting.key} in {target}")
    return _finish(etc, deps, snap, "config.unset", scope, setting.key, None)


# --- parser ------------------------------------------------------------------------------

def add_parser(subparsers: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    config = subparsers.add_parser("config", help="inspect and edit the configuration")
    sub = config.add_subparsers(dest="config_command", required=True, metavar="COMMAND")

    p = sub.add_parser("init", help="write a documented default.toml")
    p.add_argument("--force", action="store_true", help="replace an existing default.toml")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("check", help="validate the files, the database, Redis, backends "
                                     "and certificates")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("show", help="show effective values and where they come from")
    p.add_argument("words", nargs="*", metavar="[KEY] [SCOPE]",
                   help="a setting and/or sys | default | domain:<d> | user:<a>")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("set", help="set a value in one scope")
    p.add_argument("key")
    p.add_argument("value")
    p.add_argument("scope", nargs="?", default="default",
                   help="sys | default | domain:<d> | user:<a> (default: default)")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("unset", help="remove a value from one scope")
    p.add_argument("key")
    p.add_argument("scope", nargs="?", default="default",
                   help="sys | default | domain:<d> | user:<a> (default: default)")
    p.set_defaults(func=cmd_unset)

    p = sub.add_parser("doc", help="print the configuration reference as Markdown")
    p.add_argument("--output", metavar="PATH", help="write the reference to this file")
    p.set_defaults(func=cmd_doc)
