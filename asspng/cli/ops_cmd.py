# SPDX-License-Identifier: GPL-3.0-or-later
"""``assp-ng db | domain | pb | debug | status | notify`` (spec 5.5, 5.8, 8.6, 8.8, 8.11).

Exit codes: 0 success, 1 operational failure, 2 usage or configuration error. No path prints
the database URL, a password or a webhook path: messages are fixed texts or exception type
names.

``notify``, ``status`` and ``debug`` must work while the configuration is broken (ruling R60):
the proxy keeps running on its last good configuration, and a failed service must still be
able to alert. They read only the settings they need from ``assp-ng.toml``, leniently.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import socket
import stat
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from ipaddress import ip_address
from pathlib import Path
from typing import TypeVar

from asspng.cli.config_cmd import CliError, Deps, _etc
from asspng.checks.penalty_box import PenaltyBox, PenaltyStatus
from asspng.config.errors import ConfigError
from asspng.config.loader import load_config, read_system_lenient
from asspng.config.model import ConfigSnapshot
from asspng.config.registry import parse_duration
from asspng.db.migrate import current_revision
from asspng.db.repository import DomainExistsError
from asspng.log.debug import RuleKind
from asspng.net.ipnet import network_key, parse_ip
from asspng.service.alerts import event_name
from asspng.smtp.address import AddressError, normalize_domain
from asspng.state.base import StateError, StateStore

_T = TypeVar("_T")
SOCKET_HINT = "run as root or a member of the assp-ng group"
_KINDS = tuple(k.value for k in RuleKind if k is not RuleKind.ALL)
_REDIS_DOWN = ("Redis is unreachable. The penalty box lives in Redis; the in-memory state of "
               "a DEGRADED proxy cannot be reached from the CLI.")


# --- helpers -----------------------------------------------------------------------------

def _config(args: argparse.Namespace) -> ConfigSnapshot:
    try:
        return load_config(_etc(args))
    except ConfigError:
        raise CliError(2, "the configuration is invalid; run 'assp-ng config check'") from None


def _text(config: ConfigSnapshot, key: str) -> str:
    return str(config.get(key))


def _actor(deps: Deps) -> str:
    return f"{deps.actor()} (cli)"


def _warn(text: str) -> None:
    print(f"warning: {text}", file=sys.stderr)


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    widths = [max(len(str(c)) for c in col) for col in zip(headers, *rows, strict=False)]
    for row in (headers, *rows):
        print("  ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip())


def _duration(text: str) -> int:
    try:
        return parse_duration(text)
    except ValueError as exc:
        raise CliError(2, str(exc)) from None


def _fmt_remaining(seconds: float) -> str:
    left = max(0, int(seconds))
    parts = []
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if left >= size:
            parts.append(f"{left // size}{suffix}")
            left %= size
    return " ".join(parts + ([f"{left}s"] if left or not parts else []))


def _audit(deps: Deps, config: ConfigSnapshot, action: str, target: str,
           details: dict[str, object]) -> None:
    url = _text(config, "database.url")
    if not url:
        _warn("no database is configured: the audit log entry was not written")
        return
    try:
        deps.audit(url, instance=_text(config, "instance"), actor=_actor(deps),
                   action=action, target=target, details=details)
    except Exception as exc:  # the change stays; the error text could quote the URL
        _warn(f"the audit log entry was not written ({type(exc).__name__})")


# --- db ----------------------------------------------------------------------------------

def cmd_db_upgrade(args: argparse.Namespace, deps: Deps) -> int:
    url = _text(_config(args), "database.url")
    if not url:
        raise CliError(2, "no database is configured (database.url)")
    try:
        deps.upgrade(url)
        revision = current_revision(url)
    except Exception as exc:
        raise CliError(1, f"the schema upgrade failed ({type(exc).__name__})") from None
    print(f"schema at revision {revision}")
    return 0


# --- domain ------------------------------------------------------------------------------

def _db_call(call: Callable[[], _T]) -> _T:
    try:
        return call()
    except DomainExistsError as exc:
        raise CliError(1, str(exc)) from None
    except CliError:
        raise
    except Exception as exc:
        raise CliError(1, f"the database operation failed ({type(exc).__name__})") from None


def _publish_domains_changed(deps: Deps, config: ConfigSnapshot) -> None:
    async def publish() -> None:
        store = deps.store_factory(_text(config, "redis.url"), _text(config, "redis.key_prefix"),
                                   int(str(config.get("redis.op_timeout_ms"))) / 1000)
        try:
            await store.publish("events", "domains-changed")
        finally:
            close = getattr(store, "close", None)
            if close is not None:
                await close()

    try:
        asyncio.run(publish())
    except Exception as exc:
        _warn(f"the change is saved but the proxy was not notified ({type(exc).__name__}); "
              "it picks the change up at its next periodic refresh")


def _check_domain(text: str) -> None:
    """Reject what normalize_domain lets through (empty, blanks, bad address literal)."""
    try:
        name = normalize_domain(text)
        if name.startswith("["):
            ip_address(name[1:-1].removeprefix("ipv6:"))
    except (AddressError, ValueError):
        raise CliError(2, "invalid domain") from None
    if not name or any(c.isspace() or ord(c) < 32 for c in name):
        raise CliError(2, "invalid domain")


def cmd_domain_add(args: argparse.Namespace, deps: Deps) -> int:
    config = _config(args)
    _check_domain(args.domain)
    repo = deps.repo_factory(*_repo_args(config))
    try:
        _db_call(lambda: repo.add(args.domain, include_subdomains=args.subdomains,
                                  note=args.note, actor=_actor(deps)))
    finally:
        repo.close()
    _publish_domains_changed(deps, config)
    print(f"domain {args.domain} added")
    return 0


def cmd_domain_remove(args: argparse.Namespace, deps: Deps) -> int:
    config = _config(args)
    _check_domain(args.domain)
    repo = deps.repo_factory(*_repo_args(config))
    try:
        removed = _db_call(lambda: repo.remove(args.domain, actor=_actor(deps)))
    finally:
        repo.close()
    if not removed:
        raise CliError(1, f"domain {args.domain} not found")
    _publish_domains_changed(deps, config)
    print(f"domain {args.domain} removed")
    return 0


def cmd_domain_list(args: argparse.Namespace, deps: Deps) -> int:
    config = _config(args)
    repo = deps.repo_factory(*_repo_args(config))
    try:
        entries = _db_call(repo.list)
    finally:
        repo.close()
    _table(("domain", "include_subdomains", "enabled", "note"),
           [(e.domain, str(e.include_subdomains).lower(), str(e.enabled).lower(), "")
            for e in entries])
    return 0


def _repo_args(config: ConfigSnapshot) -> tuple[str, str]:
    url = _text(config, "database.url")
    if not url:
        raise CliError(2, "no database is configured (database.url)")
    return url, _text(config, "instance")


# --- penalty box -------------------------------------------------------------------------

def _net(args: argparse.Namespace, config: ConfigSnapshot) -> str:
    try:
        addr = parse_ip(args.ip)
    except ValueError:
        raise CliError(2, "invalid IP address") from None
    return network_key(addr, int(str(config.get("network.ipv4_prefix"))),
                       int(str(config.get("network.ipv6_prefix"))))


def _run_pb(deps: Deps, config: ConfigSnapshot,
            work: Callable[[PenaltyBox, StateStore], Awaitable[_T]]) -> _T:
    async def go() -> _T:
        store = deps.store_factory(_text(config, "redis.url"), _text(config, "redis.key_prefix"),
                                   int(str(config.get("redis.op_timeout_ms"))) / 1000)
        # Management operations never score, so the scoring parameters are placeholders.
        box = PenaltyBox(store, threshold=1, score_cap=1, score_ttl_s=1, ladder_s=(1,),
                         history_s=1, clock=time.time)
        try:
            return await work(box, store)
        finally:
            close = getattr(store, "close", None)
            if close is not None:
                await close()

    try:
        return asyncio.run(go())
    except (StateError, OSError):
        raise CliError(1, _REDIS_DOWN) from None


def _status_lines(st: PenaltyStatus) -> list[tuple[str, str]]:
    now = time.time()
    blocked = ("no" if st.blocked_until is None
               else f"yes, {_fmt_remaining(st.blocked_until - now)} left (level {st.level})")
    return [("network", st.net), ("blocked", blocked), ("score", str(st.score)),
            ("hits", str(st.hits)), ("reason", st.reason), ("history", str(st.history))]


def cmd_pb_show(args: argparse.Namespace, deps: Deps) -> int:
    config = _config(args)
    net = _net(args, config)
    status = _run_pb(deps, config, lambda box, store: box.status(net))
    for key, value in _status_lines(status):
        print(f"{key:<8} {value}")
    return 0


def cmd_pb_remove(args: argparse.Namespace, deps: Deps) -> int:
    config = _config(args)
    net = _net(args, config)
    _run_pb(deps, config, lambda box, store: box.remove(net, forget=args.forget))
    _audit(deps, config, "pb.remove", net, {"forget": args.forget})
    print(f"{net} removed from the penalty box" + (" (history forgotten)" if args.forget else ""))
    return 0


def cmd_pb_block(args: argparse.Namespace, deps: Deps) -> int:
    config = _config(args)
    net = _net(args, config)
    seconds = _duration(args.duration)
    if seconds <= 0:
        raise CliError(2, "the duration must be positive")
    start = time.time()
    until = _run_pb(deps, config, lambda box, store: box.block(net, seconds, args.reason))
    _audit(deps, config, "pb.block", net, {"duration_s": seconds, "reason": args.reason})
    if until > start + seconds + 1:  # a longer block was in force and is kept
        print(f"{net} is already blocked for longer ({_fmt_remaining(until - time.time())} "
              "left); the block is unchanged")
    else:
        print(f"{net} blocked for {_fmt_remaining(seconds)}")
    return 0


def cmd_pb_list(args: argparse.Namespace, deps: Deps) -> int:
    config = _config(args)

    async def work(box: PenaltyBox, store: StateStore) -> list[tuple[PenaltyStatus, int | None]]:
        rows = []
        for st in await box.list():
            ttl = None if st.blocked_until is not None else await store.ttl("pb:" + st.net)
            rows.append((st, ttl))
        return rows

    rows = _run_pb(deps, config, work)
    now = time.time()
    blocked = [(st.net, _fmt_remaining((st.blocked_until or now) - now), str(st.level), st.reason)
               for st, _ in rows if st.blocked_until is not None]
    scored = [(st.net, str(st.score), str(st.hits), "-" if ttl is None else _fmt_remaining(ttl))
              for st, ttl in rows if st.blocked_until is None and st.score > 0]
    print("blocked networks")
    _table(("network", "remaining", "level", "reason"), blocked)
    print("\nscored networks")
    _table(("network", "score", "hits", "expires in"), scored)
    return 0


# --- debug, status -----------------------------------------------------------------------

def _control(args: argparse.Namespace, deps: Deps, cmd: str,
             payload: dict[str, object]) -> object:
    run_dir = read_system_lenient(_etc(args), ("paths.run",))["paths.run"]
    path = Path(str(run_dir)) / "control.sock"

    async def request() -> object:
        return await deps.control(path, cmd, payload)

    try:
        return asyncio.run(request())
    except RuntimeError as exc:  # the server's own refusal
        raise CliError(1, str(exc)) from None
    except (OSError, TimeoutError) as exc:
        raise CliError(1, f"cannot use the control socket {path} ({type(exc).__name__}); "
                          f"{SOCKET_HINT}") from None


def _parse_target(text: str) -> tuple[str, str]:
    if text == "all":
        return "all", ""
    kind, sep, value = text.partition(":")
    if not sep or kind not in _KINDS or not value.strip():
        raise CliError(2, f"invalid target {text!r}: use all or <kind>:<value> with kind one "
                          f"of {', '.join(_KINDS)}")
    return kind, value.strip()


def _expires(rule: dict[str, object]) -> str:
    return _fmt_remaining(float(str(rule.get("expires_at", 0))) - time.time())


def cmd_debug_on(args: argparse.Namespace, deps: Deps) -> int:
    kind, value = _parse_target(args.target)
    seconds = None if args.duration is None else _duration(args.duration)
    result = _control(args, deps, "debug.on", {"kind": kind, "value": value,
                                               "duration_s": seconds, "headers": args.headers})
    rule = result if isinstance(result, dict) else {}
    print(f"debug rule {rule.get('id', '?')} on for {kind}{':' + value if value else ''}, "
          f"expires in {_expires(rule)}")
    return 0


def cmd_debug_off(args: argparse.Namespace, deps: Deps) -> int:
    if args.all == (args.id is not None):
        raise CliError(2, "give a rule id or --all")
    result = _control(args, deps, "debug.off", {"all": True} if args.all else {"id": args.id})
    removed = result.get("removed", 0) if isinstance(result, dict) else 0
    print(f"{removed} debug rule(s) switched off")
    return 0


def cmd_debug_list(args: argparse.Namespace, deps: Deps) -> int:
    result = _control(args, deps, "debug.list", {})
    rules = [r for r in result if isinstance(r, dict)] if isinstance(result, list) else []
    _table(("id", "kind", "value", "expires in", "headers"),
           [(str(r.get("id")), str(r.get("kind")), str(r.get("value")), _expires(r),
             str(r.get("headers")).lower()) for r in rules])
    return 0


def cmd_status(args: argparse.Namespace, deps: Deps) -> int:
    result = _control(args, deps, "status", {})
    if not isinstance(result, dict):
        raise CliError(1, "the proxy returned an unexpected status reply")

    def get(key: str) -> object:
        return result.get(key, "?")

    domains = result.get("domains")
    backends = result.get("backends")
    certs = result.get("certificates")
    counters = result.get("counters")
    rows: list[tuple[str, str]] = [
        ("status", str(get("status"))), ("mode", str(get("mode"))),
        ("redis", str(get("redis"))), ("db", str(get("db"))),
        ("domains", (f"{domains.get('count')} (source {domains.get('source')})"
                     if isinstance(domains, dict) else "?")),
        ("backends", (", ".join(f"{k}={v}" for k, v in backends.items()) or "none")
         if isinstance(backends, dict) else "?"),
        ("sessions", str(get("sessions"))), ("rss_mb", str(get("rss_mb"))),
        ("uptime", _fmt_remaining(int(str(result.get("uptime_s", 0))))),
        ("debug_rules", str(get("debug_rules"))),
        ("certificates", (", ".join(f"{k}: {v.get('days_left')} days"
                                    for k, v in certs.items() if isinstance(v, dict)) or "none")
         if isinstance(certs, dict) else "?"),
    ]
    width = max(len(k) for k, _ in rows)
    for key, value in rows:
        print(f"{key:<{width}}  {value}")
    if isinstance(counters, dict):
        print(f"{'counters':<{width}}  " + ("" if counters else "none"))
        for name, count in sorted(counters.items()):
            print(f"{'':<{width}}    {name}: {count}")
    return 0


# --- notify ------------------------------------------------------------------------------

_NOTIFY_KEYS = ("instance", "hostname", "alerts.email", "alerts.webhook", "alerts.smtp_server",
                "alerts.min_interval")


def _stamp_dir(deps: Deps) -> Path:
    """The rate-limit directory, created 0700 if missing. Refused (``CliError``) when it is a
    symlink, not a directory or not owned by the effective user: someone else could then
    suppress alerts or make this command write elsewhere."""
    path = deps.notify_stamp_dir
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise CliError(1, f"cannot create the rate-limit directory {path} "
                          f"({exc.strerror or type(exc).__name__}); use --force") from None
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != deps.geteuid():
        raise CliError(1, f"refusing the rate-limit directory {path}: it must be a directory "
                          "(not a symlink) owned by the current user; use --force")
    return path


def _rate_limited(deps: Deps, event: str, interval_s: int) -> bool:
    """Whether ``event`` was sent less than ``interval_s`` ago; otherwise stamp it now. An
    attempt counts even if delivery fails, like the proxy's own alerts."""
    stamp = _stamp_dir(deps) / f"{event_name(event)}.stamp"
    try:
        st = os.lstat(stamp)
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISREG(st.st_mode) and time.time() - st.st_mtime < interval_s:
            return True
    fd = os.open(stamp, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.utime(fd)
    finally:
        os.close(fd)
    return False


def cmd_notify(args: argparse.Namespace, deps: Deps) -> int:
    config = read_system_lenient(_etc(args), _NOTIFY_KEYS)

    def text(key: str) -> str:
        return str(config[key])
    channels = [name for name, key in (("email", "alerts.email"), ("webhook", "alerts.webhook"))
                if text(key).strip()]
    if not channels:
        raise CliError(1, "no alert channel is configured (alerts.email, alerts.webhook)")
    if not args.force and _rate_limited(deps, args.event, int(str(config["alerts.min_interval"]))):
        print("suppressed (rate limit)")
        return 0
    hostname = text("hostname") or socket.getfqdn()
    alerter = deps.alerter_factory(
        email=text("alerts.email"), webhook=text("alerts.webhook"),
        smtp_server=text("alerts.smtp_server"), min_interval_s=0, clock=time.time,
        instance=text("instance") or hostname, sender=f"assp-ng@{hostname}")
    if not asyncio.run(alerter.notify(args.event, args.message)):
        raise CliError(1, f"all configured channels failed ({', '.join(channels)})")
    print("alert delivered")
    return 0


# --- parser ------------------------------------------------------------------------------

def add_parser(subparsers: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    db = subparsers.add_parser("db", help="database schema")
    sub = db.add_subparsers(dest="db_command", required=True, metavar="COMMAND")
    p = sub.add_parser("upgrade", help="upgrade the database schema to the latest revision")
    p.set_defaults(func=cmd_db_upgrade)

    domain = subparsers.add_parser("domain", help="manage local domains")
    sub = domain.add_subparsers(dest="domain_command", required=True, metavar="COMMAND")
    p = sub.add_parser("add", help="add a local domain")
    p.add_argument("domain")
    p.add_argument("--subdomains", action="store_true", help="include all subdomains")
    p.add_argument("--note", default=None)
    p.set_defaults(func=cmd_domain_add)
    p = sub.add_parser("remove", help="remove a local domain")
    p.add_argument("domain")
    p.set_defaults(func=cmd_domain_remove)
    p = sub.add_parser("list", help="list local domains")
    p.set_defaults(func=cmd_domain_list)

    pb = subparsers.add_parser("pb", help="penalty box")
    sub = pb.add_subparsers(dest="pb_command", required=True, metavar="COMMAND")
    p = sub.add_parser("list", help="list blocked and scored networks")
    p.set_defaults(func=cmd_pb_list)
    p = sub.add_parser("show", help="show the state of one IP's network")
    p.add_argument("ip")
    p.set_defaults(func=cmd_pb_show)
    p = sub.add_parser("remove", help="release a network and clear its score")
    p.add_argument("ip")
    p.add_argument("--forget", action="store_true", help="also forget the block history")
    p.set_defaults(func=cmd_pb_remove)
    p = sub.add_parser("block", help="block a network manually")
    p.add_argument("ip")
    p.add_argument("--for", dest="duration", required=True, metavar="DURATION",
                   help="for example 30m, 12h, 7d")
    p.add_argument("--reason", default="manual")
    p.set_defaults(func=cmd_pb_block)

    debug = subparsers.add_parser("debug", help="runtime debug switch")
    sub = debug.add_subparsers(dest="debug_command", required=True, metavar="COMMAND")
    p = sub.add_parser("on", help="switch debug logging on for a target")
    p.add_argument("target", metavar="all|KIND:VALUE",
                   help=f"all, or {' | '.join(_KINDS)} followed by :value")
    p.add_argument("--for", dest="duration", default=None, metavar="DURATION")
    p.add_argument("--headers", action="store_true", help="also log message headers")
    p.set_defaults(func=cmd_debug_on)
    p = sub.add_parser("off", help="switch a debug rule (or all of them) off")
    p.add_argument("id", nargs="?")
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_debug_off)
    p = sub.add_parser("list", help="list active debug rules")
    p.set_defaults(func=cmd_debug_list)

    p = subparsers.add_parser("status", help="show the running proxy's status")
    p.set_defaults(func=cmd_status)

    p = subparsers.add_parser(
        "notify", help="send an alert (each event at most once per alerts.min_interval)")
    p.add_argument("--event", required=True)
    p.add_argument("--message", required=True)
    p.add_argument("--force", action="store_true", help="send even within the rate limit")
    p.set_defaults(func=cmd_notify)
