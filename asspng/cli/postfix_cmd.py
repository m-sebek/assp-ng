# SPDX-License-Identifier: GPL-3.0-or-later
"""``assp-ng postfix check | plan | apply | rollback`` (spec 8.10).

Exit codes: 0 success, 1 operational failure (including a performed rollback), 2 usage or
configuration error (no terminal without --yes, ISPConfig host, port conflict, bad config).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from asspng.cli.config_cmd import CliError, Deps, _etc
from asspng.config.errors import ConfigError
from asspng.config.loader import load_config
from asspng.config.model import ListenerConfig, ListenerKind
from asspng.net.ipnet import load_network_file
from asspng.postfix.apply import (
    ISPCONFIG_MESSAGE,
    Backend,
    Target,
    apply_plan,
    check_trusted_dir,
    rollback,
)
from asspng.postfix.inspect import (FEATURES, PostfixError, PostfixRefused, PostfixState, detect,
                                    read_state, trusted_missing_from_mynetworks)
from asspng.postfix.plan import Plan, build_plan, render_diff

_DEFAULT_BACKENDS: list[Backend] = [("127.0.0.1", 10125, False), ("127.0.0.1", 10587, True)]
_DROP_HELP = ("allow dropping filter/milter overrides of a disabled service although a DKIM "
              "signer is active")
_DEFAULT_PORTS = frozenset({25, 587, 465})
_BACKUP_NAME = re.compile(r"postfix-\d{8}T\d{12}Z")  # what apply_plan creates


def _warn(text: str) -> None:
    print(f"warning: {text}", file=sys.stderr)


def _state(deps: Deps) -> PostfixState:
    env = deps.postfix
    try:
        state = read_state(env.run, env.etc, ispconfig_dir=env.ispconfig_dir,
                           rspamd_dir=env.rspamd_dir, amavis_dir=env.amavis_dir)
    except PostfixError as exc:
        raise CliError(1, str(exc)) from None
    if state.ispconfig:
        _warn(ISPCONFIG_MESSAGE)
    return state


def _target(listener: ListenerConfig) -> Target:
    if listener.ipv4:
        host = listener.bind4 if listener.bind4 != "0.0.0.0" else "127.0.0.1"
    else:
        host = listener.bind6 if listener.bind6 != "::" else "::1"
    return Target(host, listener.port, listener.kind is ListenerKind.SUBMISSIONS)


def _backends(args: argparse.Namespace, required: bool
              ) -> tuple[list[Target], list[Backend], frozenset[int]]:
    """The listeners to probe and the backends to prepare, from the ASSP-NG configuration."""
    try:
        listeners = load_config(_etc(args)).listeners
    except ConfigError:
        if required:
            raise CliError(2, "the ASSP-NG configuration is invalid or missing; "
                              "run 'assp-ng config check'") from None
        _warn("no valid ASSP-NG configuration: planning for the default backends "
              "127.0.0.1:10125 and 127.0.0.1:10587")
        return [], list(_DEFAULT_BACKENDS), _DEFAULT_PORTS
    backends: list[Backend] = []
    for listener in listeners:
        entry = (listener.backend_host, listener.backend_port, listener.auth)
        if entry not in backends:
            backends.append(entry)
    return ([_target(listener) for listener in listeners], backends,
            frozenset(listener.port for listener in listeners))


def _plan(state: PostfixState, backends: list[Backend], ports: frozenset[int], deps: Deps,
          drop_overrides: bool) -> Plan:
    try:
        return build_plan(state, detect(state, FEATURES), backends, listener_ports=ports,
                          today=deps.postfix.now().date(), drop_overrides=drop_overrides)
    except ValueError as exc:
        raise CliError(2, str(exc)) from None


def _show(plan: Plan, state: PostfixState) -> None:
    for note in plan.notes:
        print(f"note: {note}")
    diff = render_diff(state.master_text, plan.master_text_new)
    if diff:
        # master.cf may hold undecodable bytes (surrogates); never crash while printing them
        sys.stdout.write(diff.encode("utf-8", "surrogateescape").decode("utf-8", "replace"))


def _mynetworks_note(args: argparse.Namespace, state: PostfixState) -> str | None:
    """A note naming the trusted networks that Postfix's mynetworks lacks (ruling R67)."""
    path = _etc(args) / "trusted-networks.txt"
    if not path.is_file():
        return None
    try:
        trusted = load_network_file(path)
    except (OSError, ValueError):
        _warn(f"{path} is unreadable or invalid; run 'assp-ng config check'")
        return None
    # Without an explicit value Postfix uses the host's own addresses (mynetworks_style).
    mynetworks = state.main.get("mynetworks", "127.0.0.0/8 [::1]/128")
    missing, unchecked = trusted_missing_from_mynetworks(trusted, mynetworks)
    if not missing:
        return None
    note = ("trusted networks missing from Postfix mynetworks: "
            + ", ".join(str(net) for net in missing)
            + ". ASSP-NG passes the real client address to Postfix with XCLIENT, so Postfix "
            "relays for these networks without AUTH only if mynetworks lists them too")
    if unchecked:
        note += f" (not evaluated: {', '.join(unchecked)})"
    return note


def cmd_check(args: argparse.Namespace, deps: Deps) -> int:
    state = _state(deps)
    findings = detect(state, FEATURES)
    if not findings:
        print("nothing found that assp-ng replaces")
    for f in findings:
        status = "can disable" if f.can_disable else "keep for now"
        print(f"[{status}] {f.kind}: {f.description} (replaced by: {f.replaced_by})")
    note = _mynetworks_note(args, state)
    if note is not None:
        print(f"note: {note}")
    return 0


def cmd_plan(args: argparse.Namespace, deps: Deps) -> int:
    state = _state(deps)
    _targets, backends, ports = _backends(args, required=False)
    plan = _plan(state, backends, ports, deps, args.drop_overrides)
    _show(plan, state)
    return 0


def cmd_apply(args: argparse.Namespace, deps: Deps) -> int:
    env = deps.postfix
    state = _state(deps)
    if state.ispconfig:
        raise CliError(2, ISPCONFIG_MESSAGE)
    targets, backends, ports = _backends(args, required=True)
    plan = _plan(state, backends, ports, deps, args.drop_overrides)
    _show(plan, state)
    if plan.master_text_new == state.master_text:
        print("nothing to do")
        return 0
    if not args.yes:
        if not env.isatty():
            raise CliError(2, "confirmation needed but there is no terminal: use --yes")
        if not env.confirm("Apply this plan? Postfix will be restarted and ASSP-NG started."):
            print("aborted; nothing was changed")
            return 1
    try:
        backup = apply_plan(plan, state, backup_root=env.backup_root, run=env.run,
                            verify=env.verify_factory(targets, backends), etc=env.etc,
                            now=env.now, probe=env.probe)
    except PostfixRefused as exc:
        raise CliError(2, str(exc)) from None
    except PostfixError as exc:
        raise CliError(1, str(exc)) from None
    print(f"applied; the previous configuration is in {backup}")
    return 0


def _newest(root: Path) -> Path:
    if not os.path.lexists(root):
        raise CliError(1, f"no backup found under {root}")
    try:
        check_trusted_dir(root)  # ruling R58: root restores from here
    except PostfixError as exc:
        raise CliError(1, str(exc)) from None
    found = sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink()
                   and _BACKUP_NAME.fullmatch(p.name) and (p / "master.cf").is_file())
    if not found:
        raise CliError(1, f"no backup found under {root}")
    return found[-1]


def cmd_rollback(args: argparse.Namespace, deps: Deps) -> int:
    env = deps.postfix
    backup = Path(args.backup) if args.backup else _newest(env.backup_root)
    try:
        note = rollback(backup, env.run, etc=env.etc, probe=env.probe)
    except PostfixError as exc:
        raise CliError(1, str(exc)) from None
    print(f"rolled back from {backup}")
    print(f"note: {note}")
    return 0


def add_parser(subparsers: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    postfix = subparsers.add_parser("postfix", help="Postfix integration assistant")
    sub = postfix.add_subparsers(dest="postfix_command", required=True, metavar="COMMAND")
    p = sub.add_parser("check", help="report what assp-ng can take over (read-only)")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("plan", help="show the master.cf changes as a diff (read-only)")
    p.add_argument("--drop-overrides", action="store_true", help=_DROP_HELP)
    p.set_defaults(func=cmd_plan)
    p = sub.add_parser("apply", help="back up, change master.cf, restart, verify")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.add_argument("--drop-overrides", action="store_true", help=_DROP_HELP)
    p.set_defaults(func=cmd_apply)
    p = sub.add_parser("rollback", help="restore a backup and restart Postfix")
    p.add_argument("--backup", metavar="DIR", default=None,
                   help="backup directory (default: the newest one)")
    p.set_defaults(func=cmd_rollback)
