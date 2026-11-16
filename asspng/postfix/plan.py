# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the ``master.cf`` change that moves Postfix behind ASSP-NG (spec 8.10).

The plan is pure text editing, byte-faithful (the text carries undecodable bytes as
surrogates and keeps the file's line endings): public listeners are commented out (never
deleted) and two internal ``smtpd`` services are appended. A ``master.cf`` that already carries
our services yields an empty plan.
"""
from __future__ import annotations

import datetime as dt
import difflib
import ipaddress
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field

from asspng.postfix.inspect import (DKIM_NOTE, MARKER_ADDED, MARKER_DISABLED, Finding,
                                    MasterService, PostfixState, is_public_listener,
                                    service_port, split_lines)

# Overrides whose loss changes how mail is filtered or signed.
_FILTER_KEYS = frozenset({"content_filter", "smtpd_milters", "non_smtpd_milters",
                          "milter_macro_daemon_name", "receive_override_options"})


@dataclass
class Plan:
    master_text_new: str
    notes: list[str] = field(default_factory=list)
    disabled: list[tuple[str, str]] = field(default_factory=list)  # (name, type)
    added: list[tuple[str, str]] = field(default_factory=list)


def _loopback(host: str) -> tuple[str, str]:
    """Return (service address, xclient host) for a loopback backend; refuse anything else."""
    if host == "localhost":
        return "127.0.0.1", "127.0.0.1"
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(bare)
    except ValueError:
        ip = None
    if ip is None or not ip.is_loopback:
        raise ValueError(f"backend host {host!r} must be a loopback IP address literal "
                         "(or localhost)")
    return ("[::1]", "[::1]") if ip.version == 6 else (str(ip), "127.0.0.1")


def _options(xhost: str, auth: bool) -> list[str]:
    if auth:
        return ["smtpd_sasl_auth_enable=yes", "smtpd_tls_auth_only=no",
                f"smtpd_authorized_xclient_hosts={xhost}",
                "smtpd_client_restrictions=permit_sasl_authenticated,reject"]
    return ["smtpd_sasl_auth_enable=no", f"smtpd_authorized_xclient_hosts={xhost}"]


def _chroot_column(state: PostfixState, public: list[MasterService]) -> str:
    lines = split_lines(state.master_text)
    for svc in [s for s in public if s.command == "smtpd"] + \
            [s for s in state.services if s.command == "smtpd"]:
        fields = lines[svc.line_start - 1].split()
        if len(fields) > 4:
            return fields[4]
    return "n"


def _is_ours(state: PostfixState, svc: MasterService) -> bool:
    lines = split_lines(state.master_text)
    return svc.line_start >= 2 and lines[svc.line_start - 2].startswith(MARKER_ADDED)


def _unique_backends(backends: Sequence[tuple[str, int, bool]]
                     ) -> list[tuple[str, str, int, bool]]:
    unique: list[tuple[str, str, int, bool]] = []
    for host, port, auth in backends:
        if not 0 < port < 65536:
            raise ValueError(f"backend port {port} is out of range")
        shost, xhost = _loopback(host)
        for h, _x, p, a in unique:
            if (h, p) == (shost, port):
                if a != auth:
                    raise ValueError(f"port {port} is used for both an authenticated and an "
                                     "unauthenticated backend")
                break
        else:
            unique.append((shost, xhost, port, auth))
    return unique


def build_plan(state: PostfixState, findings: Sequence[Finding],
               backends: Sequence[tuple[str, int, bool]], *,
               listener_ports: Collection[int],
               today: dt.date | None = None, drop_overrides: bool = False) -> Plan:
    """Return the new ``master.cf`` text; raise ``ValueError`` if it cannot be done safely.

    ``listener_ports`` are the ports of the configured ASSP-NG listeners: a public Postfix
    service is disabled only when one of them covers its port.
    """
    day = (today or dt.datetime.now(dt.timezone.utc).date()).isoformat()
    todo: list[tuple[str, str, int, bool]] = []
    by_name = {s.name: s for s in state.services}
    for shost, xhost, port, auth in _unique_backends(backends):
        name = f"{shost}:{port}"
        existing = by_name.get(name)
        if existing is None:
            if port in state.ports_in_use:
                raise ValueError(f"port {port} is already in use by another process; "
                                 "choose another backend port in assp-ng.toml")
            todo.append((shost, xhost, port, auth))
        elif not _is_ours(state, existing):
            raise ValueError(f"master.cf already defines a service {existing.name} that "
                             "assp-ng did not add; choose another backend port")
    public = [s for s in state.services if is_public_listener(s)]
    disable: list[MasterService] = []
    if any(f.kind == "listener" and f.can_disable for f in findings):
        uncovered = [s for s in public if service_port(s) not in listener_ports]
        if uncovered:
            raise ValueError(
                "refusing to disable public Postfix services that no ASSP-NG listener "
                "covers (they would stop accepting mail): "
                + ", ".join(f"{s.name} (port {service_port(s)})" for s in uncovered))
        disable = public
    notes: list[str] = []
    if not todo and not disable:
        notes.append("master.cf already has the assp-ng internal services and no public "
                     "listener left to disable: nothing to change")
        return Plan(state.master_text, notes)

    risky = sorted({k for s in disable for k in s.options if k in _FILTER_KEYS})
    if risky and (state.rspamd_dkim or state.amavis_dkim) and not drop_overrides:
        raise ValueError(
            "disabling the public services drops " + ", ".join(risky) + " while a DKIM "
            "signer (rspamd/amavis) is active, so mail may stop being signed or filtered; "
            "review the plan and pass --drop-overrides to go ahead")
    for svc in disable:
        if svc.options:
            notes.append(f"'{svc.name}' is disabled and its overrides are dropped: "
                         + ", ".join(f"{k}={v}" for k, v in svc.options.items()))

    eol = "\r\n" if "\r\n" in state.master_text else "\n"
    lines = split_lines(state.master_text)
    for svc in sorted(disable, key=lambda s: s.line_start, reverse=True):
        block = ["#" + line for line in lines[svc.line_start - 1:svc.line_end]]
        if block and not block[-1].endswith("\n"):
            block[-1] += eol
        lines[svc.line_start - 1:svc.line_end] = [f"{MARKER_DISABLED} {day}{eol}", *block]
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += eol
    chroot = _chroot_column(state, public)
    for shost, xhost, port, auth in todo:
        lines.append(eol + f"{MARKER_ADDED} {day}" + eol)
        lines.append(f"{shost}:{port} inet n - {chroot} - - smtpd" + eol)
        lines.extend(f"  -o {opt}{eol}" for opt in _options(xhost, auth))

    for svc in disable:
        notes.append(f"public service '{svc.name}' is commented out")
    notes.append("Postfix will be restarted, then ASSP-NG (assp-ng-proxy) restarted; no other "
                 "service is stopped in this release")
    for f in findings:
        if f.kind == "dkim-signer":
            notes.append(f"DKIM: {DKIM_NOTE}")
        elif not f.can_disable:
            notes.append(f"keep for now: {f.description} (needs: {f.replaced_by})")
    return Plan("".join(lines), notes, [(s.name, s.type) for s in disable],
                [(f"{h}:{p}", "inet") for h, _x, p, _a in todo])


def render_diff(old: str, new: str) -> str:
    """A unified diff of ``master.cf``; empty when nothing changes."""
    return "".join(difflib.unified_diff(split_lines(old), split_lines(new),
                                        "master.cf (current)", "master.cf (planned)"))
