# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only inspection of a Postfix installation and detection of what ASSP-NG replaces.

Every subprocess call goes through the injected ``run`` (a ``subprocess.run`` look-alike) as
an argument list with a 60 s timeout and a checked return code. Nothing here writes anything.
"""
from __future__ import annotations

import re
import socket
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path

from asspng.net.ipnet import IPNetwork

Run = Callable[..., "subprocess.CompletedProcess[str]"]

# What the installed ASSP-NG provides in this release (spec 8.10, capability-aware).
FEATURES = frozenset({"listeners"})

MARKER_ADDED = "# added by assp-ng"
MARKER_DISABLED = "# disabled by assp-ng"
DKIM_NOTE = "signing must be migrated before disabling rspamd/amavis — subproject 2"
PUBLIC_PORTS = frozenset({25, 587, 465})
_PORT_NAMES = {"smtp": 25, "submission": 587, "smtps": 465, "submissions": 465, "ssmtp": 465}
# systemd unit of the Postfix instance (Debian 13 runs it as postfix@-); to be confirmed on
# the test server before release.
POSTFIX_UNIT = "postfix@-"
_RESTRICTIONS = ("smtpd_client_restrictions", "smtpd_helo_restrictions",
                 "smtpd_sender_restrictions", "smtpd_relay_restrictions",
                 "smtpd_recipient_restrictions", "smtpd_data_restrictions",
                 "smtpd_end_of_data_restrictions")
_COMMAND_TIMEOUT_S = 60


class PostfixError(RuntimeError):
    """A failed command or an unusable Postfix installation; the message is safe to print."""


def run_checked(run: Run, argv: Sequence[str], timeout: int = _COMMAND_TIMEOUT_S
                ) -> "subprocess.CompletedProcess[str]":
    """Run ``argv`` (never through a shell) and raise ``PostfixError`` unless it exits 0."""
    what = " ".join(argv)
    try:
        done = run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PostfixError(f"{what} failed: {type(exc).__name__}") from None
    if done.returncode != 0:
        lines = (done.stderr or "").strip().splitlines()
        detail = f": {lines[0][:200]}" if lines else ""
        raise PostfixError(f"{what} failed (exit {done.returncode}){detail}")
    return done


class PostfixRefused(PostfixError):
    """A refusal before anything changed (usage error, exit code 2)."""


def split_lines(text: str) -> list[str]:
    """Split on ``\\n`` only, keeping the terminators (``str.splitlines`` would also split on
    form feeds, NEL and the Unicode separators, which master.cf comments may contain)."""
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def read_master(path: Path) -> str:
    """Read master.cf as bytes; undecodable bytes survive as surrogates and are written back."""
    return path.read_bytes().decode("utf-8", errors="surrogateescape")


@dataclass
class MasterService:
    """One logical ``master.cf`` entry; lines are 1-based and inclusive."""

    name: str
    type: str
    line_start: int
    line_end: int
    command: str
    options: dict[str, str]


@dataclass
class PostfixState:
    main: dict[str, str]
    master_text: str
    services: list[MasterService]
    ispconfig: bool
    rspamd_dkim: bool
    amavis_dkim: bool
    ports_in_use: set[int]


@dataclass
class Finding:
    kind: str
    description: str
    replaced_by: str
    can_disable: bool


def parse_master(text: str) -> list[MasterService]:
    """Parse active services the way Postfix's readlline does.

    A logical line starts at a line whose first character is neither whitespace nor ``#`` and
    continues across blank lines, whitespace-only lines and ``#`` lines until the next such
    line. ``line_end`` is the last line that carries content, so comments after the final
    option belong to what follows, while comments and blanks between options belong to the
    service.
    """
    lines = split_lines(text)
    services: list[MasterService] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line[0] in " \t#":
            i += 1
            continue
        last, j = i, i + 1
        while j < len(lines):
            nxt = lines[j]
            if nxt.strip() and nxt[0] not in " \t#":
                break
            if nxt.strip() and nxt[0] in " \t":
                last = j
            j += 1
        tokens: list[str] = []
        for n, physical in enumerate(lines[i:last + 1]):
            if n and (not physical.strip() or physical.strip().startswith("#")):
                continue
            tokens.extend(physical.split())
        start, i = i, j
        if len(tokens) < 8:
            continue  # malformed; Postfix itself would refuse it
        options: dict[str, str] = {}
        args = tokens[8:]
        for pos, arg in enumerate(args[:-1]):
            if arg == "-o" and "=" in args[pos + 1]:
                key, _, value = args[pos + 1].partition("=")
                options[key] = value
        services.append(MasterService(tokens[0], tokens[1], start + 1, last + 1,
                                      tokens[7], options))
    return services


def service_port(service: MasterService) -> int | None:
    if service.type != "inet":
        return None
    tail = service.name.rsplit(":", 1)[-1]
    if tail.isdigit():
        return int(tail)
    if tail in _PORT_NAMES:
        return _PORT_NAMES[tail]
    try:
        return socket.getservbyname(tail, "tcp")
    except OSError:
        return None


def service_host(service: MasterService) -> str:
    """The loopback address to probe: the bound address, or loopback for a wildcard."""
    head = service.name.rsplit(":", 1)[0] if ":" in service.name else ""
    head = head.strip("[]")
    return "127.0.0.1" if head in ("", "*", "0.0.0.0", "::") else head


def is_public_listener(service: MasterService) -> bool:
    return (service.command in ("smtpd", "postscreen")
            and service_port(service) in PUBLIC_PORTS)


def _parse_postconf_n(text: str) -> dict[str, str]:
    main: dict[str, str] = {}
    key = ""
    for line in text.splitlines():
        if line[:1] in (" ", "\t") and key:
            main[key] = (main[key] + " " + line.strip()).strip()
        elif " = " in line or line.endswith(" ="):
            key, _, value = line.partition(" =")
            key = key.strip()
            main[key] = value.strip()
    return main


def _parse_ss(text: str) -> set[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        tail = fields[3].rsplit(":", 1)[-1]
        if tail.isdigit():
            ports.add(int(tail))
    return ports


_RSPAMD_KEYS = re.compile(r"^\s*(path|selector|domain|selector_map|path_map)\b", re.M)
_RSPAMD_OFF = re.compile(r"^\s*enabled\s*=\s*false", re.M | re.I)
_AMAVIS_KEY = re.compile(r"^\s*dkim_key\s*\(", re.M)


def _active(text: str) -> str:
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith(("#", "//")))


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rspamd_dkim(rspamd_dir: Path) -> bool:
    for sub in ("local.d", "override.d"):
        body = _active(_read(rspamd_dir / sub / "dkim_signing.conf"))
        if _RSPAMD_KEYS.search(body) and not _RSPAMD_OFF.search(body):
            return True
    return False


def _amavis_dkim(amavis_dir: Path) -> bool:
    files = [amavis_dir / "amavisd.conf"]
    if (amavis_dir / "conf.d").is_dir():
        files += sorted(p for p in (amavis_dir / "conf.d").iterdir() if p.is_file())
    return any(_AMAVIS_KEY.search(_active(_read(path))) for path in files)


def read_state(run: Run = subprocess.run, etc: Path = Path("/etc/postfix"), *,
               ispconfig_dir: Path = Path("/usr/local/ispconfig"),
               rspamd_dir: Path = Path("/etc/rspamd"),
               amavis_dir: Path = Path("/etc/amavis")) -> PostfixState:
    """Collect the state. Services come from ``master.cf`` text (the plan edits that text)."""
    main = _parse_postconf_n(run_checked(run, ["postconf", "-n"]).stdout)
    ports = _parse_ss(run_checked(run, ["ss", "-Hltn"]).stdout)
    try:
        master_text = read_master(etc / "master.cf")
    except OSError as exc:
        raise PostfixError(f"cannot read {etc / 'master.cf'}: {exc.strerror}") from None
    return PostfixState(main=main, master_text=master_text, services=parse_master(master_text),
                        ispconfig=ispconfig_dir.exists(), rspamd_dkim=_rspamd_dkim(rspamd_dir),
                        amavis_dkim=_amavis_dkim(amavis_dir), ports_in_use=ports)


def detect(state: PostfixState, features: frozenset[str]) -> list[Finding]:
    """Report what ASSP-NG makes redundant; ``can_disable`` only when its feature exists."""
    findings: list[Finding] = []

    def add(kind: str, description: str, replaced_by: str, needs: set[str]) -> None:
        findings.append(Finding(kind, description, replaced_by, needs <= features))

    for svc in state.services:
        if is_public_listener(svc):
            add("listener", f"public {svc.command} service '{svc.name}' on port "
                f"{service_port(svc)}", "listeners", {"listeners"})
    main = state.main
    if any(s.command == "postscreen" for s in state.services) or "postscreen_dnsbl_sites" in main:
        extra = " with DNSBL settings" if "postscreen_dnsbl_sites" in main else ""
        add("postscreen", f"postscreen{extra}", "connection limits, DNSBL", {"dnsbl"})
    restrictions = {k: main[k] for k in _RESTRICTIONS if k in main}
    dnsbl = [k for k, v in restrictions.items() if re.search(r"reject_(rbl_client|rhsbl_)", v)]
    if dnsbl:
        add("dnsbl", "reject_rbl_client/reject_rhsbl_* in " + ", ".join(dnsbl),
            "DNSBL check", {"dnsbl"})
    grey = [v for v in restrictions.values() if "check_policy_service" in v
            and re.search(r"10023|postgrey", v)]
    if grey:
        add("postgrey", "postgrey policy service (port 10023 or postgrey socket) in "
            "the smtpd restrictions", "greylisting", {"greylisting"})
    milters = " ".join(main.get(k, "") for k in ("smtpd_milters", "non_smtpd_milters"))
    if re.search(r"rspamd|:11332", milters):
        add("rspamd", "rspamd milter in smtpd_milters/non_smtpd_milters", "spam checks", {"spam"})
    if "clamav" in milters:
        add("clamav-milter", "clamav-milter in the milters", "ClamAV check", {"antivirus"})
    amavis = _amavis_parts(state)
    if amavis:
        add("amavis", "amavis: " + ", ".join(amavis), "spam and antivirus checks",
            {"spam", "antivirus"})
    if state.rspamd_dkim or state.amavis_dkim:
        who = " and ".join(n for n, on in (("rspamd", state.rspamd_dkim),
                                           ("amavis", state.amavis_dkim)) if on)
        findings.append(Finding("dkim-signer", f"DKIM signing is done by {who}: {DKIM_NOTE}",
                                "DKIM signer (subproject 2)", False))
    return findings


def _amavis_parts(state: PostfixState) -> list[str]:
    parts: list[str] = []
    cf = state.main.get("content_filter", "")
    if "amavis" in cf or ":10024" in cf:
        parts.append(f"content_filter={cf}")
    for svc in state.services:
        if "amavis" in svc.name:
            parts.append(f"service {svc.name}")
        elif (svc.type == "inet" and svc.command == "smtpd" and not is_public_listener(svc)
              and svc.options.get("content_filter") == ""):
            parts.append(f"reinjection listener {svc.name}")
    return parts


def trusted_missing_from_mynetworks(trusted: Sequence[IPNetwork], mynetworks: str
                                    ) -> tuple[list[IPNetwork], list[str]]:
    """The trusted networks that Postfix's ``mynetworks`` value does not cover, and the
    entries of that value that cannot be evaluated here (lookup tables, files, exclusions).

    Because of XCLIENT, Postfix sees the real client address, so a trusted network that
    should relay without AUTH must be in ``mynetworks`` too (ruling R67).
    """
    covered: list[IPNetwork] = []
    unchecked: list[str] = []
    for entry in re.split(r"[\s,]+", mynetworks.strip()):
        if not entry:
            continue
        text = re.sub(r"^\[([^\]]+)\]", r"\1", entry)  # [2001:db8::]/32 -> 2001:db8::/32
        try:
            covered.append(ip_network(text, strict=False))
        except ValueError:
            unchecked.append(entry)
    return [net for net in trusted if not any(_within(net, own) for own in covered)], unchecked


def _within(net: IPNetwork, other: IPNetwork) -> bool:
    if isinstance(net, IPv4Network):
        return isinstance(other, IPv4Network) and net.subnet_of(other)
    return isinstance(other, IPv6Network) and net.subnet_of(other)
