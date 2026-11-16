# SPDX-License-Identifier: GPL-3.0-or-later
"""Static checks of the deployment files in packaging/ and docs/ (nothing installs anything)."""
from __future__ import annotations

import grp
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from asspng.config.docgen import render_default_toml
from asspng.config.loader import load_config
from asspng.config.settings import REGISTRY
from tests.support.certs import make_cert

ROOT = Path(__file__).resolve().parents[3]
PKG = ROOT / "packaging"
UNIT = PKG / "systemd" / "assp-ng-proxy.service"
NOTIFY = PKG / "systemd" / "assp-ng-notify@.service"
LOGROTATE = PKG / "logrotate" / "assp-ng"
WRAPPER = PKG / "bin" / "assp-ng"
HOOK = PKG / "certbot" / "assp-ng-deploy-hook"
INSTALL = PKG / "install.sh"
EXAMPLE = PKG / "config" / "assp-ng.toml.example"
SHELL_SCRIPTS = [INSTALL, HOOK, WRAPPER]
SPDX = "SPDX-License-Identifier: GPL-3.0-or-later"


def parse_unit(path: Path) -> dict[str, dict[str, list[str]]]:
    """Parse a unit file into {section: {key: [values...]}} (repeated keys keep every value)."""
    sections: dict[str, dict[str, list[str]]] = {}
    current = ""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, {})
            continue
        key, _, value = line.partition("=")
        sections[current].setdefault(key.strip(), []).append(value.strip())
    return sections


def test_unit_matches_spec_directives() -> None:
    unit = parse_unit(UNIT)
    service, section_unit = unit["Service"], unit["Unit"]
    assert service["Type"] == ["notify"]
    assert service["WatchdogSec"] == ["30"]
    assert service["MemoryMax"] == ["512M"]
    assert service["MemoryHigh"] == ["384M"]
    env = " ".join(service["Environment"]).split()
    assert "MALLOC_ARENA_MAX=2" in env
    assert "PYTHONPATH=/opt/assp-ng" in env
    wants = " ".join(section_unit["Wants"]).split()
    assert {"redis-server.service", "mariadb.service"} <= set(wants)
    assert "Requires" not in section_unit
    assert service["RuntimeDirectoryPreserve"] == ["restart"]
    assert section_unit["OnFailure"] == ["assp-ng-notify@%n.service"]


def test_unit_remaining_spec_directives() -> None:
    unit = parse_unit(UNIT)
    service, section_unit = unit["Service"], unit["Unit"]
    assert section_unit["Description"] == ["ASSP-NG SMTP proxy"]
    after = " ".join(section_unit["After"]).split()
    assert {"network-online.target", "redis-server.service", "mariadb.service"} <= set(after)
    expected = {
        "User": "assp-ng", "Group": "assp-ng",
        "ExecStart": "/usr/bin/python3 -m asspng.proxy --config /etc/assp-ng/assp-ng.toml",
        "ExecReload": "/bin/kill -HUP $MAINPID",
        "Restart": "on-failure", "RestartSec": "5", "TimeoutStopSec": "45",
        "AmbientCapabilities": "CAP_NET_BIND_SERVICE",
        "CapabilityBoundingSet": "CAP_NET_BIND_SERVICE",
        "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
        "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes", "ProtectControlGroups": "yes",
        "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "RestrictNamespaces": "yes",
        "LockPersonality": "yes", "StateDirectory": "assp-ng", "LogsDirectory": "assp-ng",
        "RuntimeDirectory": "assp-ng", "LimitNOFILE": "65536",
    }
    for key, value in expected.items():
        assert service[key] == [value], key
    assert unit["Install"]["WantedBy"] == ["multi-user.target"]


def test_unit_directory_modes_are_not_world_reachable() -> None:
    """Ruling R54: the control socket and the personal-data logs must not be world-reachable."""
    service = parse_unit(UNIT)["Service"]
    for key in ("RuntimeDirectoryMode", "StateDirectoryMode", "LogsDirectoryMode"):
        assert service[key] == ["0750"], key
    text = UNIT.read_text()
    assert "(9)" in text or "section 9" in text.lower() or "§9" in text


def test_notify_unit() -> None:
    unit = parse_unit(NOTIFY)
    assert unit["Service"]["Type"] == ["oneshot"]
    assert unit["Service"]["ExecStart"] == [
        '/usr/local/bin/assp-ng notify --event service-failed --message "%i failed"']
    # R60: the CLI keeps its rate-limit stamps across runs (crash loops) in a root-only
    # directory that systemd creates.
    assert unit["Service"]["RuntimeDirectory"] == ["assp-ng-notify"]
    assert unit["Service"]["RuntimeDirectoryPreserve"] == ["yes"]
    assert unit["Service"]["RuntimeDirectoryMode"] == ["0700"]
    assert "User" not in unit["Service"]


def _verify_copy(tmp_path: Path, source: Path) -> subprocess.CompletedProcess[str]:
    """systemd-analyze verify needs ExecStart binaries that exist: point them at ones that do."""
    unit_dir = tmp_path / "units"
    unit_dir.mkdir(exist_ok=True)
    # The proxy unit names assp-ng-notify@%n.service, so the template must sit beside it.
    shutil.copy(NOTIFY, unit_dir / NOTIFY.name)
    text = source.read_text().replace("/usr/local/bin/assp-ng", "/usr/bin/env")
    target = unit_dir / source.name
    target.write_text(text)
    return subprocess.run(
        ["systemd-analyze", "--man=no", "--generators=no", "verify", str(target)],
        capture_output=True, text=True, check=False)


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze missing")
@pytest.mark.parametrize("source", [UNIT, NOTIFY], ids=lambda p: p.name)
def test_systemd_analyze_verify(tmp_path: Path, source: Path) -> None:
    result = _verify_copy(tmp_path, source)
    output = result.stdout + result.stderr
    unexpected = [ln for ln in output.splitlines()
                  if ln.strip() and "assp-ng" in ln and "User" not in ln and "Group" not in ln]
    assert result.returncode == 0, output
    assert unexpected == [], output


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck missing")
def test_shellcheck_scripts() -> None:
    result = subprocess.run(["shellcheck", "-x", *map(str, SHELL_SCRIPTS)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_script_has_spdx_and_exec_bit() -> None:
    for path in SHELL_SCRIPTS:
        lines = path.read_text().splitlines()
        assert lines[0].startswith("#!"), path
        assert f"# {SPDX}" in lines[:3], path
        assert path.stat().st_mode & stat.S_IXUSR, path
    for path in (UNIT, NOTIFY, LOGROTATE, EXAMPLE):
        assert SPDX in path.read_text(), path


def test_wrapper_content() -> None:
    lines = [ln for ln in WRAPPER.read_text().splitlines() if ln.strip()]
    assert lines[0] == "#!/bin/sh"
    assert lines[-1] == 'exec env PYTHONPATH=/opt/assp-ng python3 -m asspng.cli "$@"'


def test_logrotate_content() -> None:
    text = LOGROTATE.read_text()
    directives = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("copytruncate" in ln for ln in directives)
    blocks = {m.group(1): m.group(2) for m in
              re.finditer(r"^(/var/log/assp-ng/\S+)\s*\{(.*?)\}", text, re.S | re.M)}
    assert set(blocks) == {"/var/log/assp-ng/maillog.log", "/var/log/assp-ng/assp-ng.log",
                           "/var/log/assp-ng/debug.log"}
    for name, body in blocks.items():
        words = {ln.strip() for ln in body.splitlines()}
        wanted = {"daily", "compress", "delaycompress", "missingok", "notifempty",
                  "create 0640 assp-ng assp-ng"}
        assert wanted <= words, name
        expected = "rotate 7" if name.endswith("debug.log") else "rotate 30"
        assert expected in words, name


@pytest.mark.skipif(shutil.which("logrotate") is None, reason="logrotate missing")
def test_logrotate_config_parses(tmp_path: Path) -> None:
    # The assp-ng user and group do not exist on a development machine: use the caller's.
    user, group = pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name
    config = tmp_path / "assp-ng-logrotate"
    config.write_text(LOGROTATE.read_text().replace("assp-ng assp-ng", f"{user} {group}"))
    config.chmod(0o644)
    result = subprocess.run(["logrotate", "-d", "-s", str(tmp_path / "state"), str(config)],
                            capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "error" not in output


def test_example_config_loads(tmp_path: Path) -> None:
    cert, key = make_cert(tmp_path, "mx1.example.com")
    text = EXAMPLE.read_text()
    text = text.replace("/etc/assp-ng/tls/mx1.example.com/fullchain.pem", str(cert))
    text = text.replace("/etc/assp-ng/tls/mx1.example.com/privkey.pem", str(key))
    assert str(cert) in text and str(key) in text
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "assp-ng.toml").write_text(text)
    (etc / "default.toml").write_text(render_default_toml(REGISTRY))
    snapshot = load_config(etc)
    assert snapshot.system["hostname"] == "mx1.example.com"
    assert [listener.name for listener in snapshot.listeners] == ["inbound", "submission"]
    assert [c.name for c in snapshot.certificates] == ["mx1"]
    assert snapshot.system["health.listen"].startswith("127.0.0.1:")  # type: ignore[union-attr]


# --- certbot deploy hook ---------------------------------------------------------------

_STUB_INSTALL = """#!/bin/sh
# Honours -m (real chmod) and records -o/-g, which an unprivileged test cannot apply.
echo "install $*" >> "$STUB_LOG"
mode=""; owner=""; group=""; isdir=""
while [ $# -gt 0 ]; do
    case "$1" in
        -m) mode="$2"; shift 2 ;;
        -o) owner="$2"; shift 2 ;;
        -g) group="$2"; shift 2 ;;
        -d) isdir=1; shift ;;
        *) break ;;
    esac
done
if [ -n "$isdir" ]; then
    mkdir -p "$1"
    dst="$1"
else
    cp "$1" "$2"
    dst="$2"
fi
[ -z "$mode" ] || chmod "$mode" "$dst"
echo "applied dir=${isdir:-0} mode=$mode owner=$owner group=$group dst=$dst" >> "$STUB_LOG"
"""

_STUB_SYSTEMCTL = """#!/bin/sh
echo "systemctl $*" >> "$STUB_LOG"
if [ "$1" = "is-active" ]; then
    [ "${STUB_ACTIVE:-yes}" = "yes" ]
    exit $?
fi
exit 0
"""


def _sandbox(tmp_path: Path) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("install", _STUB_INSTALL), ("systemctl", _STUB_SYSTEMCTL)):
        stub = bindir / name
        stub.write_text(body)
        stub.chmod(0o755)
    return {"PATH": f"{bindir}:{os.environ['PATH']}", "STUB_LOG": str(tmp_path / "calls.log"),
            "ASSPNG_TLS_DIR": str(tmp_path / "tls")}


def _lineage(tmp_path: Path, name: str) -> Path:
    live = tmp_path / "live" / name
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text("CHAIN")
    (live / "privkey.pem").write_text("KEY")
    return live


def _run_hook(env: dict[str, str], lineage: str | None) -> subprocess.CompletedProcess[str]:
    full = dict(env)
    if lineage is not None:
        full["RENEWED_LINEAGE"] = lineage
    return subprocess.run(["/bin/sh", str(HOOK)], env=full, capture_output=True, text=True,
                          check=False)


def _calls(env: dict[str, str]) -> str:
    log = Path(env["STUB_LOG"])
    return log.read_text() if log.exists() else ""


@pytest.mark.parametrize("bad", ["", ".hidden", "..", "a b", "a;b", "a$b"])
def test_hook_rejects_bad_lineage_name(tmp_path: Path, bad: str) -> None:
    env = _sandbox(tmp_path)
    parent = tmp_path / "live"
    parent.mkdir()
    result = _run_hook(env, f"{parent}/{bad}" if bad else "")
    assert result.returncode != 0
    assert "systemctl" not in _calls(env)
    assert not (tmp_path / "tls").exists()


def test_hook_missing_lineage_variable_fails(tmp_path: Path) -> None:
    env = _sandbox(tmp_path)
    assert _run_hook(env, None).returncode != 0


def test_hook_missing_files_fail(tmp_path: Path) -> None:
    env = _sandbox(tmp_path)
    (tmp_path / "live" / "empty").mkdir(parents=True)
    assert _run_hook(env, str(tmp_path / "live" / "empty")).returncode != 0
    assert "systemctl reload" not in _calls(env)


def test_hook_installs_atomically_and_reloads(tmp_path: Path) -> None:
    env = _sandbox(tmp_path)
    live = _lineage(tmp_path, "mx1.example.com")
    result = _run_hook(env, str(live))
    assert result.returncode == 0, result.stderr
    target = tmp_path / "tls" / "mx1.example.com"
    assert (target / "fullchain.pem").read_text() == "CHAIN"
    assert (target / "privkey.pem").read_text() == "KEY"
    assert sorted(p.name for p in target.iterdir()) == ["fullchain.pem", "privkey.pem"]
    calls = _calls(env)
    applied = [ln for ln in calls.splitlines() if ln.startswith("applied ")]
    files = [ln for ln in applied if "dir=0" in ln]
    assert len(files) == 2
    for ln in files:
        assert " mode=0640 owner=root group=assp-ng " in ln, ln
    for name in ("fullchain.pem", "privkey.pem"):
        assert stat.S_IMODE((target / name).stat().st_mode) == 0o640, name
    assert any("dir=1 mode=0750 owner=root group=assp-ng" in ln for ln in applied)
    # every file is installed to a temporary name in the target directory, then moved over
    destinations = [ln.split()[-1] for ln in calls.splitlines() if ln.startswith("install -m")]
    assert len(destinations) == 2
    assert all(re.search(r"\.pem\.new\.\d+$", d) and Path(d).parent == target
               for d in destinations), destinations
    assert "systemctl is-active --quiet assp-ng-proxy" in calls
    assert "systemctl reload assp-ng-proxy" in calls


def test_hook_does_not_reload_inactive_service(tmp_path: Path) -> None:
    env = _sandbox(tmp_path)
    env["STUB_ACTIVE"] = "no"
    live = _lineage(tmp_path, "mx1.example.com")
    result = _run_hook(env, str(live))
    assert result.returncode == 0, result.stderr
    calls = _calls(env)
    assert "is-active" in calls
    assert "systemctl reload" not in calls


# --- installer (never executed here: it is root-only) ----------------------------------

def test_install_script_static_content() -> None:
    text = INSTALL.read_text()
    lines = text.splitlines()
    assert lines[0] == "#!/bin/bash"
    assert "set -euo pipefail" in lines[:20]
    assert re.search(r'EUID.*-ne 0|id -u.*-ne 0', text), "must refuse to run as non-root"
    # never overwrites an existing config
    assert re.search(r'if \[ ! -e "\$ETC/default\.toml" \]', text)
    assert re.search(r'if \[ ! -e "\$ETC/assp-ng\.toml" \]', text)
    assert "config init" in text
    # never touches Postfix or creates DB users; it only points at the assistant
    assert "postfix check" in text and "postfix plan" in text
    assert not re.search(r"^\s*(postconf|postfix\b|systemctl\s+\w+\s+postfix)", text, re.M)
    assert "PASSWORD" in text and "CREATE USER" in text
    assert not re.search(r"^\s*(mysql|mariadb)\b", text, re.M)
    assert "root:assp-ng" in text and "0750" in text and "0640" in text
    assert "copytruncate" not in text


# --- documentation ---------------------------------------------------------------------

def _doc_commands(path: Path) -> list[list[str]]:
    commands: list[list[str]] = []
    for line in path.read_text().splitlines():
        match = re.match(r"^\s*(?:sudo\s+)?assp-ng\s+(.+)$", line)
        if match:
            commands.append(match.group(1).split())
    return commands


def _help_words(tokens: list[str]) -> list[str]:
    words: list[str] = []
    for token in tokens[:2]:
        if not re.fullmatch(r"[a-z]+", token):
            break
        words.append(token)
    return words


def _cli_help(words: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "asspng.cli", *words, "--help"],
                          cwd=ROOT, capture_output=True, text=True, check=False)


def test_docs_reference_existing_cli_commands() -> None:
    commands = _doc_commands(ROOT / "docs" / "installation.md")
    assert len(commands) >= 8, "installation.md should show assp-ng commands"
    for tokens in commands:
        words = _help_words(tokens)
        assert words, tokens
        result = _cli_help(words)
        assert result.returncode == 0, (tokens, result.stderr)
        flags = [t for t in tokens if t.startswith("--")]
        for flag in flags:
            assert flag in result.stdout, (tokens, flag)


def test_docs_helper_detects_unknown_command() -> None:
    assert _cli_help(["frobnicate"]).returncode != 0


def test_installation_doc_states_release_blockers() -> None:
    text = (ROOT / "docs" / "installation.md").read_text()
    assert "postfix@-" in text
    assert "postconf -M" in text and "postconf -P" in text
    assert "ISPConfig" in text and "template" in text
    assert "vm.overcommit_memory" in text and "appendfsync everysec" in text


def test_acceptance_checklist_covers_spec() -> None:
    text = (ROOT / "docs" / "acceptance-checklist.md").read_text()
    for needle in ("swaks", "Thunderbird", "Outlook", "587", "465", "14 days",
                   "test mode", "Let's Encrypt", "XCLIENT", "clean Debian 13"):
        assert needle in text, needle


def _install_lines(text: str) -> list[list[str]]:
    """Logical shell lines (backslash continuations joined), split into words."""
    joined = re.sub(r"\\\n\s*", " ", text)
    return [ln.split() for ln in joined.splitlines() if ln.strip()]


def test_install_script_packages_user_and_directories() -> None:
    words = _install_lines(INSTALL.read_text())
    apt = next(w for w in words if w[:3] == ["apt-get", "install", "-y"])
    assert sorted(apt[3:]) == sorted([
        "python3", "python3-dnspython", "python3-redis", "python3-pymysql",
        "python3-sqlalchemy", "python3-alembic", "python3-systemd", "python3-cryptography",
        "python3-tomlkit"])
    adduser = next(w for w in words if w[0] == "adduser")
    assert "--system" in adduser and "--no-create-home" in adduser
    assert adduser[adduser.index("--shell") + 1] == "/usr/sbin/nologin"
    assert adduser[-1] == "assp-ng"
    etc = next(w for w in words if w[:2] == ["install", "-d"] and '"$ETC"' in w)
    assert etc[2:8] == ["-m", "0750", "-o", "root", "-g", "assp-ng"]
    assert etc[8:] == ['"$ETC"', '"$ETC/domain.d"', '"$ETC/user.d"', '"$ETC/tls"']


def test_install_script_swaps_code_atomically() -> None:
    text = INSTALL.read_text()
    words = _install_lines(text)
    assert 'STAGE="$OPT/asspng.new"' in text and 'OLD="$OPT/asspng.old"' in text
    assert any(w[0] == "trap" and "rm -rf" in " ".join(w) and "$STAGE" in " ".join(w)
               and w[-1] == "EXIT" for w in words)
    lines = [" ".join(w) for w in words]

    def position(prefix: str) -> int:
        return next(i for i, ln in enumerate(lines) if ln.startswith(prefix))

    assert not any(ln.startswith('rm -rf "${OPT:?}/asspng"') for ln in lines)
    extract = position("tar -C")
    check = position('if [ ! -f "$STAGE/__init__.py" ]')
    to_old = position('mv "$OPT/asspng" "$OLD"')
    into_place = position('mv "$STAGE" "$OPT/asspng"')
    cleanup = position('rm -rf "$OLD"')
    assert extract < check < to_old < into_place < cleanup
    assert "--transform" in lines[extract] and "asspng.new" in lines[extract]
