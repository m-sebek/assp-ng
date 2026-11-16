# SPDX-License-Identifier: GPL-3.0-or-later
"""Postfix integration assistant: inspection, planning, apply and rollback (spec 8.10).

Nothing here touches the real /etc/postfix or runs a real command: every subprocess call goes
through ``FakeRun`` and the files live in a temporary directory copied from the fixtures.
"""
import datetime as dt
import os
import shutil
import smtplib
import stat
import subprocess
from collections.abc import Callable, Iterator, Sequence
from ipaddress import ip_network
from pathlib import Path

import pytest

from asspng.cli.config_cmd import Deps
from asspng.cli.main import main
from asspng.postfix.apply import (
    Target,
    apply_plan,
    check_trusted_dir,
    make_verifier,
    rollback,
)
from asspng.postfix.inspect import PostfixRefused, parse_master, read_master
from asspng.postfix.env import PostfixEnv
from asspng.postfix.inspect import (DKIM_NOTE, FEATURES, Finding, PostfixError, PostfixState,
                                    read_state)
from asspng.postfix.inspect import detect, trusted_missing_from_mynetworks
from asspng.postfix.plan import Plan, build_plan, render_diff

FIXTURES = Path(__file__).parent / "fixtures"
BACKENDS: list[tuple[str, int, bool]] = [("127.0.0.1", 10125, False), ("127.0.0.1", 10587, True)]
PORTS = frozenset({25, 587, 465})
ALL_FEATURES = frozenset({"listeners", "dnsbl", "greylisting", "spam", "antivirus"})
NOW = dt.datetime(2026, 11, 15, 12, 0, 0, tzinfo=dt.timezone.utc)
STOP = ["systemctl", "stop", "assp-ng-proxy"]
CHECK = ["postfix", "check"]
RESTART = ["systemctl", "restart", "postfix"]
RESTART_ASSP = ["systemctl", "restart", "assp-ng-proxy"]
SHOW = ["systemctl", "show", "-p", "LoadState", "--value", "assp-ng-proxy"]
ACTIVE_PF = ["systemctl", "is-active", "postfix@-"]
ACTIVE_ASSP = ["systemctl", "is-active", "assp-ng-proxy"]


class FakeRun:
    """A stand-in for subprocess.run that answers from the fixture and records every call."""

    def __init__(self, fixture: str, etc: Path | None = None) -> None:
        self.dir = FIXTURES / fixture
        self.etc = etc
        self.calls: list[list[str]] = []
        self.fail: list[list[str]] = []  # each entry fails once when called
        self.at_check: str | None = None  # master.cf content seen by "postfix check"
        self.ss_text = (self.dir / "ss.txt").read_text()
        self.units = {"assp-ng-proxy": "inactive", "postfix@-": "active"}
        self.override: dict[tuple[str, str], str] = {}
        self.load_state = "loaded"
        self.after_restart = "active"  # state of postfix@- after "systemctl restart postfix"

    def __call__(self, argv: Sequence[str], **kw: object) -> "subprocess.CompletedProcess[str]":
        assert isinstance(argv, list), "argument lists only"
        assert not kw.get("shell"), "never a shell"
        assert kw.get("timeout") == 60, "every call has a 60 s timeout"
        assert argv[0] in {"postconf", "ss", "postfix", "systemctl"}, argv
        self.calls.append(list(argv))
        if argv in self.fail:
            self.fail.remove(list(argv))
            if argv == RESTART_ASSP:  # a failed restart leaves the unit dead
                self.units["assp-ng-proxy"] = "failed"
            return subprocess.CompletedProcess(argv, 1, "", "simulated failure\n")
        if argv == CHECK and self.etc is not None:
            self.at_check = read_master(self.etc / "master.cf")
        out = ""
        if argv[:2] == ["postconf", "-c"]:
            return subprocess.CompletedProcess(argv, 0, self.simulate(Path(argv[2]), argv[3]), "")
        if argv == SHOW:
            out = self.load_state + "\n"
        elif argv[:2] == ["systemctl", "is-active"]:
            state = self.units[argv[2]]
            rc = 0 if state == "active" else 3
            return subprocess.CompletedProcess(argv, rc, state + "\n", "")
        elif argv == STOP:
            self.units["assp-ng-proxy"] = "inactive"
        elif argv == RESTART_ASSP:
            self.units["assp-ng-proxy"] = "active"
        elif argv == RESTART:
            self.units["postfix@-"] = self.after_restart
        if argv == ["postconf", "-n"]:
            out = (self.dir / "postconf-n.txt").read_text()
        elif argv == ["ss", "-Hltn"]:
            out = self.ss_text
        return subprocess.CompletedProcess(argv, 0, out, "")

    def simulate(self, directory: Path, mode: str) -> str:
        """Canned ``postconf -c DIR -M|-P`` output (hand-written fixtures, upstream format).

        ``-c <etc>`` answers for the current master.cf, any other directory (the guard's
        temporary copy) for the planned one. ``override`` replaces a canned file.
        """
        which = "current" if directory == self.etc else "planned"
        if (which, mode) in self.override:
            return self.override[(which, mode)]
        prefix = "planned_" if which == "planned" else ""
        text = (self.dir / f"{prefix}postconf_{mode[1]}.txt").read_text()
        return "".join(line + "\n" for line in text.splitlines() if not line.startswith("#"))


def canned(fixture: str, planned: bool, mode: str) -> str:
    name = f"{'planned_' if planned else ''}postconf_{mode[1]}.txt"
    text = (FIXTURES / fixture / name).read_text()
    return "".join(line + "\n" for line in text.splitlines() if not line.startswith("#"))


@pytest.fixture(autouse=True)
def umask_022() -> Iterator[None]:
    """Directories as root creates them (umask 022): the backup checks (R58) refuse a
    group-writable path, and a user-private-group umask (002) would make every one so."""
    old = os.umask(0o022)
    yield
    os.umask(old)


class Setup:
    def __init__(self, tmp: Path, fixture: str) -> None:
        self.tmp = tmp
        self.fixture = fixture
        self.etc = tmp / "etc-postfix"
        self.etc.mkdir(parents=True)
        shutil.copy(FIXTURES / fixture / "master.cf", self.etc / "master.cf")
        os.chmod(self.etc / "master.cf", 0o640)
        (self.etc / "main.cf").write_text("# main.cf of the test\n")
        (self.etc / "sasl_passwd").write_text("secret\n")
        os.chmod(self.etc / "sasl_passwd", 0o600)
        os.symlink("main.cf", self.etc / "main.cf.link")
        self.backup_root = tmp / "backup"
        self.ispconfig = tmp / "no-ispconfig"
        self.run = FakeRun(fixture, self.etc)
        self.probed: list[list[Target]] = []
        self.probe_ok = True

    def probe(self, targets: Sequence[Target]) -> bool:
        self.probed.append(list(targets))
        return self.probe_ok

    def seq(self) -> list[list[str]]:
        """The recorded commands without the read-only postconf/ss calls."""
        return [c for c in self.run.calls if c[0] not in {"postconf", "ss"}]

    def state(self) -> PostfixState:
        return read_state(self.run, self.etc, ispconfig_dir=self.ispconfig,
                          rspamd_dir=FIXTURES / self.fixture / "rspamd",
                          amavis_dir=FIXTURES / self.fixture / "amavis")

    def env(self, **over: object) -> PostfixEnv:
        values: dict[str, object] = dict(
            run=self.run, etc=self.etc, backup_root=self.backup_root,
            ispconfig_dir=self.ispconfig, rspamd_dir=FIXTURES / self.fixture / "rspamd",
            amavis_dir=FIXTURES / self.fixture / "amavis", isatty=lambda: True,
            confirm=lambda question: True, verify_factory=lambda t, b: lambda: True,
            now=lambda: NOW, probe=self.probe)
        values.update(over)
        return PostfixEnv(**values)  # type: ignore[arg-type]


@pytest.fixture
def plain(tmp_path: Path) -> Setup:
    return Setup(tmp_path / "plain", "plain")


@pytest.fixture
def rich(tmp_path: Path) -> Setup:
    return Setup(tmp_path / "rich", "postscreen-rspamd")


def kinds(findings: list[Finding]) -> list[str]:
    return [f.kind for f in findings]


def by_kind(findings: list[Finding], kind: str) -> list[Finding]:
    return [f for f in findings if f.kind == kind]


# --- detection ---------------------------------------------------------------------------

def test_detect_plain_debian(plain: Setup) -> None:
    state = plain.state()
    assert [s.name for s in state.services if s.type == "inet"] == ["smtp"]
    assert state.main["myhostname"] == "mail.example.org"
    assert not state.ispconfig and not state.rspamd_dkim and not state.amavis_dkim
    assert state.ports_in_use == {25, 22, 53}
    findings = detect(state, FEATURES)
    assert kinds(findings) == ["listener"]
    assert findings[0].can_disable and findings[0].replaced_by == "listeners"
    assert "smtp" in findings[0].description and "25" in findings[0].description


def test_detect_postscreen_postgrey_rspamd_keep_for_now(rich: Setup) -> None:
    findings = detect(rich.state(), FEATURES)
    assert set(kinds(findings)) == {"listener", "postscreen", "dnsbl", "postgrey", "rspamd",
                                    "dkim-signer"}
    assert len(by_kind(findings, "listener")) == 3  # 25 (postscreen), submission, smtps
    assert all(f.can_disable for f in by_kind(findings, "listener"))
    assert all(not f.can_disable for f in findings if f.kind != "listener")
    assert "10023" in by_kind(findings, "postgrey")[0].description
    # once the replacements exist, everything but the DKIM signer may go
    full = detect(rich.state(), ALL_FEATURES)
    assert all(f.can_disable for f in full if f.kind != "dkim-signer")
    assert not by_kind(full, "dkim-signer")[0].can_disable


def test_detect_dkim_signer(rich: Setup, plain: Setup, tmp_path: Path) -> None:
    state = rich.state()
    assert state.rspamd_dkim and not state.amavis_dkim
    (finding,) = by_kind(detect(state, FEATURES), "dkim-signer")
    assert DKIM_NOTE in finding.description
    assert DKIM_NOTE == "signing must be migrated before disabling rspamd/amavis — subproject 2"
    a_state = Setup(tmp_path / "x", "amavis").state()
    assert a_state.amavis_dkim and not a_state.rspamd_dkim
    assert DKIM_NOTE in by_kind(detect(a_state, ALL_FEATURES), "dkim-signer")[0].description
    assert not by_kind(detect(plain.state(), FEATURES), "dkim-signer")


def test_detect_amavis_and_commented_dkim(tmp_path: Path) -> None:
    s = Setup(tmp_path, "amavis")
    findings = detect(s.state(), FEATURES)
    assert {"listener", "amavis", "dnsbl", "dkim-signer"} <= set(kinds(findings))
    assert "smtp-amavis" in by_kind(findings, "amavis")[0].description
    assert "10025" in by_kind(findings, "amavis")[0].description
    # a commented dkim_key line is not a signer
    conf = FIXTURES / "amavis" / "amavis" / "conf.d" / "50-user"
    only_comment = tmp_path / "amavis-conf"
    (only_comment / "conf.d").mkdir(parents=True)
    (only_comment / "conf.d" / "50-user").write_text(
        "# dkim_key('example.org', 'dkim', '/x');\n" + conf.read_text().split("\n", 3)[0])
    state = read_state(s.run, s.etc, ispconfig_dir=s.ispconfig, amavis_dir=only_comment,
                       rspamd_dir=tmp_path / "none")
    assert not state.amavis_dkim


def test_detect_ispconfig_flag(tmp_path: Path) -> None:
    s = Setup(tmp_path, "ispconfig")
    s.ispconfig.mkdir()
    state = read_state(s.run, s.etc, ispconfig_dir=s.ispconfig, rspamd_dir=tmp_path / "n",
                       amavis_dir=tmp_path / "n")
    assert state.ispconfig
    assert {"amavis", "postgrey", "rspamd"} <= set(kinds(detect(state, FEATURES)))


def test_read_state_parses_ss_addresses(plain: Setup) -> None:
    plain.run.ss_text = ("LISTEN 0 100 [::1]:10125 [::]:*\nLISTEN 0 100 *:587 *:*\n"
                         "LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 1 [::]:465 [::]:*\n")
    assert plain.state().ports_in_use == {10125, 587, 53, 465}


def test_read_state_failure_is_a_clear_error(plain: Setup) -> None:
    plain.run.fail.append(["postconf", "-n"])
    with pytest.raises(PostfixError, match="postconf -n.*simulated failure"):
        plain.state()


def test_read_state_missing_command_is_a_clear_error(plain: Setup) -> None:
    def missing(argv: Sequence[str], **kw: object) -> "subprocess.CompletedProcess[str]":
        if argv[0] == "ss":
            raise FileNotFoundError(2, "No such file", "ss")
        return plain.run(argv, **kw)
    with pytest.raises(PostfixError, match="ss -Hltn failed"):
        read_state(missing, plain.etc, ispconfig_dir=plain.ispconfig)


# --- planning ----------------------------------------------------------------------------

def make_plan(setup: Setup, features: frozenset[str] = FEATURES, **kw: bool) -> Plan:
    state = setup.state()
    return build_plan(state, detect(state, features), BACKENDS, listener_ports=PORTS,
                      today=NOW.date(), **kw)


def test_plan_comments_out_with_marker(rich: Setup) -> None:
    plan = make_plan(rich)
    new = plan.master_text_new
    assert "# disabled by assp-ng 2026-11-15\n#smtp      inet  n       -       y       -       1" \
           "       postscreen" in new
    assert "\n#submission inet n       -       y       -       -       smtpd\n" in new
    assert "\n#smtps     inet  n       -       y       -       -       smtpd\n" in new
    assert new.count("# disabled by assp-ng 2026-11-15") == 3
    # nothing deleted: every old service line is still there once commented
    for line in ("smtp      inet  n       -       y       -       1       postscreen",
                 "submission inet n       -       y       -       -       smtpd"):
        assert "#" + line in new
    # the non-public helper services stay active
    assert "\nsmtpd     pass  -       -       y       -       -       smtpd\n" in new
    assert "\ndnsblog   unix" in new and "\ntlsproxy  unix" in new


def test_plan_comments_continuation_lines(rich: Setup) -> None:
    new = make_plan(rich).master_text_new
    assert "\n#  -o syslog_name=postfix/submission\n#  -o smtpd_tls_security_level=encrypt\n" in new
    assert "\n#  -o smtpd_tls_wrappermode=yes\n#  -o smtpd_sasl_auth_enable=yes\n" in new
    # an uncommented continuation line must never be left dangling after a commented service
    lines = new.splitlines()
    for i, line in enumerate(lines):
        if line.startswith((" ", "\t")):
            owner = next(prev for prev in reversed(lines[:i]) if not prev.startswith((" ", "\t")))
            assert not owner.startswith("#") or owner.startswith("# added by"), (owner, line)


def test_plan_adds_internal_services(plain: Setup) -> None:
    plan = make_plan(plain)
    new = plan.master_text_new
    assert new.count("# added by assp-ng 2026-11-15") == 2
    tail = new[new.index("# added by assp-ng"):]
    assert ("# added by assp-ng 2026-11-15\n"
            "127.0.0.1:10125 inet n - y - - smtpd\n"
            "  -o smtpd_sasl_auth_enable=no\n"
            "  -o smtpd_authorized_xclient_hosts=127.0.0.1\n") in tail
    assert ("127.0.0.1:10587 inet n - y - - smtpd\n"
            "  -o smtpd_sasl_auth_enable=yes\n"
            "  -o smtpd_tls_auth_only=no\n"
            "  -o smtpd_authorized_xclient_hosts=127.0.0.1\n"
            "  -o smtpd_client_restrictions=permit_sasl_authenticated,reject\n") in tail
    assert "\n#smtp      inet  n       -       y       -       -       smtpd\n" in new
    assert any("restart" in n.lower() for n in plan.notes)


def test_plan_internal_services_copy_chroot_column(tmp_path: Path) -> None:
    s = Setup(tmp_path, "ispconfig")  # the public smtpd lines there are unchrooted ("-")
    new = make_plan(s).master_text_new
    assert "127.0.0.1:10125 inet n - - - - smtpd\n" in new
    s2 = Setup(tmp_path / "b", "plain")
    assert "127.0.0.1:10125 inet n - y - - smtpd\n" in make_plan(s2).master_text_new


def test_plan_without_listener_feature_changes_nothing_public(rich: Setup) -> None:
    new = make_plan(rich, frozenset()).master_text_new
    assert "# disabled by assp-ng" not in new
    assert "\nsmtp      inet  n       -       y       -       1       postscreen\n" in new


def test_plan_refuses_port_conflict(plain: Setup) -> None:
    plain.run.ss_text += "LISTEN 0 100 0.0.0.0:10125 0.0.0.0:*\n"
    state = plain.state()
    with pytest.raises(ValueError, match="10125"):
        build_plan(state, detect(state, FEATURES), BACKENDS, listener_ports=PORTS,
                   today=NOW.date())


def test_plan_amavis_port_10025_does_not_block(tmp_path: Path) -> None:
    s = Setup(tmp_path, "amavis")
    assert {10024, 10025} <= s.state().ports_in_use
    with pytest.raises(ValueError, match="content_filter"):  # amavis DKIM signer + filter
        make_plan(s)
    plan = make_plan(s, drop_overrides=True)
    assert "127.0.0.1:10125 inet" in plan.master_text_new
    assert "127.0.0.1:10025 inet n  -       y" in plan.master_text_new  # amavis kept untouched


def test_plan_is_idempotent(plain: Setup) -> None:
    first = make_plan(plain)
    (plain.etc / "master.cf").write_text(first.master_text_new)
    # now our own services listen on 10125/10587: that is not a conflict
    plain.run.ss_text += "LISTEN 0 100 127.0.0.1:10125 0.0.0.0:*\nLISTEN 0 100 127.0.0.1:10587 x\n"
    second = make_plan(plain)
    assert second.master_text_new == first.master_text_new
    assert any("already" in n for n in second.notes)
    assert render_diff(first.master_text_new, second.master_text_new) == ""


def test_plan_backend_with_conflicting_auth_is_refused(plain: Setup) -> None:
    state = plain.state()
    with pytest.raises(ValueError, match="10125"):
        build_plan(state, [], [("127.0.0.1", 10125, False), ("127.0.0.1", 10125, True)],
                   listener_ports=PORTS)


def test_diff_rendered(plain: Setup) -> None:
    plan = make_plan(plain)
    diff = render_diff(plain.state().master_text, plan.master_text_new)
    assert diff.startswith("--- master.cf (current)\n+++ master.cf (planned)\n")
    assert "-smtp      inet  n       -       y       -       -       smtpd\n" in diff
    assert "+#smtp      inet  n       -       y       -       -       smtpd\n" in diff
    assert "+# disabled by assp-ng 2026-11-15\n" in diff
    assert "+127.0.0.1:10587 inet n - y - - smtpd\n" in diff
    assert render_diff("a\n", "a\n") == ""


# --- apply and rollback ------------------------------------------------------------------

def run_apply(setup: Setup, verify: Callable[[], bool] = lambda: True,
              plan: Plan | None = None, now: dt.datetime = NOW) -> Path:
    state = setup.state()
    plan = plan or make_plan(setup)
    setup.run.calls.clear()
    return apply_plan(plan, state, backup_root=setup.backup_root, run=setup.run, verify=verify,
                      etc=setup.etc, now=lambda: now, probe=setup.probe)


def test_apply_success_order_and_backup(plain: Setup) -> None:
    original = (plain.etc / "master.cf").read_text()
    plan = make_plan(plain)
    backup = run_apply(plain, plan=plan)
    assert plain.seq() == [SHOW, CHECK, RESTART, ACTIVE_PF, RESTART_ASSP]
    assert (plain.etc / "master.cf").read_text() == plan.master_text_new
    assert backup.parent == plain.backup_root and backup.name.startswith("postfix-20261115T")
    assert (backup / "master.cf").read_text() == original
    assert stat.S_IMODE(backup.stat().st_mode) == 0o700
    assert stat.S_IMODE(plain.backup_root.stat().st_mode) == 0o700
    assert (backup / "main.cf.link").is_symlink()
    assert os.readlink(backup / "main.cf.link") == "main.cf"
    assert stat.S_IMODE((backup / "sasl_passwd").stat().st_mode) == 0o600
    assert stat.S_IMODE((plain.etc / "master.cf").stat().st_mode) == 0o640


def test_apply_backup_and_rollback_on_verify_failure(plain: Setup) -> None:
    original = (plain.etc / "master.cf").read_text()
    with pytest.raises(PostfixError, match="verification failed.*rolled back"):
        run_apply(plain, verify=lambda: False)
    assert (plain.etc / "master.cf").read_text() == original
    assert plain.seq() == [SHOW, CHECK, RESTART, ACTIVE_PF, RESTART_ASSP,
                           STOP, CHECK, RESTART, ACTIVE_PF]
    backups = list(plain.backup_root.iterdir())
    assert len(backups) == 1 and (backups[0] / "master.cf").read_text() == original


def test_apply_verify_exception_also_rolls_back(plain: Setup) -> None:
    original = (plain.etc / "master.cf").read_text()

    def boom() -> bool:
        raise OSError("connection refused")
    with pytest.raises(PostfixError, match="rolled back"):
        run_apply(plain, verify=boom)
    assert (plain.etc / "master.cf").read_text() == original


PRE = [SHOW]
STAGES = [
    # failing command -> exact commands that follow (rollback follows how far apply got)
    (CHECK, PRE + [CHECK]),  # before the restart: master.cf restored, nothing restarted
    (RESTART, PRE + [CHECK, RESTART, CHECK, RESTART, ACTIVE_PF]),  # ASSP-NG is not stopped
    (RESTART_ASSP, PRE + [CHECK, RESTART, ACTIVE_PF, RESTART_ASSP,
                          STOP, CHECK, RESTART, ACTIVE_PF]),  # the full rollback
]


@pytest.mark.parametrize(("failing", "expected"), STAGES)
def test_apply_failure_rolls_back_according_to_progress(plain: Setup, failing: list[str],
                                                        expected: list[list[str]]) -> None:
    original = (plain.etc / "master.cf").read_bytes()
    plain.run.fail.append(failing)
    with pytest.raises(PostfixError, match="simulated failure.*rolled back"):
        run_apply(plain)
    assert plain.seq() == expected
    assert (plain.etc / "master.cf").read_bytes() == original


def test_apply_postfix_not_active_after_restart_rolls_back(plain: Setup) -> None:
    plain.run.after_restart = "failed"
    with pytest.raises(PostfixError, match=r"postfix@-.*not active"):
        run_apply(plain)
    assert STOP not in plain.seq()


def test_apply_start_and_stop_both_failing_leaves_postfix_serving(plain: Setup) -> None:
    original = (plain.etc / "master.cf").read_bytes()
    plain.run.fail += [RESTART_ASSP, STOP]
    with pytest.raises(PostfixError, match="rolled back"):
        run_apply(plain)
    # the stop failed, but the unit is not loaded/active: that counts as stopped
    assert plain.seq() == [SHOW, CHECK, RESTART, ACTIVE_PF, RESTART_ASSP, STOP, ACTIVE_ASSP,
                           CHECK, RESTART, ACTIVE_PF]
    assert (plain.etc / "master.cf").read_bytes() == original
    assert plain.run.units["postfix@-"] == "active"


def test_apply_refuses_when_assp_ng_unit_is_not_loaded(plain: Setup) -> None:
    plain.run.load_state = "not-found"
    with pytest.raises(PostfixRefused, match="not-found"):
        run_apply(plain)
    assert plain.seq() == [SHOW] and not plain.backup_root.exists()


def test_reapply_on_integrated_host_leaves_assp_ng_running_on_verify_failure(
        plain: Setup) -> None:
    (plain.etc / "master.cf").write_text(make_plan(plain).master_text_new)
    state = plain.state()
    plan = build_plan(state, detect(state, FEATURES), [*BACKENDS, ("127.0.0.1", 10588, True)],
                      listener_ports=PORTS, today=NOW.date())
    assert "127.0.0.1:10588 inet" in plan.master_text_new
    plain.run.calls.clear()
    plain.run.units["assp-ng-proxy"] = "active"
    for mode in ("-M", "-P"):
        current = canned("plain", True, mode)
        plain.run.override[("current", mode)] = current
        plain.run.override[("planned", mode)] = current + (
            "127.0.0.1:10588 inet n - y - - smtpd\n" if mode == "-M" else
            "127.0.0.1:10588/inet/smtpd_sasl_auth_enable = yes\n")
    with pytest.raises(PostfixError, match="left running"):
        apply_plan(plan, state, backup_root=plain.backup_root, run=plain.run,
                   verify=lambda: False, etc=plain.etc, now=lambda: NOW, probe=plain.probe)
    assert plain.seq() == [SHOW, CHECK, RESTART, ACTIVE_PF, RESTART_ASSP,
                           CHECK, RESTART, ACTIVE_PF, ACTIVE_ASSP]  # no stop
    assert plain.run.units["assp-ng-proxy"] == "active"
    assert plain.probed == []  # nothing public to probe on an integrated host


def fold_into_previous_service(plan: Plan) -> Plan:
    """The reviewer's failure: a continuation line left live under a commented service folds
    into the service above it."""
    marker = "#submission inet n       -       y       -       -       smtpd\n"
    assert marker in plan.master_text_new
    text = plan.master_text_new.replace(
        marker, marker + "  -o smtpd_client_restrictions=reject\n")
    return Plan(text, plan.notes, plan.disabled, plan.added)


def fold_canned(setup: Setup) -> None:
    """What postconf prints for the folded text: the option sits under tlsproxy."""
    setup.run.override[("planned", "-P")] = (
        canned("postscreen-rspamd", True, "-P")
        + "tlsproxy/unix/smtpd_client_restrictions = reject\n")


def test_apply_guard_refuses_a_plan_that_postconf_reads_differently(rich: Setup) -> None:
    state = rich.state()
    bad = fold_into_previous_service(make_plan(rich))
    fold_canned(rich)
    with pytest.raises(PostfixRefused, match="tlsproxy/unix/smtpd_client_restrictions"):
        apply_plan(bad, state, backup_root=rich.backup_root, run=rich.run,
                   verify=lambda: True, etc=rich.etc, now=lambda: NOW, probe=rich.probe)
    assert (rich.etc / "master.cf").read_text() == state.master_text
    assert not rich.backup_root.exists()
    assert not any(c[0] in {"postfix", "systemctl"} and c != SHOW for c in rich.run.calls)


def test_apply_guard_accepts_the_correct_plan(rich: Setup) -> None:
    run_apply(rich)  # postconf -c <tmp> -M/-P differ only in disabled and added services
    guard_calls = [c for c in rich.run.calls if c[:2] == ["postconf", "-c"]]
    assert len(guard_calls) == 4 and guard_calls[0][2] == str(rich.etc)
    assert guard_calls[2][2] != str(rich.etc)


def test_apply_guard_passes_an_empty_value_override_in_a_disabled_service(
        upstream: Setup) -> None:
    """N1: postconf -P prints "name/type/param = " for an empty value (Debian's submission)."""
    assert "submission/inet/smtpd_recipient_restrictions = \n" in canned(
        "upstream-template", False, "-P")
    plan = make_plan(upstream)
    assert "#  -o smtpd_recipient_restrictions=\n" in plan.master_text_new
    run_apply(upstream, plan=plan)  # must not raise PostfixRefused
    assert (upstream.etc / "master.cf").read_text() == plan.master_text_new


def test_apply_guard_still_refuses_an_extra_option_folded_into_another_service(
        upstream: Setup) -> None:
    upstream.run.override[("planned", "-P")] = (
        canned("upstream-template", True, "-P")
        + "127.0.0.1:10025/inet/smtpd_client_restrictions = permit_sasl_authenticated,reject\n")
    with pytest.raises(PostfixRefused, match="10025/inet/smtpd_client_restrictions"):
        run_apply(upstream)
    assert not upstream.backup_root.exists()


def test_default_backup_root_is_outside_the_service_users_directories() -> None:
    """R58: root restores files from here, so the service user must not control it."""
    assert PostfixEnv().backup_root == Path("/var/backups/assp-ng")


def test_apply_refuses_a_symlinked_backup_root(plain: Setup, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o755)
    plain.backup_root.symlink_to(elsewhere)
    before = (plain.etc / "master.cf").read_text()
    with pytest.raises(PostfixError, match="symlink"):
        run_apply(plain)
    assert list(elsewhere.iterdir()) == []
    assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o755  # never chmod-ed through the link
    assert (plain.etc / "master.cf").read_text() == before
    assert RESTART not in plain.seq()


@pytest.mark.parametrize("component", ["root", "parent"])
def test_apply_refuses_a_group_writable_backup_path(plain: Setup, component: str) -> None:
    target = plain.backup_root if component == "root" else plain.tmp
    target.mkdir(exist_ok=True)
    target.chmod(0o775)
    before = (plain.etc / "master.cf").read_text()
    with pytest.raises(PostfixError, match="writable"):
        run_apply(plain)
    assert (plain.etc / "master.cf").read_text() == before
    assert not plain.backup_root.exists() or not any(plain.backup_root.iterdir())


def test_rollback_refuses_a_backup_under_a_group_writable_directory(plain: Setup) -> None:
    backup = run_apply(plain)
    plain.run.calls.clear()
    plain.backup_root.chmod(0o770)
    with pytest.raises(PostfixError, match="writable"):
        rollback(backup, plain.run, etc=plain.etc, probe=plain.probe)
    assert plain.run.calls == []


def test_rollback_refuses_a_symlinked_backup(plain: Setup, tmp_path: Path) -> None:
    backup = run_apply(plain)
    plain.run.calls.clear()
    link = tmp_path / "link-to-backup"
    link.symlink_to(backup)
    with pytest.raises(PostfixError, match="symlink"):
        rollback(link, plain.run, etc=plain.etc, probe=plain.probe)
    assert plain.run.calls == []


def test_check_trusted_dir_refuses_another_owner(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    check_trusted_dir(trusted)
    if os.geteuid() == 0:
        # As root (CI containers) every directory here is root-owned and therefore trusted, so
        # hand this one to a user that is neither root nor us.
        os.chown(trusted, 4242, -1)
        euid = 0
    else:
        euid = os.geteuid() + 1
    with pytest.raises(PostfixError, match="owned by"):
        check_trusted_dir(trusted, euid=euid)


def test_check_trusted_dir_accepts_a_sticky_world_writable_parent(tmp_path: Path) -> None:
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)  # like /tmp: others cannot replace our entries
    (sticky / "mine").mkdir(mode=0o700)
    check_trusted_dir(sticky / "mine")
    with pytest.raises(PostfixError, match="writable"):
        check_trusted_dir(sticky)  # the directory itself must not be writable by others


def test_apply_never_deletes_an_existing_backup_directory(plain: Setup) -> None:
    stale = plain.backup_root / "postfix-20261115T120000000000Z"
    stale.mkdir(parents=True)
    (stale / "precious").write_text("keep me")
    before = (plain.etc / "master.cf").read_text()
    with pytest.raises(PostfixError, match="exists"):
        run_apply(plain)
    assert (stale / "precious").read_text() == "keep me"
    assert (plain.etc / "master.cf").read_text() == before
    assert STOP not in plain.seq() and RESTART not in plain.seq()


def test_apply_refuses_ispconfig(tmp_path: Path) -> None:
    s = Setup(tmp_path, "ispconfig")
    s.ispconfig.mkdir()
    state = s.state()
    assert state.ispconfig
    plan = build_plan(state, detect(state, FEATURES), BACKENDS, listener_ports=PORTS,
                      today=NOW.date())
    before = (s.etc / "master.cf").read_text()
    s.run.calls.clear()
    with pytest.raises(RuntimeError, match="ISPConfig"):
        apply_plan(plan, state, backup_root=s.backup_root, run=s.run, verify=lambda: True,
                   etc=s.etc)
    assert s.seq() == [] and not s.backup_root.exists()
    assert (s.etc / "master.cf").read_text() == before


def test_apply_refuses_an_empty_plan(plain: Setup) -> None:
    state = plain.state()
    with pytest.raises(PostfixError, match="nothing to apply"):
        apply_plan(Plan(state.master_text, []), state, backup_root=plain.backup_root,
                   run=plain.run, verify=lambda: True, etc=plain.etc)
    assert not plain.backup_root.exists()


def test_rollback_order_stops_assp_restores_checks_restarts_never_starts(plain: Setup) -> None:
    original = (plain.etc / "master.cf").read_text()
    backup = run_apply(plain)
    assert (plain.etc / "master.cf").read_text() != original
    plain.run.calls.clear()
    plain.run.at_check = None
    note = rollback(backup, plain.run, etc=plain.etc, probe=plain.probe)
    assert plain.seq() == [STOP, CHECK, RESTART, ACTIVE_PF]
    assert RESTART_ASSP not in plain.run.calls and "not started" in note
    assert [t.port for t in plain.probed[0]] == [25]
    assert plain.run.at_check == original  # restored before "postfix check" ran
    assert (plain.etc / "master.cf").read_text() == original
    assert (plain.etc / "main.cf.link").is_symlink()


def test_rollback_failure_to_stop_assp_changes_nothing(plain: Setup) -> None:
    backup = run_apply(plain)
    new = (plain.etc / "master.cf").read_text()
    plain.run.calls.clear()
    plain.run.fail.append(STOP)
    with pytest.raises(PostfixError, match="stop assp-ng-proxy"):
        rollback(backup, plain.run, etc=plain.etc, probe=plain.probe)
    assert plain.run.calls == [STOP, ACTIVE_ASSP]
    assert (plain.etc / "master.cf").read_text() == new


def test_rollback_rejects_a_bad_backup(plain: Setup, tmp_path: Path) -> None:
    with pytest.raises(PostfixError, match="not a Postfix backup"):
        rollback(tmp_path / "nope", plain.run, etc=plain.etc, probe=plain.probe)
    assert plain.run.calls == []


def test_rollback_of_an_integrated_backup_leaves_assp_ng_running(plain: Setup) -> None:
    integrated = plain.backup_root / "postfix-20261101T000000000000Z"
    integrated.mkdir(parents=True)
    (integrated / "master.cf").write_text(make_plan(plain).master_text_new)
    plain.run.units["assp-ng-proxy"] = "active"
    note = rollback(integrated, plain.run, etc=plain.etc, probe=plain.probe)
    assert plain.seq() == [CHECK, RESTART, ACTIVE_PF, ACTIVE_ASSP]
    assert "left running" in note
    assert plain.probed == []


def test_rollback_of_an_integrated_backup_with_a_dead_assp_ng_says_nothing_serves(
        plain: Setup) -> None:
    """N2: "left running" must not be claimed for a proxy that is not running."""
    integrated = plain.backup_root / "postfix-20261101T000000000000Z"
    integrated.mkdir(parents=True)
    (integrated / "master.cf").write_text(make_plan(plain).master_text_new)
    plain.run.units["assp-ng-proxy"] = "failed"
    with pytest.raises(PostfixError, match=r"nothing serves.*failed.*" + str(integrated)):
        rollback(integrated, plain.run, etc=plain.etc, probe=plain.probe)
    assert plain.seq() == [CHECK, RESTART, ACTIVE_PF, ACTIVE_ASSP]


def test_reapply_on_integrated_host_with_failed_assp_restart_reports_nothing_serves(
        plain: Setup) -> None:
    (plain.etc / "master.cf").write_text(make_plan(plain).master_text_new)
    state = plain.state()
    plan = build_plan(state, detect(state, FEATURES), [*BACKENDS, ("127.0.0.1", 10588, True)],
                      listener_ports=PORTS, today=NOW.date())
    for mode in ("-M", "-P"):
        current = canned("plain", True, mode)
        plain.run.override[("current", mode)] = current
        plain.run.override[("planned", mode)] = current + (
            "127.0.0.1:10588 inet n - y - - smtpd\n" if mode == "-M" else
            "127.0.0.1:10588/inet/smtpd_sasl_auth_enable = yes\n")
    plain.run.calls.clear()
    plain.run.units["assp-ng-proxy"] = "active"
    plain.run.fail.append(RESTART_ASSP)  # the old proxy is dead, the new one did not start
    with pytest.raises(PostfixError, match=r"nothing serves.*rollback failed|rollback failed.*"
                                           r"nothing serves"):
        apply_plan(plan, state, backup_root=plain.backup_root, run=plain.run,
                   verify=lambda: True, etc=plain.etc, now=lambda: NOW, probe=plain.probe)
    assert plain.seq() == [SHOW, CHECK, RESTART, ACTIVE_PF, RESTART_ASSP,
                           CHECK, RESTART, ACTIVE_PF, ACTIVE_ASSP]


def test_cli_rollback_integrated_backup_with_dead_assp_ng_exits_1(
        plain: Setup, conf: Path, capsys: pytest.CaptureFixture[str]) -> None:
    d = plain.backup_root / "postfix-20261101T000000000000Z"
    d.mkdir(parents=True)
    (d / "master.cf").write_text(make_plan(plain).master_text_new)
    plain.run.units["assp-ng-proxy"] = "failed"
    assert cli(plain, conf, "rollback") == 1
    err = capsys.readouterr().err
    assert "nothing serves" in err and "postfix-20261101T000000000000Z" in err


def test_rollback_reports_postfix_that_is_not_serving(plain: Setup) -> None:
    backup = run_apply(plain)
    plain.probe_ok = False
    with pytest.raises(PostfixError, match=str(backup)):
        rollback(backup, plain.run, etc=plain.etc, probe=plain.probe)
    plain.probe_ok = True
    plain.run.after_restart = "failed"
    with pytest.raises(PostfixError, match=r"postfix@-.*not active.*" + str(backup)):
        rollback(backup, plain.run, etc=plain.etc, probe=plain.probe)


# --- default verification ----------------------------------------------------------------

class FakeSmtp:
    def __init__(self, xclient: bool = True, ehlo_code: int = 250) -> None:
        self.xclient = xclient
        self.ehlo_code = ehlo_code
        self.closed = False

    def ehlo(self, name: str = "") -> tuple[int, bytes]:
        return self.ehlo_code, b"mail.example.org"

    def has_extn(self, name: str) -> bool:
        return self.xclient and name.lower() == "xclient"

    def quit(self) -> tuple[int, bytes]:
        self.closed = True
        return 221, b"bye"

    def close(self) -> None:
        self.closed = True


class Clock:
    def __init__(self) -> None:
        self.t = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds


TARGETS = [Target("127.0.0.1", 25, False), Target("127.0.0.1", 465, True)]


def verifier(connect: Callable[..., FakeSmtp], clock: Clock,
             report: Callable[[str], None] = lambda text: None) -> Callable[[], bool]:
    return make_verifier(TARGETS, BACKENDS, connect=connect,  # type: ignore[arg-type]
                         sleep=clock.sleep, monotonic=clock.monotonic, report=report)


def test_verify_checks_every_listener_and_backend() -> None:
    seen: list[tuple[str, int, bool, float]] = []

    def connect(host: str, port: int, tls: bool, timeout: float) -> FakeSmtp:
        seen.append((host, port, tls, timeout))
        return FakeSmtp()
    assert verifier(connect, Clock())() is True
    assert seen == [("127.0.0.1", 25, False, 5.0), ("127.0.0.1", 465, True, 5.0),
                    ("127.0.0.1", 10125, False, 5.0), ("127.0.0.1", 10587, False, 5.0)]


def test_verify_retries_while_assp_ng_starts() -> None:
    attempts = {"n": 0}

    def connect(host: str, port: int, tls: bool, timeout: float) -> FakeSmtp:
        if port == 25:
            attempts["n"] += 1
            if attempts["n"] < 4:
                raise ConnectionRefusedError("not yet")
        return FakeSmtp()
    clock = Clock()
    assert verifier(connect, clock)() is True
    assert attempts["n"] == 4 and len(clock.slept) == 3


def test_verify_gives_up_after_about_ten_seconds_and_says_why() -> None:
    def connect(host: str, port: int, tls: bool, timeout: float) -> FakeSmtp:
        return FakeSmtp(xclient=port < 10000)
    clock, reports = Clock(), []
    assert verifier(connect, clock, reports.append)() is False
    assert 9.0 <= clock.t <= 12.0
    assert "XCLIENT" in reports[-1] and "10125" in reports[-1]


def test_verify_rejects_bad_ehlo_and_smtp_errors() -> None:
    clock = Clock()
    assert verifier(lambda h, p, t, to: FakeSmtp(ehlo_code=451), clock)() is False

    def banner_error(host: str, port: int, tls: bool, timeout: float) -> FakeSmtp:
        raise smtplib.SMTPConnectError(554, b"no service")
    assert verifier(banner_error, Clock())() is False


# --- CLI ---------------------------------------------------------------------------------

CONFIG = """\
[[listener]]
name = "inbound"
kind = "smtp"
port = 25
backend = "127.0.0.1:10125"

[[listener]]
name = "submission"
kind = "submission"
port = 587
backend = "127.0.0.1:10587"

[[listener]]
name = "smtps"
kind = "submissions"
port = 465
backend = "127.0.0.1:10587"

[[tls.certificate]]
name = "main"
hostnames = ["mail.example.org"]
cert = "/etc/c.pem"
key = "/etc/k.pem"
"""


@pytest.fixture
def conf(tmp_path: Path) -> Path:
    d = tmp_path / "assp-conf"
    d.mkdir()
    (d / "assp-ng.toml").write_text(CONFIG)
    (d / "default.toml").write_text("")
    return d


def cli(setup: Setup, conf: Path, *argv: str, **over: object) -> int:
    return main(["--config-dir", str(conf), "postfix", *argv],
                deps=Deps(postfix=setup.env(**over)))


def test_cli_check_notes_trusted_networks_missing_from_mynetworks(
        plain: Setup, conf: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """R67: with XCLIENT Postfix sees the real client, so a trusted network that should
    relay without AUTH must be in mynetworks too. The note changes nothing."""
    (conf / "trusted-networks.txt").write_text(
        "# office\n192.0.2.0/24\n127.0.0.0/16\n2001:db8::/48\n::1\n")
    before = (plain.etc / "master.cf").read_text()
    assert cli(plain, conf, "check") == 0
    out = capsys.readouterr().out
    [note] = [line for line in out.splitlines() if "mynetworks" in line]
    assert note.startswith("note: ")
    assert "192.0.2.0/24" in note and "2001:db8::/48" in note
    assert "127.0.0.0/16" not in note and "::1" not in note  # covered by mynetworks
    assert "XCLIENT" in out
    assert plain.run.calls == [["postconf", "-n"], ["ss", "-Hltn"]]  # read-only
    assert (plain.etc / "master.cf").read_text() == before


def test_cli_check_without_missing_trusted_networks_has_no_note(
        plain: Setup, conf: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(plain, conf, "check") == 0
    assert "mynetworks" not in capsys.readouterr().out
    (conf / "trusted-networks.txt").write_text("127.0.0.1\n")
    assert cli(plain, conf, "check") == 0
    assert "mynetworks" not in capsys.readouterr().out


@pytest.mark.parametrize("mynetworks, missing, unchecked", [
    ("127.0.0.0/8 [::1]/128", ["192.0.2.0/24", "2001:db8::/48"], []),
    ("127.0.0.0/8, 192.0.2.0/23,[2001:db8::]/32", [], []),
    ("192.0.2.7 hash:/etc/postfix/network_table", ["192.0.2.0/24", "2001:db8::/48"],
     ["hash:/etc/postfix/network_table"]),
    ("", ["192.0.2.0/24", "2001:db8::/48"], []),
])
def test_trusted_missing_from_mynetworks(mynetworks: str, missing: list[str],
                                         unchecked: list[str]) -> None:
    trusted = [ip_network("192.0.2.0/24"), ip_network("2001:db8::/48")]
    found, skipped = trusted_missing_from_mynetworks(trusted, mynetworks)
    assert [str(net) for net in found] == missing
    assert skipped == unchecked


def test_cli_check_prints_findings_and_status(rich: Setup, conf: Path,
                                              capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(rich, conf, "check") == 0
    out = capsys.readouterr().out
    assert "can disable" in out and "keep for now" in out
    assert "postgrey" in out and "rspamd" in out
    assert DKIM_NOTE in out
    assert rich.run.calls == [["postconf", "-n"], ["ss", "-Hltn"]]  # read-only


def test_cli_check_failure_exits_1(plain: Setup, conf: Path,
                                   capsys: pytest.CaptureFixture[str]) -> None:
    plain.run.fail.append(["ss", "-Hltn"])
    assert cli(plain, conf, "check") == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err


def test_cli_plan_prints_diff_and_changes_nothing(plain: Setup, conf: Path,
                                                  capsys: pytest.CaptureFixture[str]) -> None:
    before = (plain.etc / "master.cf").read_text()
    assert cli(plain, conf, "plan") == 0
    out = capsys.readouterr().out
    assert "+# disabled by assp-ng 2026-11-15" in out
    assert "+127.0.0.1:10125 inet n - y - - smtpd" in out
    assert (plain.etc / "master.cf").read_text() == before
    assert not plain.backup_root.exists()
    assert ["systemctl", "restart", "postfix"] not in plain.run.calls


def test_cli_plan_port_conflict_exits_2(plain: Setup, conf: Path,
                                        capsys: pytest.CaptureFixture[str]) -> None:
    plain.run.ss_text += "LISTEN 0 100 127.0.0.1:10125 0.0.0.0:*\n"
    assert cli(plain, conf, "plan") == 2
    assert "10125" in capsys.readouterr().err


def test_cli_plan_ispconfig_warns_but_works(tmp_path: Path, conf: Path,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    s = Setup(tmp_path, "ispconfig")
    s.ispconfig.mkdir()
    assert cli(s, conf, "plan") == 0
    assert "ISPConfig" in capsys.readouterr().err
    assert cli(s, conf, "check") == 0


def test_cli_apply_ispconfig_exits_2_and_touches_nothing(tmp_path: Path, conf: Path,
                                                         capsys: pytest.CaptureFixture[str]
                                                         ) -> None:
    s = Setup(tmp_path, "ispconfig")
    s.ispconfig.mkdir()
    before = (s.etc / "master.cf").read_text()
    assert cli(s, conf, "apply", "--yes") == 2
    assert "ISPConfig" in capsys.readouterr().err
    assert (s.etc / "master.cf").read_text() == before and not s.backup_root.exists()
    assert not any(c[0] in {"postfix", "systemctl"} for c in s.run.calls)


def test_cli_apply_without_tty_and_without_yes_exits_2(plain: Setup, conf: Path,
                                                       capsys: pytest.CaptureFixture[str]) -> None:
    before = (plain.etc / "master.cf").read_text()
    assert cli(plain, conf, "apply", isatty=lambda: False) == 2
    assert "--yes" in capsys.readouterr().err
    assert (plain.etc / "master.cf").read_text() == before and not plain.backup_root.exists()


def test_cli_apply_declined_changes_nothing(plain: Setup, conf: Path) -> None:
    before = (plain.etc / "master.cf").read_text()
    assert cli(plain, conf, "apply", confirm=lambda q: False) == 1
    assert (plain.etc / "master.cf").read_text() == before and not plain.backup_root.exists()


def test_cli_apply_yes_applies_and_verifies(plain: Setup, conf: Path,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[tuple[list[Target], list[tuple[str, int, bool]]]] = []

    def factory(targets: Sequence[Target], backends: Sequence[tuple[str, int, bool]]
                ) -> Callable[[], bool]:
        seen.append((list(targets), list(backends)))
        return lambda: True
    assert cli(plain, conf, "apply", "--yes", isatty=lambda: False, verify_factory=factory) == 0
    assert "127.0.0.1:10125 inet" in (plain.etc / "master.cf").read_text()
    assert [t.port for t in seen[0][0]] == [25, 587, 465]
    assert [t.tls for t in seen[0][0]] == [False, False, True]
    assert seen[0][1] == BACKENDS
    assert plain.seq()[-3:] == [RESTART, ACTIVE_PF, RESTART_ASSP]
    assert "backup" in capsys.readouterr().out


def test_cli_apply_asks_for_confirmation_on_a_tty(plain: Setup, conf: Path) -> None:
    asked: list[str] = []
    assert cli(plain, conf, "apply", confirm=lambda q: asked.append(q) or True) == 0
    assert len(asked) == 1


def test_cli_apply_verify_failure_rolls_back_exit_1(plain: Setup, conf: Path,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    before = (plain.etc / "master.cf").read_text()
    assert cli(plain, conf, "apply", "--yes", verify_factory=lambda t, b: lambda: False) == 1
    err = capsys.readouterr().err
    assert "rolled back" in err and "systemctl start assp-ng-proxy" in err
    assert (plain.etc / "master.cf").read_text() == before
    assert plain.seq()[-4:] == [STOP, CHECK, RESTART, ACTIVE_PF]


def test_cli_apply_idempotent_second_run_is_a_noop(plain: Setup, conf: Path,
                                                   capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(plain, conf, "apply", "--yes") == 0
    capsys.readouterr()
    plain.run.calls.clear()
    assert cli(plain, conf, "apply", "--yes") == 0
    assert "nothing to do" in capsys.readouterr().out
    assert not any(c[0] == "systemctl" for c in plain.run.calls)


def test_cli_apply_needs_a_valid_config(plain: Setup, tmp_path: Path,
                                        capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(plain, tmp_path / "missing", "apply", "--yes") == 2
    assert not plain.backup_root.exists()
    assert "configuration" in capsys.readouterr().err


def make_backup(setup: Setup, name: str, tag: str) -> Path:
    d = setup.backup_root / name
    d.mkdir(parents=True)
    # a pre-integration master.cf (public listener present) that says which backup it is
    (d / "master.cf").write_text((FIXTURES / "plain" / "master.cf").read_text() + f"# {tag}\n")
    return d


def test_cli_rollback_picks_the_newest_backup(plain: Setup, conf: Path,
                                              capsys: pytest.CaptureFixture[str]) -> None:
    make_backup(plain, "postfix-20261101T000000000000Z", "old")
    make_backup(plain, "postfix-20261114T100000000000Z", "newest")
    make_backup(plain, "other-20261115T000000000000Z", "unrelated")
    assert cli(plain, conf, "rollback") == 0
    assert (plain.etc / "master.cf").read_text().endswith("# newest\n")
    assert plain.seq() == [STOP, CHECK, RESTART, ACTIVE_PF]
    assert "not started" in capsys.readouterr().out


def test_cli_rollback_ignores_names_and_partial_directories(plain: Setup, conf: Path) -> None:
    make_backup(plain, "postfix-20261101T000000000000Z", "good")
    make_backup(plain, "postfix-manual", "manual")
    make_backup(plain, "postfix-20261114T100000000000Z.partial", "partial")
    make_backup(plain, "postfix-99991231T235959999999Z-old", "suffix")
    (plain.backup_root / "postfix-20261114T110000000000Z").mkdir()  # no master.cf: incomplete
    assert cli(plain, conf, "rollback") == 0
    assert (plain.etc / "master.cf").read_text().endswith("# good\n")


def test_cli_rollback_explicit_backup(plain: Setup, conf: Path) -> None:
    chosen = make_backup(plain, "postfix-20261101T000000000000Z", "old")
    make_backup(plain, "postfix-20261114T100000000000Z", "newest")
    assert cli(plain, conf, "rollback", "--backup", str(chosen)) == 0
    assert (plain.etc / "master.cf").read_text().endswith("# old\n")


def test_cli_rollback_refuses_a_symlinked_backup_root(
        plain: Setup, conf: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    elsewhere = tmp_path / "planted"
    elsewhere.mkdir()
    (elsewhere / "postfix-20261101T000000000000Z").mkdir()
    (elsewhere / "postfix-20261101T000000000000Z" / "master.cf").write_text("# planted\n")
    plain.backup_root.symlink_to(elsewhere)
    before = (plain.etc / "master.cf").read_text()
    assert cli(plain, conf, "rollback") == 1
    assert "symlink" in capsys.readouterr().err
    assert (plain.etc / "master.cf").read_text() == before
    assert plain.run.calls == []


def test_cli_rollback_without_backup_exits_1(plain: Setup, conf: Path,
                                             capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(plain, conf, "rollback") == 1
    assert "no backup" in capsys.readouterr().err
    assert plain.run.calls == []


def test_cli_rollback_failure_reports_the_backup_and_exits_1(
        plain: Setup, conf: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_backup(plain, "postfix-20261101T000000000000Z", "old")
    plain.probe_ok = False
    assert cli(plain, conf, "rollback") == 1
    assert "postfix-20261101T000000000000Z" in capsys.readouterr().err


def test_cli_apply_refuses_when_listeners_do_not_cover_public_services(
        rich: Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    only25 = tmp_path / "only25"
    only25.mkdir()
    (only25 / "assp-ng.toml").write_text(CONFIG.split("\n[[listener]]\nname = \"submission\"")[0])
    (only25 / "default.toml").write_text("")
    assert cli(rich, only25, "apply", "--yes") == 2
    err = capsys.readouterr().err
    assert "submission" in err and "smtps" in err
    assert not rich.backup_root.exists()


def test_cli_preflight_unit_not_loaded_exits_2(plain: Setup, conf: Path) -> None:
    plain.run.load_state = "not-found"
    assert cli(plain, conf, "apply", "--yes") == 2
    assert not plain.backup_root.exists()


def test_cli_apply_guard_refusal_exits_2(rich: Setup, conf: Path,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
    fold_canned(rich)
    import asspng.cli.postfix_cmd as cmd
    real = cmd.build_plan
    monkeypatch.setattr(cmd, "build_plan",
                        lambda *a, **kw: fold_into_previous_service(real(*a, **kw)))
    assert cli(rich, conf, "apply", "--yes") == 2
    assert not rich.backup_root.exists()


# --- C1, I2, I3, I7, I8: parsing and planning --------------------------------------------

@pytest.fixture
def upstream(tmp_path: Path) -> Setup:
    return Setup(tmp_path / "up", "upstream-template")


def test_parse_follows_postfix_line_continuation(upstream: Setup) -> None:
    text = (upstream.etc / "master.cf").read_text()
    services = {s.name: s for s in parse_master(text)}
    sub = services["submission"]
    lines = text.split("\n")
    assert lines[sub.line_end - 1] == "  -o milter_macro_daemon_name=ORIGINATING"
    assert sub.options["milter_macro_daemon_name"] == "ORIGINATING"
    assert sub.options["smtpd_client_restrictions"] == "permit_sasl_authenticated,reject"
    assert len(sub.options) == 6
    assert sub.options["smtpd_recipient_restrictions"] == ""
    assert services["127.0.0.1:10025"].options == {
        "content_filter": "", "local_recipient_maps": "",
        "smtpd_recipient_restrictions": "permit_mynetworks,reject"}
    assert services["submissions"].options["smtpd_tls_wrappermode"] == "yes"


def test_plan_comments_the_whole_block_including_inner_comments_and_blanks(
        upstream: Setup) -> None:
    plan = make_plan(upstream)
    new = plan.master_text_new.split("\n")
    start = new.index("#submission inet n       -       y       -       -       smtpd")
    block = new[start:new.index("#submissions     inet  n       -       y       -       -"
                                "       smtpd")]
    assert "#  -o milter_macro_daemon_name=ORIGINATING" in block
    assert "#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject" in block
    assert "#" in block  # the blank line inside the block
    # the amavis reinjection listener above keeps exactly its own options
    after = {s.name: s for s in parse_master(plan.master_text_new)}
    assert after["127.0.0.1:10025"].options == {
        "content_filter": "", "local_recipient_maps": "",
        "smtpd_recipient_restrictions": "permit_mynetworks,reject"}
    assert "submission" not in after and "submissions" not in after
    # and apply's postconf guard agrees
    run_apply(upstream)


def test_plan_lists_every_dropped_override(upstream: Setup) -> None:
    notes = "\n".join(make_plan(upstream).notes)
    assert "'submission'" in notes and "milter_macro_daemon_name=ORIGINATING" in notes
    assert "smtpd_tls_wrappermode=yes" in notes and "'submissions'" in notes


def test_submissions_and_ssmtp_names_are_public_listeners(upstream: Setup) -> None:
    findings = detect(upstream.state(), FEATURES)
    assert sorted(f.description for f in by_kind(findings, "listener")) == [
        "public smtpd service 'smtp' on port 25",
        "public smtpd service 'submission' on port 587",
        "public smtpd service 'submissions' on port 465"]
    ssmtp = parse_master("ssmtp inet n - y - - smtpd\n")
    from asspng.postfix.inspect import service_port
    assert service_port(ssmtp[0]) == 465


def test_plan_refuses_public_services_no_listener_covers(upstream: Setup) -> None:
    state = upstream.state()
    with pytest.raises(ValueError, match=r"submission.*submissions|uncovered"):
        build_plan(state, detect(state, FEATURES), BACKENDS, listener_ports={25})
    # without the listeners feature nothing is disabled, so nothing is refused
    build_plan(state, detect(state, frozenset()), BACKENDS, listener_ports={25})


def test_plan_ipv6_backend_is_bracketed(plain: Setup) -> None:
    state = plain.state()
    plan = build_plan(state, detect(state, FEATURES), [("::1", 10125, False),
                                                       ("[::1]", 10587, True)],
                      listener_ports=PORTS, today=NOW.date())
    new = plan.master_text_new
    assert "[::1]:10125 inet n - y - - smtpd\n  -o smtpd_sasl_auth_enable=no\n" \
           "  -o smtpd_authorized_xclient_hosts=[::1]\n" in new
    assert "[::1]:10587 inet" in new


def test_plan_localhost_backend_maps_to_127_0_0_1(plain: Setup) -> None:
    state = plain.state()
    plan = build_plan(state, [], [("localhost", 10125, False)], listener_ports=PORTS)
    assert "127.0.0.1:10125 inet" in plan.master_text_new
    assert "smtpd_authorized_xclient_hosts=127.0.0.1\n" in plan.master_text_new


@pytest.mark.parametrize("host", ["192.0.2.7", "mail.example.org", "0.0.0.0", "::",
                                  "127.0.0.1\n  -o smtpd_authorized_xclient_hosts=0.0.0.0",
                                  "127.0.0.1 ", ""])
def test_plan_refuses_a_backend_that_is_not_loopback(plain: Setup, host: str) -> None:
    state = plain.state()
    with pytest.raises(ValueError, match="loopback"):
        build_plan(state, [], [(host, 10125, False)], listener_ports=PORTS)


def rich_with_filter_override(setup: Setup) -> PostfixState:
    path = setup.etc / "master.cf"
    path.write_text(path.read_text().replace(
        "  -o smtpd_tls_auth_only=yes\n", "  -o smtpd_tls_auth_only=yes\n"
        "  -o milter_macro_daemon_name=ORIGINATING\n"))
    return setup.state()


def test_plan_refuses_dropping_a_filter_override_while_a_dkim_signer_runs(rich: Setup) -> None:
    state = rich_with_filter_override(rich)
    assert state.rspamd_dkim
    with pytest.raises(ValueError, match="--drop-overrides"):
        build_plan(state, detect(state, FEATURES), BACKENDS, listener_ports=PORTS)
    plan = build_plan(state, detect(state, FEATURES), BACKENDS, listener_ports=PORTS,
                      drop_overrides=True)
    assert "milter_macro_daemon_name=ORIGINATING" in "\n".join(plan.notes)


def test_plan_drops_a_filter_override_without_a_signer_with_a_note(upstream: Setup) -> None:
    state = upstream.state()
    assert not (state.rspamd_dkim or state.amavis_dkim)
    plan = build_plan(state, detect(state, FEATURES), BACKENDS, listener_ports=PORTS)
    assert "milter_macro_daemon_name=ORIGINATING" in "\n".join(plan.notes)


def test_cli_drop_overrides_flag(rich: Setup, conf: Path,
                                 capsys: pytest.CaptureFixture[str]) -> None:
    rich_with_filter_override(rich)
    assert cli(rich, conf, "plan") == 2
    assert "--drop-overrides" in capsys.readouterr().err
    assert cli(rich, conf, "plan", "--drop-overrides") == 0
    assert cli(rich, conf, "apply", "--yes") == 2
    assert cli(rich, conf, "apply", "--yes", "--drop-overrides") == 0


def test_crlf_and_latin2_bytes_survive_byte_for_byte(plain: Setup) -> None:
    old = (FIXTURES / "plain" / "master.cf").read_bytes().replace(b"\n", b"\r\n")
    old = old.replace(b"#               (yes)   (yes)   (no)    (never) (100)",
                      b"# P\xe8kn\xfd koment\xe1\xf8 \x85 \xe2\x80\xa8 x")
    old = old.replace(b"smtp      inet  n       -       y       -       -       smtpd\r\n",
                      b"smtp      inet  n       -       y       -       -       smtpd\r\n"
                      b"  -o smtpd_banner=\xa9 mail\r\n", 1)
    (plain.etc / "master.cf").write_bytes(old)
    state = plain.state()
    plan = build_plan(state, detect(state, FEATURES), BACKENDS, listener_ports=PORTS,
                      today=NOW.date())
    run_apply(plain, plan=plan)
    new = (plain.etc / "master.cf").read_bytes()
    assert b"# P\xe8kn\xfd koment\xe1\xf8 \x85 \xe2\x80\xa8 x\r\n" in new
    assert (b"# disabled by assp-ng 2026-11-15\r\n#smtp      inet  n       -       y       -"
            b"       -       smtpd\r\n#  -o smtpd_banner=\xa9 mail\r\n") in new
    assert new.count(b"\r\n") == new.count(b"\n")  # no bare LF was introduced
    # untouched lines are identical, and the backup holds the original bytes
    backup = next(plain.backup_root.iterdir())
    assert (backup / "master.cf").read_bytes() == old
    assert new.startswith(old[:old.index(b"smtp      inet")])


def test_diff_of_non_utf8_master_does_not_crash_the_cli(plain: Setup, conf: Path,
                                                        capsys: pytest.CaptureFixture[str]
                                                        ) -> None:
    (plain.etc / "master.cf").write_bytes(
        (FIXTURES / "plain" / "master.cf").read_bytes().replace(b"(yes)   (yes)", b"\xe8"))
    assert cli(plain, conf, "plan") == 0
    assert "+# disabled by assp-ng" in capsys.readouterr().out
