# SPDX-License-Identifier: GPL-3.0-or-later
import os
import stat
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from asspng.cli.config_cmd import DEFAULT_DIR, Deps
from asspng.config import editor
from asspng.cli.main import main
from asspng.cli.probes import Probes, ProbeError
from asspng.cli.scope import ScopeError, parse_scope
from asspng.config.loader import load_config
from asspng.config.model import CertificateConfig, ListenerConfig

# Remote: needs TLS and a password (ruling R66).
SECRET_URL = "mysql+pymysql://asspng:hunter2@db.example/asspng?ssl_ca=/etc/ssl/certs/ca.pem"
DB_TOML = f'[database]\nurl = "{SECRET_URL}"\n'


class Fakes:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.active = True
        self.reload_rc = 0
        self.audits: list[dict[str, object]] = []
        self.audit_error: Exception | None = None
        self.euid = 0

    def runner(self, cmd: Sequence[str]) -> int:
        self.commands.append(list(cmd))
        if "is-active" in cmd:
            return 0 if self.active else 3
        return self.reload_rc

    def audit(self, url: str, **kwargs: object) -> None:
        if self.audit_error is not None:
            raise self.audit_error
        self.audits.append({"url": url, **kwargs})

    def deps(self, probes: Probes | None = None) -> Deps:
        return Deps(probes=probes or Probes(), runner=self.runner, audit=self.audit,
                    geteuid=lambda: self.euid, actor=lambda: "tester")


@pytest.fixture
def fakes() -> Fakes:
    return Fakes()


SYSTEM_DIR: list[Path] = []


@pytest.fixture
def run(etc_dir: Path, fakes: Fakes) -> Callable[..., int]:
    SYSTEM_DIR[:] = [etc_dir]

    def call(*argv: str, probes: Probes | None = None) -> int:
        return main(["--config-dir", str(etc_dir), *argv], deps=fakes.deps(probes))
    return call


def snapshot_of(directory: Path) -> dict[str, bytes]:
    return {str(p.relative_to(directory)): p.read_bytes()
            for p in sorted(directory.rglob("*"))
            if p.is_file() and p.name != ".assp-ng.lock"}


def test_set_preserves_comments(etc_dir: Path, run: Callable[..., int]) -> None:
    (etc_dir / "default.toml").write_text("# my policy\n[scoring]\nlimit = 50  # keep\n")
    assert run("config", "set", "scoring.limit", "60") == 0
    text = (etc_dir / "default.toml").read_text()
    assert "# my policy" in text and "# keep" in text and "limit = 60" in text
    assert load_config(etc_dir).default_layer["scoring.limit"] == 60


def test_set_creates_user_file_normalized(etc_dir: Path, run: Callable[..., int]) -> None:
    assert run("config", "set", "testmode", "true", "user:Jano@Example.COM") == 0
    path = etc_dir / "user.d" / "jano@example.com.toml"
    assert path.read_text() == "testmode = true\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert run("config", "set", "scoring.limit", "80", "domain:BÜCHER.example") == 0
    assert (etc_dir / "domain.d" / "xn--bcher-kva.example.toml").is_file()
    assert load_config(etc_dir).user_layers["jano@example.com"]["testmode"] is True


def test_set_rejects_wrong_level(etc_dir: Path, run: Callable[..., int],
                                 capsys: pytest.CaptureFixture[str]) -> None:
    before = snapshot_of(etc_dir)
    assert run("config", "set", "redis.url", "redis://x/1", "user:a@example.com") == 2
    assert run("config", "set", "scoring.limit", "60", "sys") == 2
    assert run("config", "set", "redis.url", "redis://x/1") == 2
    assert "redis.url" in capsys.readouterr().err
    assert snapshot_of(etc_dir) == before and not (etc_dir / "user.d").exists()


def test_set_rejects_invalid_value_file_unchanged(etc_dir: Path, run: Callable[..., int],
                                                  capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "default.toml").write_text("[scoring]\nlimit = 50\n")
    before = snapshot_of(etc_dir)
    assert run("config", "set", "scoring.limit", "lots") == 2
    assert run("config", "set", "scoring.limit", "-3") == 2
    assert run("config", "set", "nonsense.key", "1") == 2
    # warn above limit: passes the type check, fails the cross-file validation
    assert run("config", "set", "scoring.warn", "99") == 2
    assert "scoring.warn" in capsys.readouterr().err
    assert snapshot_of(etc_dir) == before


def test_validation_errors_name_the_real_file_not_the_temp_copy(
        etc_dir: Path, run: Callable[..., int], capsys: pytest.CaptureFixture[str]) -> None:
    assert run("config", "set", "scoring.warn", "99") == 2
    err = capsys.readouterr().err
    assert str(etc_dir / "default.toml") in err and "assp-ng-config-" not in err


def test_unset(etc_dir: Path, run: Callable[..., int]) -> None:
    (etc_dir / "default.toml").write_text("[scoring]\nlimit = 60\n")
    assert run("config", "unset", "scoring.limit") == 0
    assert "limit" not in (etc_dir / "default.toml").read_text()
    assert (etc_dir / "default.toml.bak").read_text() == "[scoring]\nlimit = 60\n"
    assert run("config", "unset", "scoring.limit") == 0  # nothing to do
    assert run("config", "unset", "redis.url", "domain:example.com") == 2


def test_show_reports_source(etc_dir: Path, run: Callable[..., int],
                             capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "default.toml").write_text("[scoring]\nlimit = 60\nwarn = 40\n")
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml").write_text("[scoring]\nlimit = 80\n")
    (etc_dir / "user.d").mkdir()
    (etc_dir / "user.d" / "a@example.com.toml").write_text("[scoring]\nlimit = 99\n")
    capsys.readouterr()
    assert run("config", "show", "scoring.limit", "user:A@example.com") == 0
    assert capsys.readouterr().out == "scoring.limit = 99  (user)\n"
    assert run("config", "show", "scoring.limit", "domain:example.com") == 0
    assert capsys.readouterr().out == "scoring.limit = 80  (domain)\n"
    assert run("config", "show", "scoring.warn", "user:a@example.com") == 0
    assert capsys.readouterr().out == "scoring.warn = 40  (default)\n"
    assert run("config", "show", "scoring.add_header") == 0
    assert capsys.readouterr().out == "scoring.add_header = true  (built-in)\n"
    assert run("config", "show", "scoring.limit", "sys") == 2
    assert run("config", "show", "limits.auth.window", "user:a@example.com") == 2
    assert run("config", "show", "no.such.key") == 2


def test_show_whole_scope_and_system_inference(etc_dir: Path, run: Callable[..., int],
                                               capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + '[limits.auth]\nwindow = "1h"\n')
    capsys.readouterr()
    assert run("config", "show", "limits.auth.window") == 0
    assert capsys.readouterr().out == 'limits.auth.window = "1h"  (system)\n'
    assert run("config", "show", "sys") == 0
    out = capsys.readouterr().out
    assert 'penalty_box.ladder = ["1d", "7d", "30d"]  (built-in)' in out
    assert "scoring.limit" not in out
    assert run("config", "show") == 0
    out = capsys.readouterr().out
    assert "scoring.limit = 50  (built-in)" in out and "redis.url" not in out


def test_show_masks_database_url(etc_dir: Path, run: Callable[..., int],
                                 capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + DB_TOML)
    capsys.readouterr()
    assert run("config", "show", "database.url") == 0
    out = capsys.readouterr().out
    assert "hunter2" not in out
    assert out == ('database.url = "mysql+pymysql://asspng:***@db.example/asspng'
                   '?ssl_ca=/etc/ssl/certs/ca.pem"  (system)\n')
    assert run("config", "show", "sys") == 0
    assert "hunter2" not in capsys.readouterr().out


def test_show_masks_secret_query_parameters_of_the_database_url(
        etc_dir: Path, run: Callable[..., int], capsys: pytest.CaptureFixture[str]) -> None:
    """Drivers also take passwords as query parameters; only known harmless ones are shown."""
    url = ("mysql+pymysql://asspng:hunter2@db.example/asspng?ssl_ca=/etc/ssl/certs/ca.pem"
           "&ssl_key_password=QuerySecret1&password=QuerySecret2&custom=QuerySecret3")
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + f'[database]\nurl = "{url}"\n')
    capsys.readouterr()
    assert run("config", "show", "database.url") == 0
    out = capsys.readouterr().out
    assert "QuerySecret" not in out and "hunter2" not in out
    assert out == ('database.url = "mysql+pymysql://asspng:***@db.example/asspng'
                   '?custom=***&password=***&ssl_ca=/etc/ssl/certs/ca.pem'
                   '&ssl_key_password=***"  (system)\n')
    assert run("config", "show", "sys") == 0
    assert "QuerySecret" not in capsys.readouterr().out


def test_show_masks_secret_query_parameters_of_the_redis_url(
        etc_dir: Path, run: Callable[..., int], capsys: pytest.CaptureFixture[str]) -> None:
    url = "rediss://:hunter2@redis.example:6380/0?ssl_cert_reqs=required&password=QuerySecret4"
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + f'[redis]\nurl = "{url}"\n')
    capsys.readouterr()
    assert run("config", "show", "redis.url") == 0
    out = capsys.readouterr().out
    assert "QuerySecret" not in out and "hunter2" not in out
    assert out == ('redis.url = "rediss://:***@redis.example:6380/0'
                   '?password=***&ssl_cert_reqs=required"  (system)\n')


def test_set_database_url_never_echoes_it(etc_dir: Path, run: Callable[..., int],
                                          fakes: Fakes,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    assert run("config", "set", "database.url", SECRET_URL, "sys") == 0
    captured = capsys.readouterr()
    assert "hunter2" not in captured.out + captured.err
    assert fakes.audits[0]["details"] == {"key": "database.url", "scope": "sys", "value": "***"}
    assert run("config", "set", "database.url", "not a url", "sys") == 2
    captured = capsys.readouterr()
    assert "not a url" not in captured.out + captured.err


def test_init_refuses_overwrite(etc_dir: Path, run: Callable[..., int]) -> None:
    (etc_dir / "default.toml").write_text("testmode = true\n")
    assert run("config", "init") == 1
    assert (etc_dir / "default.toml").read_text() == "testmode = true\n"
    assert run("config", "init", "--force") == 0
    assert (etc_dir / "default.toml.bak").read_text() == "testmode = true\n"
    assert "scoring" in (etc_dir / "default.toml").read_text()
    assert load_config(etc_dir)


def test_init_creates_file_with_mode_0640(tmp_path: Path, fakes: Fakes) -> None:
    target = tmp_path / "fresh"
    target.mkdir()
    assert main(["--config-dir", str(target), "config", "init"], deps=fakes.deps()) == 0
    assert stat.S_IMODE((target / "default.toml").stat().st_mode) == 0o640


def test_existing_mode_is_kept(etc_dir: Path, run: Callable[..., int]) -> None:
    path = etc_dir / "default.toml"
    path.chmod(0o664)
    assert run("config", "set", "testmode", "true") == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o664
    assert stat.S_IMODE((etc_dir / "default.toml.bak").stat().st_mode) == 0o664


def test_doc_prints_and_writes(tmp_path: Path, run: Callable[..., int],
                               capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "ref.md"
    assert run("config", "doc", "--output", str(out)) == 0
    assert "| `scoring.limit` |" in out.read_text()
    capsys.readouterr()
    assert run("config", "doc") == 0
    assert capsys.readouterr().out == out.read_text()


def test_bak_written(etc_dir: Path, run: Callable[..., int]) -> None:
    (etc_dir / "default.toml").write_text("testmode = false\n")
    assert run("config", "set", "testmode", "true") == 0
    assert (etc_dir / "default.toml.bak").read_text() == "testmode = false\n"


@pytest.mark.parametrize("scope", [
    "domain:../../etc/passwd", "user:a/b@x.example", "domain:.hidden", "user:.x@example.com",
    "domain:a\\b.example", "domain:a b.example", "user:a b@example.com", "domain:x\x00.example",
    "domain:x\n.example", "domain:..", "domain:", "user:", "user:nodomain", "user:@example.com",
    "domain:[1.2.3.4]", "domain:a*b.example", "user:a@..", "domain:/etc", "../x", "file:x",
    "SYS", "domain:\t", "user:\"a/b\"@example.com", "domain:a..example", "user:postmaster",
])
def test_scope_rejects_traversal_and_garbage(etc_dir: Path, run: Callable[..., int],
                                             scope: str) -> None:
    before = snapshot_of(etc_dir)
    with pytest.raises(ScopeError):
        parse_scope(scope)
    assert run("config", "set", "testmode", "true", scope) == 2
    assert run("config", "unset", "testmode", scope) == 2
    assert snapshot_of(etc_dir) == before
    assert not (etc_dir.parent / "passwd.toml").exists()


def test_scope_files(etc_dir: Path) -> None:
    assert parse_scope("sys").path(etc_dir) == etc_dir / "assp-ng.toml"
    assert parse_scope("default").path(etc_dir) == etc_dir / "default.toml"
    assert parse_scope("domain:Example.COM.").path(etc_dir) == etc_dir / "domain.d/example.com.toml"
    assert parse_scope("user:A.B+c@Example.com").path(etc_dir) == \
        etc_dir / "user.d/a.b+c@example.com.toml"


def test_root_needed_only_for_the_default_directory(etc_dir: Path, fakes: Fakes,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    fakes.euid = 1000
    assert main(["--config-dir", str(etc_dir), "config", "set", "testmode", "true"],
                deps=fakes.deps()) == 0
    # The default directory is refused for non-root before anything is read or written.
    for argv in (["config", "set", "testmode", "true"], ["config", "unset", "testmode"],
                 ["config", "init"]):
        assert main(argv, deps=fakes.deps()) == 1
        assert "needs root" in capsys.readouterr().err
    assert str(DEFAULT_DIR) == "/etc/assp-ng"
    fakes.euid = 0


def test_reload_runs_only_when_active(etc_dir: Path, run: Callable[..., int],
                                      fakes: Fakes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("asspng.cli.config_cmd.DEFAULT_DIR", SYSTEM_DIR[0])
    assert run("config", "set", "testmode", "true") == 0
    assert fakes.commands == [["systemctl", "is-active", "--quiet", "assp-ng-proxy"],
                              ["systemctl", "reload", "assp-ng-proxy"]]
    fakes.commands.clear()
    fakes.active = False
    assert run("config", "set", "testmode", "false") == 0
    assert fakes.commands == [["systemctl", "is-active", "--quiet", "assp-ng-proxy"]]
    fakes.commands.clear()
    # a rejected change never reaches the service
    assert run("config", "set", "scoring.limit", "x") == 2
    assert fakes.commands == []


def test_reload_failure_is_reported(run: Callable[..., int], fakes: Fakes,
                                    capsys: pytest.CaptureFixture[str],
                                    monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("asspng.cli.config_cmd.DEFAULT_DIR", SYSTEM_DIR[0])
    fakes.reload_rc = 1
    assert run("config", "set", "testmode", "true") == 1
    assert "reload" in capsys.readouterr().err


def test_audit_written_when_database_configured(etc_dir: Path, run: Callable[..., int],
                                                fakes: Fakes) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        'instance = "mx1"\n' + (etc_dir / "assp-ng.toml").read_text() + DB_TOML)
    assert run("config", "set", "scoring.limit", "70", "domain:Example.com") == 0
    assert run("config", "unset", "scoring.limit", "domain:example.com") == 0
    set_entry, unset_entry = fakes.audits
    assert set_entry == {
        "url": SECRET_URL, "instance": "mx1", "actor": "tester", "action": "config.set",
        "target": "domain:example.com:scoring.limit",
        "details": {"key": "scoring.limit", "scope": "domain:example.com", "value": "70"}}
    assert unset_entry["action"] == "config.unset"


def test_no_audit_without_database(run: Callable[..., int], fakes: Fakes) -> None:
    assert run("config", "set", "testmode", "true") == 0
    assert fakes.audits == []


def test_audit_failure_warns_and_keeps_change(etc_dir: Path, run: Callable[..., int],
                                              fakes: Fakes,
                                              capsys: pytest.CaptureFixture[str],
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("asspng.cli.config_cmd.DEFAULT_DIR", SYSTEM_DIR[0])
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + DB_TOML)
    fakes.audit_error = RuntimeError(f"cannot connect to {SECRET_URL}")
    assert run("config", "set", "testmode", "true") == 0
    captured = capsys.readouterr()
    assert "warning" in captured.err and "RuntimeError" in captured.err
    assert "hunter2" not in captured.out + captured.err
    assert (etc_dir / "default.toml").read_text() == "testmode = true\n"
    assert ["systemctl", "reload", "assp-ng-proxy"] in fakes.commands


def test_argparse_errors_exit_2(run: Callable[..., int]) -> None:
    assert main(["config"]) == 2
    assert main(["config", "set", "onlykey"]) == 2
    assert main(["frobnicate"]) == 2
    assert main(["--help"]) == 0
    assert run("config", "show", "a", "b", "c") == 2


def test_missing_config_dir(tmp_path: Path, fakes: Fakes) -> None:
    gone = str(tmp_path / "nope")
    assert main(["--config-dir", gone, "config", "set", "testmode", "true"],
                deps=fakes.deps()) == 1
    assert main(["--config-dir", gone, "config", "check"], deps=fakes.deps()) == 1


# --- check -------------------------------------------------------------------------------

def good_probes(calls: list[str] | None = None) -> Probes:
    log = calls if calls is not None else []

    def database(url: str) -> str:
        log.append("db")
        return "connected"

    def redis(url: str, prefix: str) -> str:
        log.append("redis")
        return "ping ok"

    def backend(listener: ListenerConfig, connect_s: float, banner_s: float) -> str:
        log.append(f"backend:{listener.name}")
        return "banner and EHLO ok"

    def certificate(cert: CertificateConfig) -> str:
        log.append(f"cert:{cert.name}")
        return "valid, 80 days left"

    return Probes(database, redis, backend, certificate)


def test_check_all_ok(etc_dir: Path, run: Callable[..., int],
                      capsys: pytest.CaptureFixture[str]) -> None:
    calls: list[str] = []
    assert run("config", "check", probes=good_probes(calls)) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "OK   config: 1 listeners, 0 certificates",
        "OK   database: not configured",
        "OK   redis: ping ok",
        "OK   backend inbound (127.0.0.1:1): banner and EHLO ok",
    ]
    assert calls == ["redis", "backend:inbound"]


def test_check_failures_exit_1_and_never_print_urls(etc_dir: Path, run: Callable[..., int],
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + DB_TOML
        + '[[tls.certificate]]\nname = "mx"\nhostnames = ["mx.example.com"]\n'
          'cert = "/c.pem"\nkey = "/k.pem"\n')

    def database(url: str) -> str:
        raise RuntimeError(f"access denied for {SECRET_URL}")

    def redis(url: str, prefix: str) -> str:
        raise ConnectionError(f"cannot reach {url}")

    def certificate(cert: CertificateConfig) -> str:
        raise ProbeError("expired 3 days ago")

    probes = good_probes()
    probes.database, probes.redis, probes.certificate = database, redis, certificate
    assert run("config", "check", probes=probes) == 1
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert "FAIL database: RuntimeError" in lines
    assert "FAIL redis: ConnectionError" in lines
    assert "FAIL certificate mx: ProbeError: expired 3 days ago" in lines
    assert "OK   backend inbound (127.0.0.1:1): banner and EHLO ok" in lines
    assert "hunter2" not in captured.out + captured.err
    assert "redis://" not in captured.out + captured.err


def test_check_reports_invalid_files(etc_dir: Path, run: Callable[..., int],
                                     capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "default.toml").write_text("bogus = 1\n")
    calls: list[str] = []
    assert run("config", "check", probes=good_probes(calls)) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL config: ") and "bogus" in out
    assert calls == []


def test_unexpected_error_prints_type_only(etc_dir: Path, fakes: Fakes,
                                           capsys: pytest.CaptureFixture[str],
                                           monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError(SECRET_URL)

    monkeypatch.setattr("asspng.cli.config_cmd.load_config", boom)
    assert main(["--config-dir", str(etc_dir), "config", "check"], deps=fakes.deps()) == 1
    captured = capsys.readouterr()
    assert "hunter2" not in captured.out + captured.err
    assert "RuntimeError" in captured.err
    assert os.path.isdir(etc_dir)


# --- R49 ---------------------------------------------------------------------------------

def test_show_masks_webhook_to_scheme_and_host(etc_dir: Path, run: Callable[..., int],
                                               capsys: pytest.CaptureFixture[str]) -> None:
    hook = "https://user:pw@hooks.example:8443/services/T000/B000/SECRETPATH?t=SECRETQ#frag"
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + f'[alerts]\nwebhook = "{hook}"\n')
    capsys.readouterr()
    assert run("config", "show", "alerts.webhook") == 0
    assert capsys.readouterr().out == 'alerts.webhook = "https://hooks.example:8443"  (system)\n'
    assert run("config", "show", "sys") == 0
    out = capsys.readouterr().out
    assert "SECRET" not in out and "pw@" not in out


def test_show_webhook_malformed_and_empty(etc_dir: Path, run: Callable[..., int],
                                          capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + '[alerts]\nwebhook = "not a url SECRET"\n')
    capsys.readouterr()
    assert run("config", "show", "alerts.webhook") == 0
    assert capsys.readouterr().out == 'alerts.webhook = "<invalid url>"  (system)\n'


def test_reload_only_for_the_system_directory(etc_dir: Path, run: Callable[..., int],
                                              fakes: Fakes,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    assert run("config", "set", "testmode", "true") == 0
    assert fakes.commands == []
    monkeypatch.setattr("asspng.cli.config_cmd.DEFAULT_DIR", etc_dir)
    assert run("config", "set", "testmode", "false") == 0
    assert fakes.commands == [["systemctl", "is-active", "--quiet", "assp-ng-proxy"],
                              ["systemctl", "reload", "assp-ng-proxy"]]


def test_invalid_existing_config_names_file_and_key_not_values(
        etc_dir: Path, run: Callable[..., int], capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "default.toml").write_text('[scoring]\nlimit = "SECRETVALUE"\n')
    before = snapshot_of(etc_dir)
    assert run("config", "set", "testmode", "true") == 2
    err = capsys.readouterr().err
    assert str(etc_dir / "default.toml") in err and "scoring.limit" in err
    assert "SECRETVALUE" not in err
    assert snapshot_of(etc_dir) == before


# --- R51 ---------------------------------------------------------------------------------

def test_concurrent_sets_both_survive(etc_dir: Path, fakes: Fakes,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
    import threading
    import time

    real_dumps = editor.tomlkit.dumps

    def slow_dumps(doc: object) -> str:
        text: str = real_dumps(doc)
        time.sleep(0.3)  # between the read of the file and the rename: the lost-update window
        return text

    monkeypatch.setattr(editor.tomlkit, "dumps", slow_dumps)
    codes: list[int] = []

    def worker(key: str, value: str) -> None:
        codes.append(main(["--config-dir", str(etc_dir), "config", "set", key, value],
                          deps=fakes.deps()))

    threads = [threading.Thread(target=worker, args=("scoring.limit", "70")),
               threading.Thread(target=worker, args=("scoring.add_header", "false"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert codes == [0, 0]
    layer = load_config(etc_dir).default_layer
    assert layer["scoring.limit"] == 70 and layer["scoring.add_header"] is False


def test_symlinked_policy_dir_is_never_written_during_validation(
        etc_dir: Path, tmp_path_factory: pytest.TempPathFactory,
        run: Callable[..., int]) -> None:
    outside = tmp_path_factory.mktemp("outside")
    (outside / "other.toml").write_text("testmode = true\n")
    (etc_dir / "domain.d").symlink_to(outside)
    before = snapshot_of(outside)
    assert run("config", "set", "scoring.warn", "99", "domain:example.com") == 2
    assert snapshot_of(outside) == before
    assert run("config", "set", "scoring.limit", "70", "domain:example.com") == 0
    assert sorted(p.name for p in outside.iterdir()) == ["example.com.toml", "other.toml"]
    assert (outside / "example.com.toml").read_text() == "[scoring]\nlimit = 70\n"


def test_dangling_symlink_is_a_validation_error(etc_dir: Path, run: Callable[..., int],
                                                capsys: pytest.CaptureFixture[str]) -> None:
    (etc_dir / "domain.d").symlink_to(etc_dir / "nowhere")
    assert run("config", "set", "testmode", "true") == 2
    assert "domain.d" in capsys.readouterr().err


def test_symlinked_lock_file_is_refused(etc_dir: Path, tmp_path_factory: pytest.TempPathFactory,
                                        run: Callable[..., int],
                                        capsys: pytest.CaptureFixture[str]) -> None:
    victim = tmp_path_factory.mktemp("victim") / "target"
    victim.write_text("keep")
    (etc_dir / ".assp-ng.lock").symlink_to(victim)
    assert run("config", "set", "testmode", "true") == 1
    assert ".assp-ng.lock" in capsys.readouterr().err
    assert victim.read_text() == "keep" and not (etc_dir / "default.toml").read_text()
