# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from asspng.cli.config_cmd import Deps
from asspng.cli.main import main
from asspng.domains.index import DomainEntry
from asspng.db.repository import DomainExistsError
from asspng.service.control import ControlServer
from asspng.state.base import StateError
from asspng.state.memory_store import MemoryStore

# Remote: needs TLS and a password (ruling R66).
SECRET_URL = "mysql+pymysql://asspng:hunter2@db.example/asspng?ssl_ca=/etc/ssl/certs/ca.pem"


class FakeRepo:
    def __init__(self, owner: "Env") -> None:
        self.owner = owner

    def _check(self) -> None:
        if self.owner.db_error is not None:
            raise self.owner.db_error

    def add(self, domain: str, *, include_subdomains: bool, note: str | None, actor: str) -> None:
        self._check()
        if domain in self.owner.domains:
            raise DomainExistsError(f"domain already exists: {domain}")
        self.owner.domains[domain] = (include_subdomains, note or "")
        self.owner.repo_calls.append(("add", domain, actor))
        self.owner.order.append("commit")

    def remove(self, domain: str, *, actor: str) -> bool:
        self._check()
        self.owner.repo_calls.append(("remove", domain, actor))
        self.owner.order.append("commit")
        return self.owner.domains.pop(domain, None) is not None

    def list(self) -> list[DomainEntry]:
        self._check()
        return [DomainEntry(d, v[0], True) for d, v in sorted(self.owner.domains.items())]

    def close(self) -> None:
        pass


class RecordingStore(MemoryStore):
    def __init__(self, owner: "Env") -> None:
        super().__init__(1000, time.time)
        self.owner = owner

    async def publish(self, channel: str, message: str) -> None:
        if self.owner.redis_down:
            raise StateError("redis publish failed: ConnectionError")
        self.owner.order.append("publish")
        self.owner.published.append((channel, message))

    async def get_hash(self, key: str) -> dict[str, str]:
        if self.owner.redis_down:
            raise StateError("redis get_hash failed: ConnectionError")
        return await super().get_hash(key)

    async def set_hash(self, key: str, values: "dict[str, str]", ttl_s: int | None) -> None:
        if self.owner.redis_down:
            raise StateError("redis set_hash failed: ConnectionError")
        await super().set_hash(key, values, ttl_s)

    async def keys(self, pattern: str) -> list[str]:
        if self.owner.redis_down:
            raise StateError("redis keys failed: ConnectionError")
        return await super().keys(pattern)

    async def delete(self, *keys: str) -> int:
        if self.owner.redis_down:
            raise StateError("redis delete failed: ConnectionError")
        return await super().delete(*keys)


class FakeAlerter:
    def __init__(self, owner: "Env", **kwargs: object) -> None:
        self.owner = owner
        owner.alerter_kwargs = kwargs

    async def notify(self, event: str, message: str) -> bool:
        self.owner.notified.append((event, message))
        return self.owner.deliver


class Env:
    def __init__(self, stamp_dir: Path) -> None:
        self.stamp_dir = stamp_dir
        self.domains: dict[str, tuple[bool, str]] = {}
        self.repo_calls: list[tuple[str, str, str]] = []
        self.db_error: Exception | None = None
        self.redis_down = False
        self.published: list[tuple[str, str]] = []
        self.order: list[str] = []
        self.audits: list[dict[str, object]] = []
        self.audit_error: Exception | None = None
        self.upgrades: list[str] = []
        self.control_calls: list[tuple[str, str, dict[str, object]]] = []
        self.control_replies: dict[str, object] = {}
        self.control_error: BaseException | None = None
        self.notified: list[tuple[str, str]] = []
        self.deliver = True
        self.alerter_kwargs: dict[str, object] = {}
        self.store = RecordingStore(self)
        self.store_args: list[tuple[str, str, float]] = []

    def make_store(self, url: str, prefix: str, timeout: float) -> RecordingStore:
        self.store_args.append((url, prefix, timeout))
        return self.store

    def audit(self, url: str, **kwargs: object) -> None:
        if self.audit_error is not None:
            raise self.audit_error
        self.audits.append({"url": url, **kwargs})

    def upgrade(self, url: str) -> None:
        if self.db_error is not None:
            raise self.db_error
        self.upgrades.append(url)

    async def control(self, path: Path, cmd: str, args: dict[str, object],
                      timeout_s: float = 5.0) -> object:
        if self.control_error is not None:
            raise self.control_error
        self.control_calls.append((str(path), cmd, args))
        reply = self.control_replies.get(cmd)
        if isinstance(reply, Exception):
            raise reply
        return reply

    def deps(self) -> Deps:
        return Deps(
            audit=self.audit, actor=lambda: "tester", upgrade=self.upgrade,
            repo_factory=lambda url, instance: FakeRepo(self),
            store_factory=self.make_store,
            control=self.control,
            alerter_factory=lambda **kw: FakeAlerter(self, **kw),  # type: ignore[arg-type]
            notify_stamp_dir=self.stamp_dir)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path / "notify-stamps")


@pytest.fixture
def run(etc_dir: Path, env: Env) -> Callable[..., int]:
    (etc_dir / "assp-ng.toml").write_text(
        'instance = "mx1"\n[database]\nurl = "%s"\n' % SECRET_URL
        + '[alerts]\nemail = "adm@example.com"\n'
        + '[redis]\nurl = "rediss://:redispw@r.example:6380/3"\nkey_prefix = "zz:"\n'
        + '[network]\nipv6_prefix = 64\n\n'
        + (etc_dir / "assp-ng.toml").read_text())

    def call(*argv: str) -> int:
        return main(["--config-dir", str(etc_dir), *argv], deps=env.deps())
    return call


def test_domain_add_publishes_event(run: Callable[..., int], env: Env,
                                    capsys: pytest.CaptureFixture[str]) -> None:
    assert run("domain", "add", "Example.COM", "--subdomains", "--note", "main") == 0
    assert env.repo_calls == [("add", "Example.COM", "tester (cli)")]
    assert env.published == [("events", "domains-changed")]
    assert env.order == ["commit", "publish"]  # published only after the commit


def test_domain_add_duplicate_and_remove_missing_exit_1(
        run: Callable[..., int], env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("domain", "add", "a.example") == 0
    assert run("domain", "add", "a.example") == 1
    assert "already exists" in capsys.readouterr().err
    assert run("domain", "remove", "zzz.example") == 1
    assert "not found" in capsys.readouterr().err
    assert env.published == [("events", "domains-changed")]


def test_domain_publish_failure_warns_and_exits_0(
        run: Callable[..., int], env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.redis_down = True
    assert run("domain", "add", "a.example") == 0
    err = capsys.readouterr().err
    assert "warning" in err and "StateError" in err
    assert "a.example" in env.domains


def test_domain_remove_and_list(run: Callable[..., int], env: Env,
                                capsys: pytest.CaptureFixture[str]) -> None:
    run("domain", "add", "b.example", "--subdomains", "--note", "hello")
    capsys.readouterr()
    assert run("domain", "list") == 0
    out = capsys.readouterr().out
    assert "include_subdomains" in out and "b.example" in out and "True" in out.replace(
        "yes", "True").replace("true", "True")
    assert run("domain", "remove", "b.example") == 0
    assert env.published[-1] == ("events", "domains-changed")


def test_pb_show_uses_network_key(run: Callable[..., int], env: Env,
                                  capsys: pytest.CaptureFixture[str]) -> None:
    assert run("pb", "show", "2001:db8::1") == 0
    assert "2001:db8::/64" in capsys.readouterr().out


def test_pb_block_duration(run: Callable[..., int], env: Env,
                           capsys: pytest.CaptureFixture[str]) -> None:
    before = time.time()
    assert run("pb", "block", "192.0.2.7", "--for", "2h", "--reason", "abuse") == 0
    block = asyncio.run(env.store.get_hash("pb:block:192.0.2.7/32"))
    assert 7190 < float(block["until"]) - before < 7210
    assert block["reason"] == "abuse" and block["level"] == "0"
    assert env.audits[-1]["action"] == "pb.block"
    assert env.audits[-1]["actor"] == "tester (cli)"
    assert env.audits[-1]["target"] == "192.0.2.7/32"
    assert run("pb", "block", "192.0.2.7", "--for", "soon") == 2
    assert run("pb", "show", "192.0.2.7") == 0
    assert "abuse" in capsys.readouterr().out


def test_pb_invalid_ip_exits_2(run: Callable[..., int]) -> None:
    assert run("pb", "show", "not-an-ip") == 2
    assert run("pb", "remove", "999.1.1.1") == 2
    assert run("pb", "block", "x", "--for", "1h") == 2


def test_pb_remove_forget_deletes_history(run: Callable[..., int], env: Env) -> None:
    async def seed() -> None:
        await env.store.set_hash("pb:192.0.2.9/32", {"score": "5"}, 100)
        await env.store.set_hash("pb:block:192.0.2.9/32", {"until": "1", "level": "1"}, 100)
        await env.store.incr("pb:hist:192.0.2.9/32", 100)
    asyncio.run(seed())
    assert run("pb", "remove", "192.0.2.9") == 0
    assert asyncio.run(env.store.keys("pb:*")) == ["pb:hist:192.0.2.9/32"]
    assert run("pb", "remove", "192.0.2.9", "--forget") == 0
    assert asyncio.run(env.store.keys("pb:*")) == []
    assert [a["action"] for a in env.audits] == ["pb.remove", "pb.remove"]
    assert env.audits[1]["details"] == {"forget": True}


def test_pb_list_shows_blocked_and_scored(run: Callable[..., int], env: Env,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    run("pb", "block", "192.0.2.1", "--for", "1h")
    asyncio.run(env.store.set_hash("pb:198.51.100.2/32", {"score": "7", "hits": "2"}, 600))
    capsys.readouterr()
    assert run("pb", "list") == 0
    out = capsys.readouterr().out
    assert "192.0.2.1/32" in out and "198.51.100.2/32" in out


def test_pb_redis_down_exits_1_with_explanation(
        run: Callable[..., int], env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.redis_down = True
    for argv in (("show", "192.0.2.1"), ("list",), ("remove", "192.0.2.1"),
                 ("block", "192.0.2.1", "--for", "1h")):
        assert run("pb", *argv) == 1
        err = capsys.readouterr().err
        assert "Redis" in err and "DEGRADED" in err


def test_pb_audit_failure_warns_and_keeps_change(
        run: Callable[..., int], env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.audit_error = RuntimeError(SECRET_URL)
    assert run("pb", "block", "192.0.2.5", "--for", "1h") == 0
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "hunter2" not in err
    assert asyncio.run(env.store.get_hash("pb:block:192.0.2.5/32"))


def test_debug_on_parses_rule(run: Callable[..., int], env: Env) -> None:
    env.control_replies["debug.on"] = {"id": "abc", "kind": "ip", "value": "2001:db8::1",
                                       "expires_at": time.time() + 60, "headers": True}
    assert run("debug", "on", "ip:2001:db8::1", "--for", "10m", "--headers") == 0
    path, cmd, args = env.control_calls[0]
    assert path.endswith("/run/assp-ng/control.sock")
    assert cmd == "debug.on"
    assert args == {"kind": "ip", "value": "2001:db8::1", "duration_s": 600, "headers": True}
    env.control_replies["debug.on"] = {"id": "d", "kind": "all", "value": "",
                                       "expires_at": time.time() + 60, "headers": False}
    assert run("debug", "on", "all") == 0
    assert env.control_calls[1][2] == {"kind": "all", "value": "", "duration_s": None,
                                       "headers": False}


@pytest.mark.parametrize("argv", [("on", "bogus:1"), ("on", "ip"), ("on", "ip:"),
                                  ("on", "ip:1.2.3.4", "--for", "xx"), ("on",)])
def test_debug_on_bad_syntax_exits_2(run: Callable[..., int], env: Env,
                                     argv: tuple[str, ...]) -> None:
    assert run("debug", *argv) == 2
    assert env.control_calls == []


def test_debug_on_over_max_errors(run: Callable[..., int], env: Env,
                                  capsys: pytest.CaptureFixture[str]) -> None:
    env.control_replies["debug.on"] = RuntimeError("duration exceeds debug.max_duration (24h)")
    assert run("debug", "on", "from:a@example.com", "--for", "999d") == 1
    assert "debug.max_duration" in capsys.readouterr().err


def test_debug_off_and_list(run: Callable[..., int], env: Env,
                            capsys: pytest.CaptureFixture[str]) -> None:
    env.control_replies["debug.off"] = {"removed": 2}
    assert run("debug", "off", "--all") == 0
    assert env.control_calls[-1] == (env.control_calls[-1][0], "debug.off", {"all": True})
    assert run("debug", "off", "abc") == 0
    assert env.control_calls[-1][2] == {"id": "abc"}
    assert run("debug", "off") == 2
    assert run("debug", "off", "abc", "--all") == 2
    env.control_replies["debug.list"] = [{"id": "abc", "kind": "ip", "value": "1.2.3.4",
                                          "expires_at": time.time() + 90, "headers": False}]
    capsys.readouterr()
    assert run("debug", "list") == 0
    out = capsys.readouterr().out
    assert "abc" in out and "1.2.3.4" in out


@pytest.mark.parametrize("error", [FileNotFoundError(2, "No such file"),
                                   PermissionError(13, "Permission denied"),
                                   ConnectionRefusedError(111, "refused")])
def test_control_socket_errors_print_hint(run: Callable[..., int], env: Env,
                                          capsys: pytest.CaptureFixture[str],
                                          error: OSError) -> None:
    env.control_error = error
    assert run("debug", "list") == 1
    assert "run as root or a member of the assp-ng group" in capsys.readouterr().err
    assert run("status") == 1


STATUS = {
    "status": "degraded", "instance": "mx1", "mode": "DEGRADED", "redis": "down", "db": "ok",
    "domains": {"source": "db", "count": 3}, "backends": {"inbound": "ok", "sub": "down"},
    "sessions": 4, "rss_mb": 123.4, "uptime_s": 93784, "debug_rules": 1,
    "certificates": {"mx": {"days_left": 40}}, "counters": {"rejected": 9, "accepted": 100},
}


def test_status_table(run: Callable[..., int], env: Env,
                      capsys: pytest.CaptureFixture[str]) -> None:
    env.control_replies["status"] = STATUS
    assert run("status") == 0
    out = capsys.readouterr().out
    for word in ("status", "degraded", "mode", "DEGRADED", "redis", "db", "domains", "backends",
                 "inbound", "sub", "sessions", "rss_mb", "123.4", "uptime", "1d 2h 3m",
                 "debug_rules", "certificates", "mx", "40", "counters", "rejected", "9"):
        assert word in out, word


async def test_status_against_real_control_server(
        tmp_path: Path, etc_dir: Path, env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    from asspng.service.control import control_request

    async def status(args: dict[str, object]) -> object:
        return STATUS
    sock = tmp_path / "control.sock"
    server = ControlServer(sock, {"status": status}, group=None)
    await server.start()
    try:
        deps = env.deps()
        deps.control = control_request
        (etc_dir / "assp-ng.toml").write_text(
            f'[paths]\nrun = "{tmp_path}"\n' + (etc_dir / "assp-ng.toml").read_text())
        code = await asyncio.to_thread(
            main, ["--config-dir", str(etc_dir), "status"], deps=deps)
    finally:
        await server.close()
    assert code == 0
    assert "DEGRADED" in capsys.readouterr().out


def test_notify_calls_alerter(run: Callable[..., int], env: Env) -> None:
    assert run("notify", "--event", "unit-failed", "--message", "boom") == 0
    assert env.notified == [("unit-failed", "boom")]
    kw = env.alerter_kwargs
    assert kw["min_interval_s"] == 0 and kw["clock"] is time.time
    assert kw["instance"] == "mx1" and kw["email"] == "adm@example.com"
    assert kw["webhook"] == "" and kw["smtp_server"] == "127.0.0.1:10125"


def test_notify_failed_channels_exit_1(run: Callable[..., int], env: Env,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    env.deliver = False
    assert run("notify", "--event", "e", "--message", "m") == 1
    assert "email" in capsys.readouterr().err


def test_notify_no_channels_exits_1(etc_dir: Path, env: Env,
                                    capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--config-dir", str(etc_dir), "notify", "--event", "e", "--message", "m"],
                deps=env.deps()) == 1
    assert "no alert channel" in capsys.readouterr().err
    assert env.notified == []


def test_notify_ignores_broken_policy_files(etc_dir: Path, env: Env) -> None:
    """R60: notify reads only instance, hostname and alerts.* from assp-ng.toml."""
    (etc_dir / "assp-ng.toml").write_text(
        'bogus_key = 1\ninstance = "mx9"\nhostname = "mx9.example"\n'
        '[alerts]\nemail = "adm@example.com"\nmin_interval = "not a duration"\n'
        '[[listener]]\nname = "x"\n')
    (etc_dir / "default.toml").write_text("[[[ not toml\n")
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "Bad Name.toml").write_text("x = 1\n")
    assert main(["--config-dir", str(etc_dir), "notify", "--event", "e", "--message", "m"],
                deps=env.deps()) == 0
    assert env.notified == [("e", "m")]
    kw = env.alerter_kwargs
    assert kw["instance"] == "mx9" and kw["email"] == "adm@example.com"
    assert kw["sender"] == "assp-ng@mx9.example"


def test_notify_unparsable_system_file_uses_defaults(
        tmp_path: Path, env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "assp-ng.toml").write_text('[alerts\nemail = "adm@example.com"\n')
    assert main(["--config-dir", str(tmp_path), "notify", "--event", "e", "--message", "m"],
                deps=env.deps()) == 1  # no channel in the defaults: 1, never 2
    assert "no alert channel" in capsys.readouterr().err
    assert main(["--config-dir", str(tmp_path / "missing"), "notify", "--event", "e",
                 "--message", "m"], deps=env.deps()) == 1


def test_notify_invalid_alert_value_falls_back_to_its_default(
        etc_dir: Path, env: Env) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        '[alerts]\nemail = "adm@example.com"\nsmtp_server = 25\n')
    assert main(["--config-dir", str(etc_dir), "notify", "--event", "e", "--message", "m"],
                deps=env.deps()) == 0
    assert env.alerter_kwargs["smtp_server"] == "127.0.0.1:10125"


def test_notify_rate_limited_per_event(run: Callable[..., int], env: Env,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    """Spec 8.6: at most once per alerts.min_interval per event, also across processes."""
    assert run("notify", "--event", "service-failed", "--message", "one") == 0
    capsys.readouterr()
    assert run("notify", "--event", "service-failed", "--message", "two") == 0
    assert "suppressed (rate limit)" in capsys.readouterr().out
    assert run("notify", "--event", "other", "--message", "three") == 0
    assert env.notified == [("service-failed", "one"), ("other", "three")]
    stamp = env.stamp_dir / "service-failed.stamp"
    assert stamp.is_file()
    assert stat.S_IMODE(env.stamp_dir.stat().st_mode) == 0o700
    old = time.time() - 1801  # alerts.min_interval defaults to 30m
    os.utime(stamp, (old, old))
    assert run("notify", "--event", "service-failed", "--message", "four") == 0
    assert env.notified[-1] == ("service-failed", "four")


def test_notify_force_bypasses_the_rate_limit(run: Callable[..., int], env: Env) -> None:
    assert run("notify", "--event", "e", "--message", "one") == 0
    assert run("notify", "--event", "e", "--message", "two", "--force") == 0
    assert env.notified == [("e", "one"), ("e", "two")]


def test_notify_rate_limit_uses_min_interval(etc_dir: Path, env: Env) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        '[alerts]\nemail = "adm@example.com"\nmin_interval = "1m"\n')

    def notify(message: str) -> int:
        return main(["--config-dir", str(etc_dir), "notify", "--event", "e", "--message",
                     message], deps=env.deps())
    assert notify("one") == 0
    stamp = env.stamp_dir / "e.stamp"
    old = time.time() - 61
    os.utime(stamp, (old, old))
    assert notify("two") == 0
    assert env.notified == [("e", "one"), ("e", "two")]


def test_notify_event_name_cannot_leave_the_stamp_directory(
        run: Callable[..., int], env: Env) -> None:
    assert run("notify", "--event", "../../x", "--message", "m") == 0
    assert run("notify", "--event", "..", "--message", "m") == 0
    assert sorted(p.name for p in env.stamp_dir.iterdir()) == ["...stamp", ".._.._x.stamp"]


def test_notify_refuses_a_symlinked_stamp_directory(
        run: Callable[..., int], env: Env, tmp_path: Path,
        capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    env.stamp_dir.symlink_to(target)
    assert run("notify", "--event", "e", "--message", "m") == 1
    assert "rate-limit directory" in capsys.readouterr().err
    assert env.notified == []
    assert list(target.iterdir()) == []
    assert run("notify", "--event", "e", "--message", "m", "--force") == 0
    assert env.notified == [("e", "m")]


def test_notify_refuses_a_stamp_directory_of_another_owner(
        run: Callable[..., int], env: Env, etc_dir: Path,
        capsys: pytest.CaptureFixture[str]) -> None:
    env.stamp_dir.mkdir(mode=0o700)
    deps = env.deps()
    deps.geteuid = lambda: os.geteuid() + 1
    assert main(["--config-dir", str(etc_dir), "notify", "--event", "e", "--message", "m"],
                deps=deps) == 1
    assert "rate-limit directory" in capsys.readouterr().err
    assert env.notified == []


def test_db_upgrade(run: Callable[..., int], env: Env, capsys: pytest.CaptureFixture[str],
                    monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("asspng.cli.ops_cmd.current_revision", lambda url: "0001")
    assert run("db", "upgrade") == 0
    out = capsys.readouterr().out
    assert "schema at revision 0001" in out and "hunter2" not in out
    assert env.upgrades == [SECRET_URL]


def test_db_upgrade_without_url_exits_2(etc_dir: Path, env: Env) -> None:
    assert main(["--config-dir", str(etc_dir), "db", "upgrade"], deps=env.deps()) == 2


def test_invalid_config_exits_2(tmp_path: Path, env: Env) -> None:
    (tmp_path / "assp-ng.toml").write_text("bogus_key = 1\n")
    for argv in (("domain", "list"), ("pb", "list"), ("db", "upgrade")):
        assert main(["--config-dir", str(tmp_path), *argv], deps=env.deps()) == 2


def test_status_and_debug_need_only_the_run_path(
        etc_dir: Path, env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    """R60: the proxy keeps running on its old configuration while a file is broken."""
    (etc_dir / "assp-ng.toml").write_text(
        'bogus_key = 1\n[paths]\nrun = "/srv/run-x"\n' + (etc_dir / "assp-ng.toml").read_text())
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml").write_text("not = [valid toml\n")
    (etc_dir / "default.toml").write_text("[[[\n")
    env.control_replies["status"] = STATUS
    env.control_replies["debug.list"] = []
    assert main(["--config-dir", str(etc_dir), "status"], deps=env.deps()) == 0
    assert "DEGRADED" in capsys.readouterr().out
    assert main(["--config-dir", str(etc_dir), "debug", "list"], deps=env.deps()) == 0
    assert [call[:2] for call in env.control_calls] == [
        ("/srv/run-x/control.sock", "status"), ("/srv/run-x/control.sock", "debug.list")]


def test_status_with_unparsable_system_file_uses_the_default_run_path(
        tmp_path: Path, env: Env) -> None:
    (tmp_path / "assp-ng.toml").write_text("[paths\nrun = 1\n")
    env.control_replies["status"] = STATUS
    assert main(["--config-dir", str(tmp_path), "status"], deps=env.deps()) == 0
    assert env.control_calls[0][0] == "/run/assp-ng/control.sock"


def test_no_output_contains_the_db_password(
        run: Callable[..., int], env: Env, capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch) -> None:
    env.db_error = RuntimeError(SECRET_URL)
    env.audit_error = RuntimeError(SECRET_URL)
    monkeypatch.setattr("asspng.cli.ops_cmd.current_revision",
                        lambda url: (_ for _ in ()).throw(RuntimeError(SECRET_URL)))
    codes = [run("db", "upgrade"), run("domain", "add", "a.example"),
             run("domain", "remove", "a.example"), run("domain", "list"),
             run("pb", "block", "192.0.2.1", "--for", "1h"), run("pb", "remove", "192.0.2.1"),
             run("pb", "list")]
    captured = capsys.readouterr()
    assert "hunter2" not in captured.out + captured.err
    assert codes[:4] == [1, 1, 1, 1]


REDIS_ARGS = ("rediss://:redispw@r.example:6380/3", "zz:", 0.2)


def test_redis_url_and_prefix_reach_the_store(run: Callable[..., int], env: Env) -> None:
    assert run("pb", "show", "192.0.2.1") == 0
    assert run("domain", "add", "a.example") == 0
    assert env.store_args == [REDIS_ARGS, REDIS_ARGS]


def test_pb_block_ipv4_mapped_uses_ipv4_key(run: Callable[..., int], env: Env) -> None:
    assert run("pb", "block", "::ffff:192.0.2.7", "--for", "1h") == 0
    assert asyncio.run(env.store.keys("pb:*")) == ["pb:block:192.0.2.7/32"]


def _with_prefixes(etc_dir: Path, v4: int, v6: int) -> None:
    path = etc_dir / "assp-ng.toml"
    path.write_text(f'[database]\nurl = "{SECRET_URL}"\n[network]\nipv4_prefix = {v4}\n'
                    f"ipv6_prefix = {v6}\n" + path.read_text())


def test_pb_uses_configured_ipv4_prefix(etc_dir: Path, env: Env,
                                        capsys: pytest.CaptureFixture[str]) -> None:
    _with_prefixes(etc_dir, 24, 48)

    def go(*argv: str) -> int:
        return main(["--config-dir", str(etc_dir), *argv], deps=env.deps())
    assert go("pb", "block", "192.0.2.77", "--for", "1h") == 0
    assert asyncio.run(env.store.keys("pb:*")) == ["pb:block:192.0.2.0/24"]
    assert go("pb", "show", "192.0.2.200") == 0
    assert "192.0.2.0/24" in capsys.readouterr().out
    assert env.audits[-1]["target"] == "192.0.2.0/24"


def test_pb_uses_configured_ipv6_prefix(etc_dir: Path, env: Env) -> None:
    _with_prefixes(etc_dir, 24, 48)
    assert main(["--config-dir", str(etc_dir), "pb", "block", "2001:db8:1:2::9", "--for", "1h"],
                deps=env.deps()) == 0
    assert asyncio.run(env.store.keys("pb:*")) == ["pb:block:2001:db8:1::/48"]


@pytest.mark.parametrize("domain", ["", "a..b", "[300.1.1.1]", "bad domain"])
def test_invalid_domain_exits_2_before_the_db(run: Callable[..., int], env: Env,
                                              capsys: pytest.CaptureFixture[str],
                                              domain: str) -> None:
    assert run("domain", "add", domain) == 2
    assert run("domain", "remove", domain) == 2
    assert "invalid domain" in capsys.readouterr().err
    assert env.repo_calls == [] and env.store_args == []
