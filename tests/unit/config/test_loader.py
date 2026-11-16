# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path

import pytest

from asspng.config.errors import ConfigError
from asspng.config.loader import load_config
from asspng.config.model import ListenerKind
from asspng.config.registry import Level, Registry, Setting
from asspng.config.settings import REGISTRY
from tests.conftest import MINIMAL_SYSTEM_TOML

CERT = """
[[tls.certificate]]
name = "mx"
hostnames = ["mx.example.com"]
cert = "/etc/c.pem"
key = "/etc/k.pem"
"""


def submission(extra: str = "", backend: str = "127.0.0.1:10587") -> str:
    return f"""
[[listener]]
name = "sub"
kind = "submission"
port = 587
backend = "{backend}"
{extra}
"""


def errors_of(etc: Path) -> list[str]:
    with pytest.raises(ConfigError) as info:
        load_config(etc)
    return info.value.errors


def test_minimal_loads(etc_dir: Path) -> None:
    snap = load_config(etc_dir)
    (listener,) = snap.listeners
    assert listener.kind is ListenerKind.SMTP
    assert (listener.port, listener.backend_host, listener.backend_port) == (0, "127.0.0.1", 1)
    assert listener.xclient is True and listener.auth is False
    assert (listener.bind4, listener.bind6, listener.ipv4, listener.ipv6) == (
        "0.0.0.0", "::", True, True)
    assert snap.get("redis.key_prefix") == "asspng:"
    assert snap.get("hostname") and snap.get("instance") == snap.get("hostname")
    assert snap.default_layer == {} and snap.certificates == ()
    assert len(snap.trusted) == 0 and snap.etc_dir == etc_dir
    with pytest.raises(KeyError):
        snap.get("scoring.limit")
    with pytest.raises(TypeError):
        snap.system["x"] = 1  # type: ignore[index]


def test_list_values_are_immutable_and_defaults_untouched(etc_dir: Path) -> None:
    before = list(REGISTRY.get("penalty_box.ladder").default)  # type: ignore[call-overload]
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + '\n[penalty_box]\nladder = ["1h"]\n')
    snap = load_config(etc_dir)
    assert snap.get("penalty_box.ladder") == (3600,)
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text().replace('ladder = ["1h"]\n', ""))
    default = load_config(etc_dir).get("penalty_box.ladder")
    assert isinstance(default, tuple)
    assert list(REGISTRY.get("penalty_box.ladder").default) == before  # type: ignore[call-overload]


def test_policy_list_values_are_tuples(etc_dir: Path) -> None:
    registry = Registry()
    for setting in REGISTRY.all():
        registry.register(setting)
    registry.register(Setting("tags", "list[str]", [], Level.RECIPIENT, "test list"))
    (etc_dir / "default.toml").write_text('tags = ["a"]\n')
    assert load_config(etc_dir, registry).default_layer["tags"] == ("a",)


def test_hostname_and_instance_explicit(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        'hostname = "mx1.example.com"\ninstance = "mx1"\n'
        + (etc_dir / "assp-ng.toml").read_text())
    snap = load_config(etc_dir)
    assert (snap.get("hostname"), snap.get("instance")) == ("mx1.example.com", "mx1")


def test_missing_default_mentions_init(etc_dir: Path) -> None:
    (etc_dir / "default.toml").unlink()
    assert any("assp-ng config init" in e for e in errors_of(etc_dir))


def test_missing_system_file(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").unlink()
    assert any("assp-ng.toml" in e for e in errors_of(etc_dir))


def test_unknown_key_error(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("bogus.key = 1\n")
    (err,) = errors_of(etc_dir)
    assert "default.toml" in err and "bogus.key" in err


def test_system_key_in_domain_file_is_error(etc_dir: Path) -> None:
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml").write_text('hostname = "x"\n')
    (err,) = errors_of(etc_dir)
    assert "example.com.toml" in err and "hostname" in err


def test_policy_key_in_system_file_is_error(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        "scoring.limit = 10\n" + (etc_dir / "assp-ng.toml").read_text())
    (err,) = errors_of(etc_dir)
    assert "scoring.limit" in err


def test_domain_file_name_must_be_normalized(etc_dir: Path) -> None:
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "Example.COM.toml").write_text("")
    (err,) = errors_of(etc_dir)
    assert "Example.COM.toml" in err


def test_only_toml_files_loaded(etc_dir: Path) -> None:
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml.bak").write_text("garbage {{")
    (etc_dir / "domain.d" / "example.com.toml~").write_text("garbage {{")
    assert load_config(etc_dir).domain_layers == {}


def test_domain_layer(etc_dir: Path) -> None:
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml").write_text("testmode = true\n")
    assert load_config(etc_dir).domain_layers["example.com"] == {"testmode": True}


def test_user_file_layer(etc_dir: Path) -> None:
    (etc_dir / "user.d").mkdir()
    (etc_dir / "user.d" / "jano@example.com.toml").write_text("scoring.limit = 99\n")
    snap = load_config(etc_dir)
    assert snap.user_layers["jano@example.com"] == {"scoring.limit": 99}


def test_user_file_name_must_be_key(etc_dir: Path) -> None:
    (etc_dir / "user.d").mkdir()
    (etc_dir / "user.d" / "Jano@example.com.toml").write_text("")
    (etc_dir / "user.d" / "nodomain.toml").write_text("")
    assert len(errors_of(etc_dir)) == 2


def test_nested_tables_flatten_and_coerce(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("[scoring]\nlimit = 60\nwarn = 40\n")
    assert load_config(etc_dir).default_layer == {"scoring.limit": 60, "scoring.warn": 40}


def test_invalid_value_names_file_and_key(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text('scoring.limit = "many"\n')
    (err,) = errors_of(etc_dir)
    assert "default.toml" in err and "scoring.limit" in err


def test_toml_syntax_error_names_file(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("this is [ not toml\n")
    (err,) = errors_of(etc_dir)
    assert "default.toml" in err


def test_array_of_tables_in_policy_is_error(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text('[[listener]]\nname = "x"\n')
    assert any("default.toml" in e for e in errors_of(etc_dir))


def test_other_array_of_tables_in_system_is_error(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        (etc_dir / "assp-ng.toml").read_text() + '\n[[bogus]]\nname = "x"\n')
    assert any("bogus" in e for e in errors_of(etc_dir))


def test_warn_above_limit_in_each_layer(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("scoring.warn = 60\n")
    assert any("default.toml" in e for e in errors_of(etc_dir))
    (etc_dir / "default.toml").write_text("")
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml").write_text("scoring.limit = 10\n")
    assert any("example.com.toml" in e for e in errors_of(etc_dir))
    domain_file = etc_dir / "domain.d" / "example.com.toml"
    domain_file.write_text("scoring.limit = 10\nscoring.warn = 5\n")
    (etc_dir / "user.d").mkdir()
    (etc_dir / "user.d" / "a@example.com.toml").write_text("scoring.warn = 12\n")
    assert any("a@example.com.toml" in e for e in errors_of(etc_dir))
    (etc_dir / "user.d" / "a@example.com.toml").write_text("scoring.limit = 8\n")
    load_config(etc_dir)


def smtp_listener(extra: str = "", backend: str = "127.0.0.1:10025") -> str:
    return f"""
[[listener]]
name = "inbound-auth"
kind = "smtp"
port = 25
backend = "{backend}"
{extra}
"""


@pytest.mark.parametrize("backend", ["198.51.100.7:25", "[2001:db8::1]:25", "mx.example:25"])
def test_auth_listener_requires_a_loopback_backend(etc_dir: Path, backend: str) -> None:
    """R65: AUTH credentials cross the backend connection in plain text."""
    (etc_dir / "assp-ng.toml").write_text(smtp_listener("auth = true", backend) + CERT)
    errors = [e for e in errors_of(etc_dir) if "inbound-auth" in e and "loopback" in e]
    assert len(errors) == 1
    host = backend.rpartition(":")[0].strip("[]")
    assert host not in errors[0]


@pytest.mark.parametrize("backend", ["127.0.0.1:10025", "[::1]:10025", "localhost:10025"])
def test_auth_listener_with_a_loopback_backend_loads(etc_dir: Path, backend: str) -> None:
    (etc_dir / "assp-ng.toml").write_text(smtp_listener("auth = true", backend) + CERT)
    (listener,) = load_config(etc_dir).listeners
    assert listener.auth is True


def test_listener_without_auth_may_use_a_remote_backend(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").write_text(smtp_listener("auth = false", "198.51.100.7:25"))
    (listener,) = load_config(etc_dir).listeners
    assert listener.backend_host == "198.51.100.7"


def test_penalty_threshold_above_score_cap_is_an_error(etc_dir: Path) -> None:
    """C7: with the cap below the threshold a network could never be blocked."""
    system = etc_dir / "assp-ng.toml"
    system.write_text("[penalty_box]\nthreshold = 120\nscore_cap = 100\n" + MINIMAL_SYSTEM_TOML)
    (err,) = errors_of(etc_dir)
    assert "assp-ng.toml" in err and "penalty_box.threshold" in err and "score_cap" in err
    system.write_text("[penalty_box]\nthreshold = 500\n" + MINIMAL_SYSTEM_TOML)
    assert any("penalty_box.threshold" in e for e in errors_of(etc_dir))  # the default cap
    system.write_text("[penalty_box]\nthreshold = 100\nscore_cap = 100\n" + MINIMAL_SYSTEM_TOML)
    load_config(etc_dir)


def test_submission_requires_cert_and_loopback(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").write_text(submission())
    assert any("certificate" in e for e in errors_of(etc_dir))
    (etc_dir / "assp-ng.toml").write_text(submission(backend="10.0.0.5:25") + CERT)
    assert any("loopback" in e for e in errors_of(etc_dir))
    (etc_dir / "assp-ng.toml").write_text(submission("auth = false") + CERT)
    assert any("auth" in e for e in errors_of(etc_dir))
    (etc_dir / "assp-ng.toml").write_text(submission(backend="[::1]:10587") + CERT)
    snap = load_config(etc_dir)
    (listener,) = snap.listeners
    assert listener.auth is True and listener.backend_host == "::1"
    assert listener.backend_port == 10587
    assert snap.certificates[0].cert == Path("/etc/c.pem")
    assert snap.certificates[0].hostnames == ("mx.example.com",)
    (etc_dir / "assp-ng.toml").write_text(submission(backend="localhost:10587") + CERT)
    load_config(etc_dir)


def test_listener_validation(etc_dir: Path) -> None:
    base = 'name = "a"\nkind = "smtp"\nport = 25\nbackend = "127.0.0.1:1"\n'
    cases = [
        base.replace('"smtp"', '"imap"'),
        base.replace("25", "70000"),
        base.replace("25", '"25"'),
        base + "ipv4 = false\nipv6 = false\n",
        base + "colour = 1\n",
        base.replace('"127.0.0.1:1"', '"127.0.0.1"'),
        base.replace('"127.0.0.1:1"', '"h:99999"'),
        base.replace('"127.0.0.1:1"', "{ host = 1 }"),
        base.replace('name = "a"\n', ""),
        base.replace('"a"', '""'),
        base.replace('"a"', '"a b"'),
        base + 'bind4 = "::1"\n',
        base + 'bind6 = "0.0.0.0"\n',
        base + 'bind4 = "nonsense"\n',
    ]
    for case in cases:
        (etc_dir / "assp-ng.toml").write_text(f"[[listener]]\n{case}")
        assert any("assp-ng.toml" in e for e in errors_of(etc_dir)), case
    for text in ("listener = 5\n", 'listener = ["a"]\n'):
        (etc_dir / "assp-ng.toml").write_text(text)
        assert any("assp-ng.toml" in e and "listener" in e for e in errors_of(etc_dir)), text


def test_duplicate_listener_names(etc_dir: Path) -> None:
    text = (etc_dir / "assp-ng.toml").read_text()
    (etc_dir / "assp-ng.toml").write_text(text + text)
    assert any("duplicate" in e for e in errors_of(etc_dir))


def test_certificate_validation(etc_dir: Path) -> None:
    text = (etc_dir / "assp-ng.toml").read_text()
    for bad in ('name = "m"\nhostnames = []\ncert = "/c"\nkey = "/k"\n',
                'name = "m"\nhostnames = "x"\ncert = "/c"\nkey = "/k"\n',
                'name = "m"\nhostnames = ["h"]\ncert = "c"\nkey = "/k"\n',
                'name = "m"\nhostnames = ["h"]\ncert = "/c"\n'):
        (etc_dir / "assp-ng.toml").write_text(text + f"[[tls.certificate]]\n{bad}")
        assert any("assp-ng.toml" in e for e in errors_of(etc_dir)), bad


def test_invalid_certificate_does_not_hide_submission_listener(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").write_text(
        submission() + '[[tls.certificate]]\nname = "m"\nhostnames = []\n'
        'cert = "/c"\nkey = "/k"\n')
    errors = errors_of(etc_dir)
    assert len(errors) == 1 and "hostnames" in errors[0]


def test_syntax_error_in_system_file_is_the_only_error(etc_dir: Path) -> None:
    (etc_dir / "assp-ng.toml").write_text("not [ toml\n")
    (err,) = errors_of(etc_dir)
    assert "assp-ng.toml" in err


def test_empty_unknown_table_is_error(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("[bogus]\n")
    (err,) = errors_of(etc_dir)
    assert "unknown setting table" in err and "bogus" in err
    (etc_dir / "default.toml").write_text("[scoring]\n")
    load_config(etc_dir)


def test_all_errors_reported_together(etc_dir: Path) -> None:
    (etc_dir / "default.toml").write_text("bogus.a = 1\n")
    (etc_dir / "domain.d").mkdir()
    (etc_dir / "domain.d" / "example.com.toml").write_text("bogus.b = 1\n")
    assert len(errors_of(etc_dir)) == 2


def test_network_files(etc_dir: Path) -> None:
    (etc_dir / "trusted-networks.txt").write_text("10.0.0.0/8\n# c\n")
    (etc_dir / "exempt-networks.txt").write_text("192.0.2.0/24\n")
    snap = load_config(etc_dir)
    assert len(snap.trusted) == 1 and len(snap.exempt) == 1


def test_bad_network_file_is_error(etc_dir: Path) -> None:
    (etc_dir / "trusted-networks.txt").write_text("not-a-net\n")
    (err,) = errors_of(etc_dir)
    assert "trusted-networks.txt:1" in err


def test_network_file_not_utf8_names_file(etc_dir: Path) -> None:
    (etc_dir / "exempt-networks.txt").write_bytes(b"\xff\xfe\n")
    (err,) = errors_of(etc_dir)
    assert "exempt-networks.txt" in err


# --- values that must never be echoed or exposed (R48) -----------------------------------------

PASSWORD = "S3cretPW"


def with_system(etc: Path, line: str) -> None:
    (etc / "assp-ng.toml").write_text(line + "\n" + (etc / "assp-ng.toml").read_text())


@pytest.mark.parametrize("url", [
    "mysql+pymysql://assp:S3cretPW@db.example/assp?ssl_ca=/etc/ssl/certs/ca.pem",
    "mysql+pymysql://assp:S3cretPW@192.0.2.10:3306/assp?ssl_verify_cert=true",
    "mysql+pymysql://assp:S3cretPW@localhost/assp",
    "mysql+pymysql://assp:S3cretPW@127.0.0.1:3306/assp",
    "mysql+pymysql://assp:S3cretPW@[::1]/assp",
    "mysql+pymysql://assp:S3cretPW@/assp?unix_socket=/run/mysqld/mysqld.sock",
    "sqlite:////var/lib/assp-ng/domains.sqlite",
])
def test_database_url_accepted(etc_dir: Path, url: str) -> None:
    with_system(etc_dir, f'database.url = "{url}"')
    assert load_config(etc_dir).get("database.url") == url


@pytest.mark.parametrize("url", [
    "mysql+pymysql://assp:S3cretPW@db.example/assp",  # no TLS
    "mysql+pymysql://assp:S3cretPW@192.0.2.10/assp?charset=utf8mb4",  # no TLS
    "mysql+pymysql://assp@db.example/assp?ssl_ca=/etc/ssl/certs/ca.pem",  # no password
])
def test_remote_database_needs_tls_and_a_password(etc_dir: Path, url: str) -> None:
    """R66, spec 3.4: a remote MySQL must use TLS and authentication."""
    with_system(etc_dir, f'database.url = "{url}"')
    (err,) = errors_of(etc_dir)
    assert "database.url" in err and "TLS" in err
    assert PASSWORD not in err and "db.example" not in err and "192.0.2.10" not in err


@pytest.mark.parametrize("url", [
    "redis://localhost:6379/0",
    "redis://127.0.0.1:6379/3",
    "redis://[::1]:6379/0",
    "redis://:S3cretPW@localhost:6379/0",
    "unix:///run/redis/redis-server.sock?db=0",
    "rediss://:S3cretPW@redis.example:6380/0",
    "rediss://assp:S3cretPW@192.0.2.20/1",
])
def test_redis_url_accepted(etc_dir: Path, url: str) -> None:
    with_system(etc_dir, f'redis.url = "{url}"')
    assert load_config(etc_dir).get("redis.url") == url


@pytest.mark.parametrize("url", [
    "redis://:S3cretPW@redis.example:6379/0",  # no TLS
    "redis://192.0.2.20:6379/0",  # neither
    "rediss://redis.example:6380/0",  # no password
    "rediss://assp@redis.example:6380/0",  # no password
])
def test_remote_redis_needs_tls_and_a_password(etc_dir: Path, url: str) -> None:
    """R66, spec 3.4: a remote Redis must use TLS (rediss://) and a password."""
    with_system(etc_dir, f'redis.url = "{url}"')
    (err,) = errors_of(etc_dir)
    assert "redis.url" in err and "rediss://" in err
    assert PASSWORD not in err and "redis.example" not in err and "192.0.2.20" not in err


@pytest.mark.parametrize("url", [
    "mysql+pymysql:/assp:S3cretPW@db/assp",  # a typo: one slash
    "assp:S3cretPW@db",
    "mysql+pymysql://assp:S3cretPW@db:port/assp",
])
def test_invalid_database_url_never_echoed(etc_dir: Path, url: str) -> None:
    with_system(etc_dir, f'database.url = "{url}"')
    (err,) = errors_of(etc_dir)
    assert "assp-ng.toml" in err and "database.url" in err
    assert PASSWORD not in err and url not in err


@pytest.mark.parametrize("listen", ["127.0.0.1:8025", "[::1]:8025", "localhost:0",
                                    "127.0.0.2:65535", "LOCALHOST:8025"])
def test_health_listen_on_loopback_accepted(etc_dir: Path, listen: str) -> None:
    with_system(etc_dir, f'health.listen = "{listen}"')
    assert load_config(etc_dir).get("health.listen") == listen


@pytest.mark.parametrize("listen", [
    "0.0.0.0:8025", "[::]:8025", "[2001:db8::1]:8025", "192.0.2.1:8025", "mx.example.com:8025",
    "8025", "127.0.0.1", "127.0.0.1:", ":8025", "127.0.0.1:http", "127.0.0.1:70000",
    "[::1]", "[::1:8025",
])
def test_health_listen_must_be_loopback_host_and_port(etc_dir: Path, listen: str) -> None:
    with_system(etc_dir, f'health.listen = "{listen}"')
    (err,) = errors_of(etc_dir)
    assert "assp-ng.toml" in err and "health.listen" in err
    assert listen not in err
