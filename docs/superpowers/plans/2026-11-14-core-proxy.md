# ASSP-NG Subproject 1 — Core SMTP Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the ASSP-NG core: an asyncio SMTP proxy in front of Postfix with TLS, AUTH passthrough, XCLIENT, buffered DATA, a check/scoring framework with limits and an escalating penalty box, Redis state with a degraded mode, layered configuration, operations tooling, a CLI and a Postfix integration assistant.

**Architecture:** A single asyncio process (`python3 -m asspng.proxy`) runs one `Session` coroutine per client and relays commands in lockstep to a per-session backend connection. Pure protocol units (`smtp/`), configuration (`config/`), state (`state/`) and checks (`checks/`) are built and tested first. They are then wired into `proxy/session.py` and `service/app.py`. MySQL is used only outside the hot path (local domains, audit). Redis holds the hot state, and `MemoryStore` takes over during Redis outages.

**Tech Stack:** Python 3.12+ (Debian 13: 3.13.5); `asyncio`, `ssl`, `ipaddress`, `tomllib` (stdlib); Debian packages python3-dnspython 2.7, python3-redis 6.1 (`redis.asyncio`), python3-pymysql 1.1, python3-sqlalchemy 2.0, python3-alembic 1.13, python3-systemd 235, python3-cryptography 43, python3-tomlkit 0.13; tests: python3-pytest 8.3, python3-pytest-asyncio 0.25, python3-hypothesis, python3-pytest-cov, python3-mypy 1.15, python3-flake8 7.1, redis-server, swaks, postfix (smtp-source/smtp-sink), shellcheck.

**Spec:** `docs/superpowers/specs/2026-11-12-core-proxy-design.md` (section numbers below such as "§4.7" refer to it). Later-subproject decisions: `docs/superpowers/specs/2026-11-14-later-subprojects-decisions.md`. Neither is implemented here.

## Global Constraints

- Python ≥ 3.12. No dependency outside the official Debian 13 repositories. No pip, no venv, no Docker.
- Code, comments, docstrings, docs, log messages and commit messages are in English.
- Every source file starts with `# SPDX-License-Identifier: GPL-3.0-or-later`. `LICENSE` is a copy of `/usr/share/common-licenses/GPL-3`.
- Package name `asspng`, CLI name `assp-ng`, service unit `assp-ng-proxy.service`, system user and group `assp-ng`.
- Tests run from the repository root with `python3 -m pytest` (`pythonpath = ["."]`). The package is never installed during development.
- `mypy --strict` must pass for `asspng/smtp`, `asspng/proxy`, `asspng/checks` and `asspng/state`. `flake8` (max line length 100) must pass for the whole tree.
- Coverage ≥ 85 % for `asspng/smtp`, `asspng/proxy`, `asspng/checks` and `asspng/state`.
- AUTH passwords never appear in any log, debug output, exception message or test failure output.
- Commits use conventional prefixes (`feat:`, `test:`, `docs:`, `build:`, `ci:`) and end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Default ports and paths: backends `127.0.0.1:10125` (smtp) and `127.0.0.1:10587` (submission kinds), health `127.0.0.1:8025`, `/etc/assp-ng`, `/var/lib/assp-ng/{spool,cache}`, `/var/log/assp-ng`, `/run/assp-ng/control.sock`, code in `/opt/assp-ng`.

## Review Focus

1. **Real-world command syntax:** lowercase verbs, `MAIL FROM: <a@b>` with a space after the colon, parameters `BODY=8BITMIME SMTPUTF8 SIZE=123`, quoted local parts and source routes. All must be accepted, as Postfix accepts them. The tests are in Task 3.
2. **Client vanishing mid-DATA or while the backend answers:** the spool file is deleted, the buffer budget and the connection slot are released, the backend connection is closed, and no traceback is logged above DEBUG. The test is in Task 26.
3. **Case and IDN variants of local domains:** `Jano@EXAMPLE.com` and `jano@bücher.example` versus a stored `xn--bcher-kva.example` must resolve to the same relay decision and the same `user.d`/`domain.d` file. The tests are in Tasks 3, 10 and 11.
4. **IPv4 clients on IPv6 sockets** (`::ffff:203.0.113.5`) must be keyed, logged, rate-limited and penalised as IPv4 `/32`. The tests are in Tasks 2 and 31.
5. **Reload during active sessions:** a running transaction keeps the policy it started with, new sessions use the new configuration, and an invalid reload changes nothing. The test is in Task 31.

## Plan decisions (where the spec leaves a choice)

- **EHLO filtering uses an allow-list:** only `SIZE`, `8BITMIME`, `SMTPUTF8`, `ENHANCEDSTATUSCODES` and `DSN` are kept from the MTA. Everything else is dropped. This is safe for unknown future extensions.
- **The test MTA is a small scripted asyncio server** (`tests/support/fake_mta.py`) instead of `aiosmtpd`, because `aiosmtpd` cannot advertise or handle `XCLIENT`.
- **Session abuse limits are enforced by the session itself**, not through the engine, like input limits: protocol errors, invalid recipients and relay attempts. They are always active and add IP score. Messages per session and recipients per message are the `session_limits` check (§5.4) and follow check modes.
- **IP score defaults** (the spec gives no values): `conn_limits` 5, `auth_limits` 20, protocol error 10, invalid recipient 10, relay denied 10.
- **Backends are plaintext only.** `config check` and the loader reject a submission listener whose backend is not a loopback address, because AUTH credentials would cross the network unencrypted. Remote backends with STARTTLS are left for later.
- **`domain.d` matching is exact:** `domain.d/example.com.toml` does not apply to `sub.example.com`.
- **`max_message_size` defaults to 52428800 bytes (50 MiB).** The documentation tells the admin to align it with Postfix `message_size_limit`.
- **ISPConfig hosts:** `assp-ng postfix apply` refuses to modify Postfix on ISPConfig hosts until the custom-template mechanism has been verified on the test server (§8.10). `check` and `plan` work everywhere.

---

## File Structure

```
pyproject.toml  .flake8  LICENSE  README.md
asspng/__init__.py                      __version__
asspng/net/ipnet.py                     parse_ip, network_key, is_private, parse_cidr_strict, NetworkSet, load_network_file
asspng/net/dns.py                       PtrResult, PtrResolver protocol, DnsPtrResolver
asspng/smtp/address.py                  Address, parse_path, normalize_domain
asspng/smtp/commands.py                 Command, parse_command, MailFrom, RcptTo, parse_mail_from, parse_rcpt_to
asspng/smtp/replies.py                  Reply, read_reply, standard reply constants
asspng/smtp/lines.py                    read_line, LineTooLong, ConnectionClosed, ReadTimeout
asspng/smtp/ehlo.py                     filter_ehlo
asspng/smtp/datacodec.py                DataReceiver, Stuffer
asspng/smtp/headers.py                  split_header, strip_fields, format_field
asspng/proxy/buffer.py                  BufferBudget, MessageBuffer, purge_spool
asspng/proxy/connections.py             ConnectionTracker
asspng/proxy/xclient.py                 format_xclient
asspng/proxy/backend.py                 Backend protocol, SmtpBackend, Backend errors
asspng/proxy/auth.py                    AuthExchange, redact_auth
asspng/proxy/session.py                 SessionDeps, Session
asspng/proxy/listener.py                ListenerManager
asspng/proxy/__main__.py                entry point -> asspng.service.app.main
asspng/config/errors.py                 ConfigError
asspng/config/registry.py               Level, Setting, Registry, parse_duration
asspng/config/settings.py               REGISTRY with every subproject-1 setting
asspng/config/model.py                  ListenerKind, ListenerConfig, CertificateConfig, ConfigSnapshot
asspng/config/loader.py                 load_config
asspng/config/policy.py                 Policy, PolicyResolver
asspng/config/editor.py                 set_value, unset_value (tomlkit, atomic, .bak)
asspng/config/docgen.py                 render_reference, render_default_toml
asspng/domains/index.py                 DomainEntry, DomainIndex, load_snapshot, save_snapshot
asspng/domains/refresher.py             DomainHolder, DomainRefresher
asspng/state/base.py                    StateStore protocol, StateError
asspng/state/memory_store.py            MemoryStore
asspng/state/redis_store.py             RedisStore, EventBus
asspng/state/controller.py              StateMode, StateController
asspng/checks/base.py                   Phase, Mode, CheckResult, CheckSettings, SessionInfo, TransactionInfo, CheckContext, Check
asspng/checks/engine.py                 Outcome, Decision, CheckEngine
asspng/checks/penalty_box.py            PenaltyStatus, PenaltyBox, PenaltyBoxCheck
asspng/checks/limits.py                 ConnLimitsCheck, SessionLimitsCheck, AuthLimitsCheck, UserRateCheck
asspng/tls/store.py                     CertificateStore, make_server_context, INTERMEDIATE_CIPHERS
asspng/db/schema.py, db/migrate.py, db/migrations/versions/0001_initial.py, db/repository.py
asspng/log/redact.py, log/maillog.py, log/setup.py, log/debug.py
asspng/service/systemd.py, service/health.py, service/alerts.py, service/memory.py,
asspng/service/control.py, service/app.py
asspng/cli/__main__.py, cli/main.py, cli/config_cmd.py, cli/ops_cmd.py, cli/postfix_cmd.py
asspng/postfix/inspect.py, postfix/plan.py, postfix/apply.py
packaging/systemd/assp-ng-proxy.service, packaging/systemd/assp-ng-notify@.service,
packaging/logrotate/assp-ng, packaging/install.sh, packaging/bin/assp-ng,
packaging/certbot/assp-ng-deploy-hook, packaging/config/assp-ng.toml.example
tests/conftest.py, tests/support/{fake_mta.py,certs.py,redis_server.py,smtp_client.py}
tests/unit/..., tests/session/..., tests/integration/..., tests/security/..., tests/load/run_load.sh
docs/development.md, docs/installation.md, docs/acceptance-checklist.md, docs/configuration.md (generated)
.github/workflows/ci.yml
```

---

## Milestone 1 — Foundations

### Task 1: Project skeleton, tooling and CI skeleton

**Files:**
- Create: `pyproject.toml`, `.flake8`, `LICENSE`, `README.md`, `asspng/__init__.py`, `tests/conftest.py`, `tests/unit/test_version.py`, `docs/development.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `asspng.__version__: str = "0.1.0.dev0"`. Fixture `fake_clock` (in `tests/conftest.py`): an object with `.now() -> float` and `.advance(seconds: float) -> None`, starting at `1_000_000.0`.

- [ ] **Step 1: Install dev packages.** This needs root, so ask the user to run:
  `apt install python3-dnspython python3-redis python3-pymysql python3-sqlalchemy python3-alembic python3-systemd python3-cryptography python3-tomlkit python3-pytest python3-pytest-asyncio python3-hypothesis python3-pytest-cov python3-mypy python3-flake8 redis-server swaks shellcheck`.
  Record the same list in `docs/development.md`, together with how to run the tests and the `ASSPNG_TEST_DB_URL` variable.
- [ ] **Step 2: Write the failing test** `tests/unit/test_version.py`:
  ```python
  import asspng
  def test_version_is_pep440_dev():
      assert asspng.__version__ == "0.1.0.dev0"
  ```
- [ ] **Step 3: Run it.** `python3 -m pytest tests/unit/test_version.py -v` → FAIL (`ModuleNotFoundError`).
- [ ] **Step 4: Create the skeleton files.**
  - `pyproject.toml`: `[project]` metadata (name `assp-ng`, license `GPL-3.0-or-later`, `requires-python = ">=3.12"`);
    `[tool.pytest.ini_options]` with `pythonpath=["."]`, `asyncio_mode="auto"`, `asyncio_default_fixture_loop_scope="function"`, `testpaths=["tests"]`;
    `[tool.mypy]` with `python_version="3.12"`, `strict=true` for the four core packages via `[[tool.mypy.overrides]]`, and `ignore_missing_imports` for `systemd.*`, `redis.*`, `tomlkit.*`;
    `[tool.coverage.run]` with `source=["asspng"]`.
  - `.flake8`: `max-line-length = 100`.
  - `LICENSE`: copied from `/usr/share/common-licenses/GPL-3`.
  - `README.md`: one-paragraph description and a link to the spec.
  - `ci.yml`: one job in container `debian:trixie` that apt-installs the Step 1 list and runs `python3 -m flake8`, `python3 -m mypy asspng` and `python3 -m pytest tests/unit`. Debian's `python3-flake8` and `python3-mypy` install no `flake8`/`mypy` commands, so every invocation uses `python3 -m`.
- [ ] **Step 5: Run it.** `python3 -m pytest tests/unit -v && python3 -m flake8 && python3 -m mypy asspng` → all pass.
- [ ] **Step 6: Commit** `build: add project skeleton, tooling and CI`.

### Task 2: IP and network helpers

**Files:**
- Create: `asspng/net/__init__.py`, `asspng/net/ipnet.py`, `tests/unit/net/test_ipnet.py`

**Interfaces:**
- Produces:
  - `IPAddress = IPv4Address | IPv6Address` and `IPNetwork = IPv4Network | IPv6Network`
  - `parse_ip(text: str) -> IPAddress`: strips brackets and a `%zone`, and unwraps IPv4-mapped IPv6 addresses
  - `network_key(addr: IPAddress, v4_prefix: int = 32, v6_prefix: int = 64) -> str`
  - `is_private(addr: IPAddress) -> bool`
  - `parse_cidr_strict(text: str) -> IPNetwork`: raises `ValueError` when host bits are set; a bare address becomes `/32` or `/128`
  - `class NetworkSet`: `__init__(networks: Iterable[IPNetwork])`, `__contains__(addr: IPAddress) -> bool`, `__len__`
  - `load_network_file(path: Path) -> list[IPNetwork]`: `#` comments and blank lines are ignored; errors raise `ValueError("<path>:<line>: <reason>")`

- [ ] **Step 1: Write failing tests.**
  ```python
  def test_mapped_ipv4_is_ipv4(): assert parse_ip("::ffff:203.0.113.5") == IPv4Address("203.0.113.5")
  def test_bracketed_v6(): assert parse_ip("[2001:db8::1]") == IPv6Address("2001:db8::1")
  def test_key_v4(): assert network_key(parse_ip("203.0.113.5")) == "203.0.113.5/32"
  def test_key_v6_64(): assert network_key(parse_ip("2001:db8:1:2:3:4:5:6")) == "2001:db8:1:2::/64"
  def test_key_mapped(): assert network_key(parse_ip("::ffff:203.0.113.5")) == "203.0.113.5/32"
  def test_private(): assert is_private(parse_ip("10.1.2.3")) and is_private(parse_ip("::1")) and is_private(parse_ip("fe80::1")) and not is_private(parse_ip("8.8.8.8"))
  def test_strict_rejects_host_bits(): pytest.raises(ValueError, parse_cidr_strict, "203.0.113.5/24")
  def test_strict_bare(): assert str(parse_cidr_strict("2001:db8::1")) == "2001:db8::1/128"
  def test_networkset(): s = NetworkSet([parse_cidr_strict("192.0.2.0/24")]); assert parse_ip("192.0.2.9") in s and parse_ip("192.0.3.1") not in s
  def test_file_errors_carry_line(tmp_path): p = tmp_path/"n.txt"; p.write_text("# c\n192.0.2.0/24\nbogus\n"); with pytest.raises(ValueError, match=":3:"): load_network_file(p)
  ```
- [ ] **Step 2: Run them.** `python3 -m pytest tests/unit/net -v` → FAIL (import error).
- [ ] **Step 3: Implement `asspng/net/ipnet.py`** with the `ipaddress` stdlib. `is_private` is true for `is_private`, `is_loopback`, `is_link_local`, `is_unspecified` and `is_reserved`. `NetworkSet` keeps one list per family and checks `addr in net`. Sets are small, so a linear scan is fine.
- [ ] **Step 4: Run them.** Same command → PASS.
- [ ] **Step 5: Commit** `feat(net): add IP parsing, network keys and network sets`.

### Task 3: SMTP addresses and command parsing

**Files:**
- Create: `asspng/smtp/__init__.py`, `asspng/smtp/address.py`, `asspng/smtp/commands.py`, `tests/unit/smtp/test_address.py`, `tests/unit/smtp/test_commands.py`

**Interfaces:**
- Produces:
  - `class AddressError(ValueError)`
  - `@dataclass(frozen=True) Address(local: str, domain: str)`, with `__str__ -> "local@domain"` (`"postmaster"` when the domain is empty) and `key -> str`, which is the lowercase local part + `@` + the normalized domain
  - `normalize_domain(domain: str) -> str`: lowercase, IDNA A-labels via the stdlib `idna` codec, trailing dot removed
  - `parse_path(text: str) -> Address | None`: parses `<…>`, returns `None` for `<>`, drops a source route, accepts quoted local parts and UTF-8, accepts `<postmaster>` without a domain
  - `class CommandSyntaxError(ValueError)`
  - `@dataclass(frozen=True) Command(verb: str, arg: str)`: verb uppercased
  - `parse_command(line: bytes) -> Command`: UTF-8 decode; errors raise `CommandSyntaxError`
  - `@dataclass(frozen=True) MailFrom(path: Address | None, params: dict[str, str | None])`
  - `@dataclass(frozen=True) RcptTo(path: Address, params: dict[str, str | None])`
  - `parse_mail_from(arg: str, max_params: int = 10) -> MailFrom` and `parse_rcpt_to(arg: str, max_params: int = 10) -> RcptTo`: parameter keys are uppercased; more than `max_params` parameters raises `CommandSyntaxError`

- [ ] **Step 1: Write failing tests**, including Review Focus 1 and 3:
  ```python
  def test_idn_and_case(): assert parse_path("<Jano@BÜCHER.Example>").key == "jano@xn--bcher-kva.example"
  def test_null_path(): assert parse_path("<>") is None
  def test_source_route(): assert str(parse_path("<@a.example,@b.example:x@c.example>")) == "x@c.example"
  def test_quoted_local(): assert parse_path('<"john doe"@example.com>').local == '"john doe"'
  def test_postmaster(): assert parse_path("<postmaster>") == Address("postmaster", "")
  def test_lowercase_verb(): assert parse_command(b"mail from:<a@b.example>") == Command("MAIL", "from:<a@b.example>")
  def test_mail_space_and_params(): m = parse_mail_from("FROM: <a@b.example> BODY=8BITMIME SMTPUTF8 SIZE=123"); assert m.params == {"BODY": "8BITMIME", "SMTPUTF8": None, "SIZE": "123"}
  def test_rcpt_postmaster(): assert parse_rcpt_to("TO:<postmaster>").path.domain == ""
  def test_too_many_params(): pytest.raises(CommandSyntaxError, parse_mail_from, "FROM:<a@b.example> " + " ".join(f"P{i}=1" for i in range(11)))
  def test_garbage(): pytest.raises(CommandSyntaxError, parse_command, b"\xff\xfe")
  ```
- [ ] **Step 2: Run them.** `python3 -m pytest tests/unit/smtp -v` → FAIL.
- [ ] **Step 3: Implement** both modules. `FROM:`/`TO:` match case-insensitively, with optional whitespace before the `<`.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(smtp): parse commands, paths and parameters`.

### Task 4: Replies and line reading

**Files:**
- Create: `asspng/smtp/replies.py`, `asspng/smtp/lines.py`, `tests/unit/smtp/test_replies.py`, `tests/unit/smtp/test_lines.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) Reply(code: int, lines: tuple[str, ...])` with:
    - `encode() -> bytes`
    - `of(code: int, *lines: str) -> Reply` (classmethod)
    - `is_positive` (2xx or 3xx), `is_temporary` (4xx), `is_permanent` (5xx)
  - `class BackendProtocolError(Exception)` and `class ReadTimeout(Exception)`
  - `async read_reply(reader: asyncio.StreamReader, timeout: float, max_lines: int = 100) -> Reply`
  - `class LineTooLong(Exception)` and `class ConnectionClosed(Exception)`
  - `async read_line(reader: asyncio.StreamReader, limit: int, timeout: float) -> bytes`: returns the line without `\r\n`/`\n`. An over-long line is consumed up to its newline and then raises `LineTooLong`. EOF raises `ConnectionClosed`. A timeout raises `ReadTimeout`.
  - The following constants live in `replies.py` (exact texts from the spec):

    | Constant | Reply |
    |---|---|
    | `R_RELAY_DENIED` | 554 "5.7.1 Relay access denied" |
    | `R_TOO_MANY_RCPT` | 452 "4.5.3 Too many recipients" |
    | `R_POLICY_SPLIT` | 452 "4.5.3 Too many recipients, try again" |
    | `R_AUTH_REQUIRED` | 530 "5.7.0 Authentication required" |
    | `R_ENCRYPTION_REQUIRED` | 538 "5.7.11 Encryption required" |
    | `R_SIZE` | 552 "5.3.4 Message size exceeds limit" |
    | `R_NO_RCPT` | 554 "5.5.1 No valid recipients" |
    | `R_SCORE` | 554 "5.7.1 Message score too high" |
    | `R_VRFY` | 252 "2.5.2 Cannot VRFY user" |
    | `R_NOT_IMPL` | 502 "5.5.1 Command not implemented" |
    | `R_SYNTAX` | 500 "5.5.2 Syntax error" |
    | `R_LINE_TOO_LONG` | 500 "5.5.2 Line too long" |
    | `R_BAD_ARG` | 501 "5.5.4 Invalid argument" |
    | `R_TLS_READY` | 220 "2.0.0 Ready to start TLS" |
    | `R_TLS_UNAVAILABLE` | 454 "4.7.0 TLS not available" |
    | `R_TLS_ACTIVE` | 503 "5.5.1 TLS already active" |
    | `R_BAD_SEQUENCE` | 503 "5.5.1 Bad sequence of commands" |
    | `R_AUTH_TEMPFAIL` | 454 "4.7.0 Temporary authentication failure" |
    | `R_BACKEND_DOWN` | 421 "4.3.2 Service temporarily unavailable" |
    | `R_TEMPFAIL` | 421 "4.3.0 Service temporarily unavailable" |
    | `R_TEMPFAIL_CMD` | 451 "4.3.0 Service temporarily unavailable" |
    | `R_TOO_MANY_ERRORS` | 421 "4.7.0 Too many errors" |
    | `R_TRY_LATER` | 421 "4.7.0 Try again later" |
    | `R_BACKEND_LOST` | 421 "4.4.2 Connection to mail server lost" |
    | `R_RATE` | 451 "4.7.1 Rate limit exceeded" |
    | `R_IDLE` | 421 "4.4.2 Idle timeout" |
    | `R_INTERNAL` | 421 "4.3.0 Internal error, try again later" |
    | `R_BYE` | 221 "2.0.0 Bye" |
    | `R_DATA_GO` | 354 "End data with <CR><LF>.<CR><LF>" |
    | `R_HELP` | 214 "2.0.0 See RFC 5321" |
    | `R_DOMAINS_UNAVAILABLE` | 451 "4.3.0 Local domain list unavailable" |

- [ ] **Step 1: Write failing tests.**
  ```python
  def test_encode_multiline(): assert Reply.of(250, "a", "b").encode() == b"250-a\r\n250 b\r\n"
  async def test_read_multiline(): r = await read_reply(reader_from(b"250-x\r\n250 y\r\n"), 1); assert r == Reply(250, ("x", "y"))
  async def test_mixed_codes_rejected(): with pytest.raises(BackendProtocolError): await read_reply(reader_from(b"250-x\r\n251 y\r\n"), 1)
  async def test_line_too_long_consumes_rest(): r = reader_from(b"A"*3000 + b"\r\nNOOP\r\n"); with pytest.raises(LineTooLong): await read_line(r, 2048, 1); assert await read_line(r, 2048, 1) == b"NOOP"
  async def test_eof(): with pytest.raises(ConnectionClosed): await read_line(reader_from(b""), 2048, 1)
  ```
  `reader_from(data)` is a helper in `tests/conftest.py`: a `StreamReader` fed with `data` and then EOF.
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.** The `StreamReader` is created with a 64 KiB limit. `read_line` uses `readuntil(b"\n")` and handles `LimitOverrunError` by discarding until the newline.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(smtp): add replies and bounded line reading`.

### Task 5: EHLO capability filter

**Files:**
- Create: `asspng/smtp/ehlo.py`, `tests/unit/smtp/test_ehlo.py`

**Interfaces:**
- Consumes: `Reply` (Task 4).
- Produces: `filter_ehlo(mta: Reply, *, hostname: str, offer_starttls: bool, auth_allowed: bool, max_size: int) -> Reply`.
  - The first line is `hostname`.
  - The kept set is `SIZE`, `8BITMIME`, `SMTPUTF8`, `ENHANCEDSTATUSCODES` and `DSN`.
  - `SIZE` becomes `SIZE <min(mta_size or max_size, max_size)>`.
  - `STARTTLS` is appended if `offer_starttls`.
  - `AUTH PLAIN LOGIN` is appended if `auth_allowed` and the MTA advertised `AUTH`.

- [ ] **Step 1: Write failing tests.**
  ```python
  MTA = Reply.of(250, "mta.local", "PIPELINING", "SIZE 10240000", "VRFY", "ETRN", "STARTTLS", "AUTH PLAIN LOGIN", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN", "SMTPUTF8", "CHUNKING", "XCLIENT NAME ADDR", "XFORWARD NAME")
  def test_filter(): r = filter_ehlo(MTA, hostname="mx1.example.com", offer_starttls=True, auth_allowed=False, max_size=52428800); assert r.lines == ("mx1.example.com", "SIZE 10240000", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN", "SMTPUTF8", "STARTTLS")
  def test_auth_only_if_mta_has_it(): assert "AUTH PLAIN LOGIN" not in filter_ehlo(Reply.of(250, "m", "SIZE"), hostname="h", offer_starttls=False, auth_allowed=True, max_size=1).lines
  def test_size_capped(): assert "SIZE 1000" in filter_ehlo(Reply.of(250, "m", "SIZE 0"), hostname="h", offer_starttls=False, auth_allowed=False, max_size=1000).lines
  ```
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement** the filter. The kept capabilities keep the MTA's order.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(smtp): filter EHLO capabilities with an allow-list`.

### Task 6: DATA codec and header utilities

**Files:**
- Create: `asspng/smtp/datacodec.py`, `asspng/smtp/headers.py`, `tests/unit/smtp/test_datacodec.py`, `tests/unit/smtp/test_headers.py`, `tests/security/test_smuggling.py`

**Interfaces:**
- Produces:
  - `class DataReceiver`:
    - `__init__(sink: Callable[[bytes], None])`: `sink` receives normalized, unstuffed content with CRLF line ends
    - `feed(chunk: bytes) -> bool`: returns `True` once the end of data has been seen
    - `leftover: bytes`: bytes after the terminator
  - `class Stuffer`: `feed(chunk: bytes) -> bytes` and `finish() -> bytes`. The output is dot-stuffed, `finish` ensures a final CRLF and appends `.\r\n`.
  - `split_header(data: bytes) -> tuple[bytes, int]`: returns the header block (including the CRLF that ends the last field) and the offset where the body starts (after the empty line). If there is no empty line, all of `data` is the header.
  - `strip_fields(header: bytes, prefix: str) -> bytes`: removes every field whose name starts with `prefix` (case-insensitive), including folded continuation lines.
  - `format_field(name: str, value: str) -> bytes`: `name: value\r\n`. Values longer than 998 bytes raise `ValueError`.
- Algorithm (`DataReceiver`), which the tests pin:
  1. **Physical lines** end only at `\r\n`.
  2. A physical line that is exactly `.` is the end of data.
  3. A physical line starting with `.` loses that one dot (RFC 5321 transparency).
  4. Inside a physical line, every bare `\r` or bare `\n` becomes a CRLF line break. The resulting **logical lines** are never unstuffed and never terminate the data.
  5. A `\r` at a chunk boundary is held until the next chunk.
  6. Physical lines longer than 8 KiB are flushed in pieces. They cannot be the terminator once they are longer than one byte.

- [ ] **Step 1: Write failing tests**, including `tests/security/test_smuggling.py`:
  ```python
  @pytest.mark.parametrize("smuggle", [b"\n.\n", b"\r.\r", b"\r\n.\r", b"\n.\r\n", b"\r.\r\n", b".\n"])
  def test_smuggling_variant_is_content(smuggle):
      out = []; rx = DataReceiver(out.append)
      done = rx.feed(b"Subject: a\r\n\r\nbody" + smuggle + b"MAIL FROM:<x@evil>\r\n.\r\n")
      assert done and b"MAIL FROM:<x@evil>" in b"".join(out)
      st = Stuffer(); stuffed = st.feed(b"".join(out)) + st.finish()
      assert stuffed.count(b"\r\n.\r\n") == 1 and stuffed.endswith(b"\r\n.\r\n")  # the only terminator comes from finish()
  def test_unstuff_and_terminate(): out=[]; rx=DataReceiver(out.append); assert rx.feed(b"..x\r\n.\r\n"); assert b"".join(out) == b".x\r\n"
  def test_split_chunks_cr_boundary(): out=[]; rx=DataReceiver(out.append); assert not rx.feed(b"a\r"); assert rx.feed(b"\n.\r\n"); assert b"".join(out) == b"a\r\n"
  @given(st.binary(max_size=4000))
  def test_roundtrip(content): ...  # normalize(content) fed through Stuffer then DataReceiver equals normalized content
  def test_strip_folded(): assert strip_fields(b"X-ASSP-NG-Score: 1\r\n  folded\r\nSubject: s\r\n", "x-assp-ng-") == b"Subject: s\r\n"
  ```
- [ ] **Step 2: Run them.** `python3 -m pytest tests/unit/smtp tests/security -v` → FAIL.
- [ ] **Step 3: Implement** both modules following the algorithm above.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(smtp): add smuggling-safe DATA codec and header utilities`.

### Task 7: Message buffer with memory budget and spool

**Files:**
- Create: `asspng/proxy/__init__.py`, `asspng/proxy/buffer.py`, `tests/unit/proxy/test_buffer.py`

**Interfaces:**
- Produces:
  - `class BufferBudget`: `__init__(total: int)`, `try_reserve(n: int) -> bool`, `release(n: int) -> None`, `used: int`.
  - `class MessageBuffer`:
    - `__init__(budget: BufferBudget, spool_dir: Path, memory_limit: int, max_size: int)`
    - `write(data: bytes) -> None`
    - `size: int`, `oversize: bool`, `spooled: bool`
    - `read_head(limit: int) -> bytes`
    - `iter_chunks(start: int = 0, chunk: int = 65536) -> Iterator[bytes]`
    - `close() -> None`: idempotent; deletes the spool file and releases the budget
    - context manager
  - `purge_spool(spool_dir: Path) -> int`
- Spool files are created with `tempfile.mkstemp(dir=spool_dir)` and chmod 0600. The memory part spills to the file when `memory_limit` is exceeded or `try_reserve` fails. Above `max_size` the data is counted but discarded, and `oversize` becomes `True`.

- [ ] **Step 1: Write failing tests:**
  - `test_small_stays_in_memory`
  - `test_spills_over_memory_limit`: the file exists with mode 0600 and the budget is released after the spill
  - `test_spills_when_budget_exhausted`
  - `test_oversize_discards`: `size` stops at `max_size` and `oversize` is true
  - `test_close_deletes_and_releases`: `budget.used == 0` and the file is gone
  - `test_close_idempotent`
  - `test_purge_spool_removes_leftovers`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add message buffer with memory budget and private spool`.

---

## Milestone 2 — Configuration and domains

### Task 8: Settings registry

**Files:**
- Create: `asspng/config/__init__.py`, `asspng/config/errors.py`, `asspng/config/registry.py`, `asspng/config/settings.py`, `tests/unit/config/test_registry.py`

**Interfaces:**
- Produces:
  - `class ConfigError(Exception)` with an `errors: list[str]` attribute.
  - `class Level(Enum)` with values `SYSTEM`, `RECIPIENT` and `SENDER`.
  - `@dataclass(frozen=True) Setting`:
    - `key: str`, `kind: str` (one of `int`, `float`, `bool`, `str`, `duration`, `list[duration]`, `list[str]`)
    - `default: object`, `level: Level`, `description: str`
    - `choices: tuple[str, ...] | None = None`, `minimum: float | None = None`, `maximum: float | None = None`
    - `fingerprint: bool = True`: whether the setting takes part in recipient grouping (RECIPIENT level only)
  - `class Registry`: `register(s: Setting) -> None` (a duplicate raises), `get(key: str) -> Setting` (raises `KeyError`), `all() -> list[Setting]`, `coerce(key: str, value: object) -> object` (raises `ConfigError`).
  - `parse_duration(text: str) -> int` accepts `s`, `m`, `h` and `d` suffixes.
  - `REGISTRY: Registry` lives in `settings.py`.
- Every subproject-1 setting goes into `settings.py` with the default and level shown below:

  | Key(s) | Default | Level |
  |---|---|---|
  | `instance`, `hostname` (empty means `socket.getfqdn()`), `banner.text` | `""` | SYSTEM |
  | `database.url` | `""` | SYSTEM |
  | `redis.url` | `"redis://localhost:6379/0"` | SYSTEM |
  | `redis.key_prefix` | `"asspng:"` | SYSTEM |
  | `redis.op_timeout_ms` | 200 | SYSTEM |
  | `state.on_redis_failure` | `"degraded"` (choices `degraded`, `tempfail`) | SYSTEM |
  | `state.failures_to_degrade` | 3 | SYSTEM |
  | `state.unreachable_to_degrade_s` | 2 | SYSTEM |
  | `state.probe_interval_s` | 10 | SYSTEM |
  | `state.memory_max_entries` | 200000 | SYSTEM |
  | `network.ipv4_prefix` | 32 | SYSTEM |
  | `network.ipv6_prefix` | 64 | SYSTEM |
  | `limits.net.concurrent` | 5 | SYSTEM |
  | `limits.net.connections_per_minute` | 30 | SYSTEM |
  | `limits.instance.concurrent` | 500 | SYSTEM |
  | `limits.session.messages` | 50 | SYSTEM |
  | `limits.session.protocol_errors` | 5 | SYSTEM |
  | `limits.session.invalid_recipients` | 5 | SYSTEM |
  | `limits.message.recipients` | 100 | SYSTEM |
  | `limits.auth.failures_per_net` | 5 | SYSTEM |
  | `limits.auth.failures_per_user` | 10 | SYSTEM |
  | `limits.auth.window` | `"15m"` | SYSTEM |
  | `limits.user.messages_per_minute` | 30 | SENDER |
  | `limits.user.messages_per_hour` | 300 | SENDER |
  | `limits.user.recipients_per_hour` | 1000 | SENDER |
  | `penalty_box.threshold` | 50 | SYSTEM |
  | `penalty_box.score_cap` | 100 | SYSTEM |
  | `penalty_box.score_ttl` | `"24h"` | SYSTEM |
  | `penalty_box.ladder` | `["24h", "7d", "30d"]` | SYSTEM |
  | `penalty_box.history` | `"90d"` | SYSTEM |
  | `abuse.protocol_error_ip_score`, `abuse.invalid_recipient_ip_score`, `abuse.relay_denied_ip_score` | 10 | SYSTEM |
  | `checks.conn_limits.{mode,ip_score,msg_score,timeout_ms}` | `"block"`, 5, 0, 1000 | SYSTEM |
  | `checks.penalty_box.{mode,ip_score,msg_score,timeout_ms}` | `"block"`, 0, 0, 1000 | SYSTEM |
  | `checks.session_limits.{mode,ip_score,msg_score,timeout_ms}` | `"block"`, 0, 0, 1000 | SYSTEM |
  | `checks.auth_limits.{mode,ip_score,msg_score,timeout_ms}` | `"block"`, 20, 0, 1000 | SYSTEM |
  | `checks.user_rate.{mode,ip_score,msg_score,timeout_ms}` | `"block"`, 0, 0, 1000 | SENDER |
  | `testmode` | false | RECIPIENT |
  | `scoring.limit` | 50 | RECIPIENT |
  | `scoring.warn` | 35 | RECIPIENT |
  | `scoring.add_header` | true | RECIPIENT |
  | `scoring.warn_subject_tag` | `""` | RECIPIENT |
  | `timeouts.tls_handshake` | 30 | SYSTEM |
  | `timeouts.backend_connect` | 10 | SYSTEM |
  | `timeouts.backend_banner` | 30 | SYSTEM |
  | `timeouts.command` | 300 | SYSTEM |
  | `timeouts.data_block` | 180 | SYSTEM |
  | `timeouts.data_total` | 600 | SYSTEM |
  | `timeouts.backend_command` | 300 | SYSTEM |
  | `timeouts.backend_final` | 600 | SYSTEM |
  | `timeouts.shutdown` | 30 | SYSTEM |
  | `timeouts.ptr` | 3 | SYSTEM |
  | `buffer.memory_per_message` | 1048576 | SYSTEM |
  | `buffer.memory_total` | 134217728 | SYSTEM |
  | `max_message_size` | 52428800 | SYSTEM |
  | `paths.spool` | `"/var/lib/assp-ng/spool"` | SYSTEM |
  | `paths.cache` | `"/var/lib/assp-ng/cache"` | SYSTEM |
  | `paths.run` | `"/run/assp-ng"` | SYSTEM |
  | `paths.log_dir` | `"/var/log/assp-ng"` | SYSTEM |
  | `health.listen` | `"127.0.0.1:8025"` | SYSTEM |
  | `alerts.email`, `alerts.webhook` | `""` | SYSTEM |
  | `alerts.smtp_server` | `"127.0.0.1:10125"` | SYSTEM |
  | `alerts.min_interval` | `"30m"` | SYSTEM |
  | `log.level` | `"info"` | SYSTEM |
  | `debug.max_size_mb` | 100 | SYSTEM |
  | `debug.default_duration` | `"30m"` | SYSTEM |
  | `debug.max_duration` | `"24h"` | SYSTEM |
  | `debug.max_duration_all` | `"1h"` | SYSTEM |
  | `debug.ring_lines` | 50 | SYSTEM |
  | `memory.soft_limit_mb` | 360 | SYSTEM |
  | `memory.idle_trim_after_s` | 60 | SYSTEM |
  | `memory.trim_interval_s` | 600 | SYSTEM |
  | `domains.refresh_interval_s` | 300 | SYSTEM |

- [ ] **Step 1: Write failing tests:**
  - `test_duration("90d") == 7776000`
  - `test_coerce_rejects_out_of_range`: `scoring.limit` with -1 raises `ConfigError`
  - `test_coerce_choices`: `checks.conn_limits.mode = "maybe"` raises
  - `test_levels`: `REGISTRY.get("testmode").level is Level.RECIPIENT` and `REGISTRY.get("limits.user.messages_per_hour").level is Level.SENDER`
  - `test_all_keys_documented`: every `description` is non-empty and in English
  - `test_duplicate_register_raises`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.** Durations are stored as strings and coerced to seconds by `coerce`.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(config): add typed settings registry with levels`.

### Task 9: Configuration model and layered loader

**Files:**
- Create: `asspng/config/model.py`, `asspng/config/loader.py`, `tests/unit/config/test_loader.py`; add an `etc_dir` fixture to `tests/conftest.py`

**Interfaces:**
- Consumes: the registry (Task 8), `load_network_file` and `NetworkSet` (Task 2), `normalize_domain` and `parse_path` (Task 3).
- Produces:
  - `class ListenerKind(Enum)` with values `SMTP = "smtp"`, `SUBMISSION = "submission"`, `SUBMISSIONS = "submissions"`.
  - `@dataclass(frozen=True) ListenerConfig(name: str, kind: ListenerKind, port: int, ipv4: bool, ipv6: bool, bind4: str, bind6: str, backend_host: str, backend_port: int, xclient: bool, auth: bool)`
  - `@dataclass(frozen=True) CertificateConfig(name: str, hostnames: tuple[str, ...], cert: Path, key: Path)`
  - `@dataclass(frozen=True) ConfigSnapshot`:
    - `system: Mapping[str, object]`: every SYSTEM key, resolved
    - `listeners: tuple[ListenerConfig, ...]`, `certificates: tuple[CertificateConfig, ...]`
    - `default_layer: Mapping[str, object]`, `domain_layers: Mapping[str, Mapping[str, object]]`, `user_layers: Mapping[str, Mapping[str, object]]`
    - `trusted: NetworkSet`, `exempt: NetworkSet`, `etc_dir: Path`
    - method `get(key: str) -> object`
  - `load_config(etc_dir: Path, registry: Registry = REGISTRY) -> ConfigSnapshot`: collects every problem and then raises a single `ConfigError`.
  - Fixture `etc_dir(tmp_path)` writes a minimal valid `assp-ng.toml` and `default.toml` with one `smtp` listener on port 0 and backend `127.0.0.1:1`.
- Rules (§7.1–§7.4):
  - Nested TOML tables are flattened to dotted keys. `[[listener]]` and `[[tls.certificate]]` are special arrays.
  - A missing `assp-ng.toml` is an error.
  - A missing `default.toml` is an error whose text contains `assp-ng config init`.
  - Unknown keys are errors.
  - A key at a forbidden level is an error: SYSTEM keys may appear only in `assp-ng.toml`, RECIPIENT and SENDER keys only in the policy files.
  - `domain.d/<name>.toml` must be named after the normalized domain, and `user.d/<name>.toml` after the normalized address key.
  - A submission-kind listener requires `auth = true`, a configured certificate and a loopback `backend_host`.
  - Listener defaults: `auth` follows the kind, `bind4 = "0.0.0.0"`, `bind6 = "::"`, `backend = "<host>:<port>"`.
  - `trusted-networks.txt` and `exempt-networks.txt` are optional; missing means empty.

- [ ] **Step 1: Write failing tests:**
  - `test_minimal_loads`
  - `test_missing_default_mentions_init`
  - `test_unknown_key_error`
  - `test_system_key_in_domain_file_is_error`
  - `test_domain_file_name_must_be_normalized`: `domain.d/Example.COM.toml` raises
  - `test_user_file_layer`: `user.d/jano@example.com.toml` with `scoring.limit = 99` appears in `user_layers["jano@example.com"]`
  - `test_submission_requires_cert_and_loopback`
  - `test_all_errors_reported_together`: two errors give `len(err.errors) == 2`
  - `test_network_files`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement** with `tomllib`.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(config): load and validate layered configuration`.

### Task 10: Policy resolver

**Files:**
- Create: `asspng/config/policy.py`, `tests/unit/config/test_policy.py`

**Interfaces:**
- Consumes: `ConfigSnapshot` (Task 9), `Address` (Task 3), `Registry` (Task 8).
- Produces:
  - `@dataclass(frozen=True) Policy(values: Mapping[str, object], sources: Mapping[str, str], fingerprint: str)`. Each source is one of `"user"`, `"domain"`, `"default"` or `"built-in"`.
  - `class PolicyResolver`:
    - `__init__(snapshot: ConfigSnapshot, registry: Registry = REGISTRY)`
    - `for_recipient(rcpt: Address) -> Policy`: RECIPIENT keys, resolved user → domain (exact match) → default → built-in
    - `for_sender(username: str) -> Policy`: SENDER keys, using the user and domain layers when `username` contains `@`
    - `default_policy() -> Policy`
- `fingerprint` is the first 16 hex characters of the SHA-256 of `repr(sorted((k, v) for k, v in values.items() if registry.get(k).fingerprint))`.

- [ ] **Step 1: Write failing tests:**
  - `test_user_over_domain_over_default`: values 99 / 80 / 60, with sources `user`, `domain`, `default`
  - `test_builtin_source`
  - `test_same_effective_values_same_fingerprint`: a user file that repeats the domain's value gives the same fingerprint
  - `test_different_testmode_different_fingerprint`
  - `test_idn_recipient_finds_domain_file` (Review Focus 3): rcpt `jano@BÜCHER.example` uses `domain.d/xn--bcher-kva.example.toml`
  - `test_sender_policy_uses_user_layer`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(config): resolve per-recipient and per-sender policy`.

### Task 11: Local domain index and snapshot

**Files:**
- Create: `asspng/domains/__init__.py`, `asspng/domains/index.py`, `tests/unit/domains/test_index.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) DomainEntry(domain: str, include_subdomains: bool, enabled: bool = True)`, where `domain` is normalized.
  - `class DomainIndex`:
    - `__init__(entries: Iterable[DomainEntry], available: bool = True)`
    - `is_local(domain: str) -> bool`: normalizes the input. An empty domain (bare `postmaster`) is always local. Disabled entries are ignored.
    - `available: bool`, `__len__`
    - `DomainIndex.unavailable() -> DomainIndex`: classmethod
  - `save_snapshot(path: Path, entries: Sequence[DomainEntry]) -> None`: atomic write via a temporary file and rename, JSON
  - `load_snapshot(path: Path) -> list[DomainEntry] | None`: `None` when the file is missing or corrupt

- [ ] **Step 1: Write failing tests:**
  - `test_exact_and_subdomains`
  - `test_case_and_idn`: an entry `xn--bcher-kva.example` matches `BÜCHER.example`
  - `test_empty_domain_is_local`
  - `test_disabled_ignored`
  - `test_snapshot_roundtrip`
  - `test_corrupt_snapshot_none`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(domains): add local domain index with snapshot`.

---

## Milestone 3 — State and checks

### Task 12: State store protocol and memory store

**Files:**
- Create: `asspng/state/__init__.py`, `asspng/state/base.py`, `asspng/state/memory_store.py`, `tests/unit/state/test_memory_store.py`

**Interfaces:**
- Produces:
  - `class StateError(Exception)`
  - `class StateStore(Protocol)`. Keys are given without the prefix.
    - `async incr_window(key: str, window_s: int) -> int`: `EXPIRE` is set only on the first increment
    - `async incr(key: str, ttl_s: int | None) -> int`: the TTL is refreshed on every call
    - `async get(key: str) -> str | None`
    - `async get_hash(key: str) -> dict[str, str]`
    - `async set_hash(key: str, values: Mapping[str, str], ttl_s: int | None) -> None`: replaces the whole hash
    - `async delete(*keys: str) -> int`
    - `async keys(pattern: str) -> list[str]`: glob
    - `async ttl(key: str) -> int | None`
    - `async ping() -> None`
    - `async publish(channel: str, message: str) -> None`
  - `class MemoryStore(StateStore)`: `__init__(max_entries: int, clock: Callable[[], float])`, `clear() -> None`. Eviction is LRU when full, and expiry is applied lazily on access.

- [ ] **Step 1: Write failing tests** with `fake_clock`:
  - `test_incr_window_expires_after_window`
  - `test_incr_window_ttl_not_extended`
  - `test_incr_refreshes_ttl`
  - `test_hash_ttl`
  - `test_lru_eviction_at_capacity`
  - `test_keys_glob`
  - `test_clear`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(state): add state store protocol and in-memory store`.

### Task 13: Redis store and event bus

**Files:**
- Create: `asspng/state/redis_store.py`, `tests/support/redis_server.py`, `tests/integration/state/test_redis_store.py`

**Interfaces:**
- Consumes: `StateStore` and `StateError` (Task 12).
- Produces:
  - `class RedisStore(StateStore)`: `__init__(url: str, prefix: str, op_timeout_s: float)` and `async close()`. Every redis or timeout error becomes `StateError`.
  - `class EventBus`:
    - `__init__(url: str, prefix: str)`
    - `async run(handler: Callable[[str], Awaitable[None]]) -> None`: subscribes to `<prefix>events` and reconnects every 5 s after an error
    - `async close()`
  - Fixture `redis_server` (session-scoped, in `tests/support/redis_server.py`): finds a free port and starts `redis-server --port N --save "" --appendonly no` in a temporary directory. It yields the URL and offers `.stop()` and `.start()`.

- [ ] **Step 1: Write failing tests:**
  - every `MemoryStore` behaviour from Task 12 re-run against `RedisStore`, through one shared parametrized test module `tests/support/store_contract.py` used by both. Move the Task 12 behaviour tests into this module and keep `tests/unit/state/test_memory_store.py` as a thin wrapper that runs the contract against `MemoryStore`
  - `test_prefix_applied`: the raw key `asspng:x` exists in Redis
  - `test_errors_become_state_error`: after `redis_server.stop()` an operation raises `StateError` within 0.5 s
  - `test_event_bus_receives`
- [ ] **Step 2: Run them.** `python3 -m pytest tests/integration/state -v` → FAIL.
- [ ] **Step 3: Implement** with `redis.asyncio.Redis.from_url(url, socket_timeout=…, socket_connect_timeout=…)`.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(state): add Redis store and event bus`.

### Task 14: State controller (degraded mode)

**Files:**
- Create: `asspng/state/controller.py`, `tests/unit/state/test_controller.py`

**Interfaces:**
- Consumes: `StateStore`, `MemoryStore`, `StateError`.
- Produces:
  - `class StateMode(Enum)` with values `NORMAL`, `DEGRADED` and `TEMPFAIL`.
  - `class StateController(StateStore)`:
    - `__init__(primary: StateStore, fallback: MemoryStore, *, failures_to_degrade: int = 3, unreachable_s: float = 2.0, strict: bool = False, clock: Callable[[], float], on_change: Callable[[StateMode, StateMode, str], None])`
    - `mode: StateMode`
    - `async probe() -> None`
    - `force_tempfail(reason: str) -> None`
- Transitions (§6.2), which the tests pin:
  - **NORMAL:** operations use `primary`. A failing operation is answered by `fallback`, the consecutive-failure counter goes up, and the time of the first failure is remembered. The mode switches to DEGRADED (TEMPFAIL when `strict`) at the 3rd consecutive failure or once 2 s have passed since the first failure. A success resets the counter.
  - **DEGRADED:** every operation uses `fallback`. An exception from `fallback` switches to TEMPFAIL and raises `StateError`.
  - **TEMPFAIL:** every operation raises `StateError`.
  - **`probe()`:** while not NORMAL, `primary.ping()` is called. On success, `fallback.clear()` runs and the mode returns to NORMAL.
  - Every change calls `on_change(old, new, reason)`.

- [ ] **Step 1: Write failing tests** with a `FlakyStore` fake:
  - `test_single_failure_stays_normal_uses_fallback`
  - `test_three_failures_degrade`
  - `test_two_seconds_degrade`
  - `test_strict_goes_tempfail`
  - `test_fallback_error_tempfail`
  - `test_probe_recovers_and_clears`
  - `test_on_change_called_with_reason`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(state): add degraded-mode controller`.

### Task 15: Check framework and engine

**Files:**
- Create: `asspng/checks/__init__.py`, `asspng/checks/base.py`, `asspng/checks/engine.py`, `asspng/proxy/connections.py`, `tests/unit/checks/test_engine.py`, `tests/unit/proxy/test_connections.py`

**Interfaces:**
- Consumes: `Reply`, `Policy`, `ConfigSnapshot`, `StateStore`, `IPAddress`, `Address`, `MessageBuffer`, `ListenerConfig`.
- Produces in `proxy/connections.py`: `class ConnectionTracker` with `acquire(net: str) -> int`, `release(net: str) -> None`, `count(net: str) -> int` and `total: int`. It is in-process and per instance. Its test `test_acquire_release_counts` is part of this task.
- Produces in `base.py`:
  - `class Phase(Enum)` with values `CONNECT=1`, `HELO=2`, `AUTH=3`, `MAIL=4`, `RCPT=5`, `HEADER=6`, `BODY=7`
  - `class Mode(Enum)` with values `OFF="off"`, `BLOCK="block"`, `MONITOR="monitor"`, `SCORE="score"`, `TEST="test"`
  - `@dataclass(frozen=True) CheckResult(hit: bool, msg_score: int = 0, ip_score: int = 0, reason: str = "", reply: Reply | None = None, temporary: bool = False)` and `NEUTRAL = CheckResult(False)`
  - `@dataclass(frozen=True) CheckSettings(mode: Mode, msg_score: int, ip_score: int, timeout_s: float)`
  - `@dataclass SessionInfo`:
    `session_id: str`, `client_ip: IPAddress`, `net_key: str`, `listener: ListenerConfig`, `tls_version: str | None`, `auth_user: str | None`, `helo: str | None`, `trusted: bool`, `exempt: bool`, `messages: int`, `protocol_errors: int`, `invalid_recipients: int`
  - `@dataclass TransactionInfo`:
    `number: int`, `mail_from: Address | None`, `recipients: list[Address]`, `current_rcpt: Address | None`, `policy: Policy | None`, `score: int`, `reasons: list[tuple[str, int]]`, `would_reject: list[str]`, `warn: bool`, `message: MessageBuffer | None`
  - `@dataclass CheckContext`:
    `session: SessionInfo`, `txn: TransactionInfo | None`, `config: ConfigSnapshot`, `default_policy: Policy`, `sender_policy: Policy | None`, `state: StateStore`, `clock: Callable[[], float]`, `connections: ConnectionTracker`, and method `setting(key: str) -> object`. `setting` resolves by the setting's level: SYSTEM → `config.get`, RECIPIENT → `txn.policy` (falling back to `default_policy`), SENDER → `sender_policy` (falling back to the default layer).
  - `class Check(Protocol)`: `name: str`, `phases: frozenset[Phase]`, `exempt: frozenset[str]` (a subset of `{"trusted", "authenticated"}`), `async run(ctx: CheckContext, phase: Phase) -> CheckResult`
- Produces in `engine.py`:
  - `class Outcome(Enum)` with values `CONTINUE`, `REJECT` and `TEMPFAIL`
  - `@dataclass(frozen=True) Decision(outcome: Outcome, reply: Reply | None = None)`
  - `class CheckEngine`: `__init__(checks: Sequence[Check], ip_score_sink: Callable[[CheckContext, int, str], Awaitable[None]], on_error: Callable[[str, BaseException], None])` and `async run_phase(phase: Phase, ctx: CheckContext) -> Decision`
- Rules (§5.2):
  - Settings come from `checks.<name>.{mode,msg_score,ip_score,timeout_ms}` via `ctx.setting`.
  - A check is skipped when its mode is `OFF` or an exemption matches (`trusted` → `session.trusted`, `authenticated` → `session.auth_user`).
  - A timeout or exception calls `on_error` and counts as `NEUTRAL`.
  - The **effective test mode** is `txn.policy["testmode"]` when a transaction policy exists, otherwise `default_policy["testmode"]`.
  - On a hit:
    - if `ip_score > 0` and the session is not trusted, exempt, authenticated or private, `await ip_score_sink(ctx, ip_score, reason)`;
    - BLOCK in test mode → append `would_reject`;
    - BLOCK otherwise → `REJECT`, or `TEMPFAIL` when `temporary`, with `result.reply`;
    - SCORE → add `msg_score` to `txn.score` and `reasons`;
    - MONITOR → log only;
    - TEST → append `would_reject`.
  - After the phase, with a transaction: `score ≥ scoring.limit` → REJECT with `R_SCORE`, or `would_reject` in test mode. `score ≥ scoring.warn` sets `txn.warn = True`.

- [ ] **Step 1: Write failing tests** with stub checks:
  - `test_block_rejects`
  - `test_temporary_block_tempfails`
  - `test_testmode_converts_block_to_would_reject`: the domain policy has `testmode = true`
  - `test_score_accumulates_and_limit_rejects`
  - `test_warn_marks`
  - `test_monitor_logs_only`
  - `test_off_skipped`
  - `test_exempt_authenticated_skipped`
  - `test_exception_is_neutral_and_reported`
  - `test_timeout_is_neutral`
  - `test_ip_score_not_sent_for_private_or_trusted`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(checks): add check framework and decision engine`.

### Task 16: Penalty box with escalation

**Files:**
- Create: `asspng/checks/penalty_box.py`, `tests/unit/checks/test_penalty_box.py`

**Interfaces:**
- Consumes: `StateStore`, `Check`, `CheckResult`, `Phase`, `R_TRY_LATER`, `ListenerKind`.
- Produces:
  - `@dataclass(frozen=True) PenaltyStatus(net: str, score: int, reason: str, hits: int, blocked_until: float | None, level: int, history: int)`
  - `class PenaltyBox`:
    - `__init__(store: StateStore, *, threshold: int, score_cap: int, score_ttl_s: int, ladder_s: Sequence[int], history_s: int, clock: Callable[[], float])`
    - `async add_score(net: str, points: int, reason: str) -> PenaltyStatus`
    - `async blocked_until(net: str) -> float | None`
    - `async status(net: str) -> PenaltyStatus`
    - `async remove(net: str, *, forget: bool = False) -> None`
    - `async block(net: str, duration_s: int, reason: str) -> None`: a manual block; it does not raise the history count
    - `async list() -> list[PenaltyStatus]`
  - `class PenaltyBoxCheck(Check)`: `name = "penalty_box"`, phases `{CONNECT}`. It hits only for `ListenerKind.SMTP` while blocked, with `reply = R_TRY_LATER` and `temporary = True`.
- Keys (§6.1): `pb:<net>` (hash: score, reason, hits, first, last), `pb:block:<net>` (hash: until, level, reason), `pb:hist:<net>`.
- Escalation (§5.5):
  - Each score update writes `min(cap, score + points)` and refreshes the TTL to `score_ttl`.
  - When the score reaches the threshold: `history = await store.incr("pb:hist:"+net, history_s)`, `level = min(history, len(ladder))`, block for `ladder[level-1]`, then delete `pb:<net>`.

- [ ] **Step 1: Write failing tests** with `MemoryStore` and `fake_clock`:
  - `test_first_block_24h`
  - `test_second_block_7d`
  - `test_third_and_later_30d`
  - `test_history_expires_after_90d_restarts_level1`
  - `test_score_capped`
  - `test_score_expires_24h_after_last_hit`
  - `test_remove_keeps_history_unless_forget`
  - `test_manual_block_no_history`
  - `test_check_only_on_smtp_listener`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(checks): add penalty box with escalating blocks`.

### Task 17: Limit checks

**Files:**
- Create: `asspng/checks/limits.py`, `tests/unit/checks/test_limits.py`

**Interfaces:**
- Consumes: `ConnectionTracker` (Task 15), `CheckContext`, `StateStore`.
- Produces:
  - `ConnLimitsCheck`: CONNECT.
    - `ctx.connections.count(net) > limits.net.concurrent` → hit with reply 421 "4.7.0 Too many connections", temporary.
    - `incr_window("rl:conn:"+net, 60) > limits.net.connections_per_minute` → hit with the same reply.
    - Exempt networks are skipped.
  - `SessionLimitsCheck`:
    - MAIL: `session.messages >= limits.session.messages` → 421 "4.7.0 Too many messages", temporary.
    - RCPT: `len(txn.recipients) >= limits.message.recipients` → `R_TOO_MANY_RCPT`, temporary.
  - `AuthLimitsCheck`: AUTH. It hits with `R_AUTH_TEMPFAIL` (temporary) when `rl:authfail:net:<net>` ≥ `limits.auth.failures_per_net` or `rl:authfail:user:<user>` ≥ `limits.auth.failures_per_user`.
    - `async record_failure(state: StateStore, net: str, username: str | None, window_s: int) -> None`: increments both counters.
  - `UserRateCheck`: MAIL and RCPT, only for authenticated sessions.
    - MAIL: `rl:umsg:m:<user>` (60 s) > `limits.user.messages_per_minute` or `rl:umsg:h:<user>` (3600 s) > `limits.user.messages_per_hour` → `R_RATE`, temporary.
    - RCPT: `rl:urcpt:h:<user>` (3600 s) > `limits.user.recipients_per_hour` → `R_RATE`, temporary.

- [ ] **Step 1: Write failing tests:**
  - `test_concurrent_limit`
  - `test_per_minute_limit_resets_next_window`
  - `test_exempt_network_skipped`
  - `test_messages_per_session`
  - `test_recipients_per_message_452`
  - `test_auth_net_limit`
  - `test_auth_user_limit_across_nets`
  - `test_user_rate_minute_and_hour`
  - `test_user_rate_ignores_unauthenticated`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(checks): add connection, session, AUTH and user rate limit checks`.

---

## Milestone 4 — Proxy

### Task 18: TLS certificate store

**Files:**
- Create: `asspng/tls/__init__.py`, `asspng/tls/store.py`, `tests/support/certs.py`, `tests/unit/tls/test_store.py`

**Interfaces:**
- Produces:
  - `INTERMEDIATE_CIPHERS = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"`
  - `make_server_context(cert: Path, key: Path) -> ssl.SSLContext`: `minimum_version = TLSv1_2`, `OP_NO_COMPRESSION`, `OP_NO_RENEGOTIATION`, `set_ciphers(INTERMEDIATE_CIPHERS)`
  - `class CertificateStore`:
    - `__init__(certs: Sequence[CertificateConfig])`: raises `ConfigError` on an unreadable or invalid pair
    - `front_context() -> ssl.SSLContext | None`: a stable context whose `sni_callback` swaps in the current context by hostname (exact, then `*.domain`, then the first entry)
    - `reload(certs) -> None`: builds the new contexts and swaps them atomically; on failure keeps the old ones and raises
    - `days_left() -> dict[str, int]`: computed with `cryptography`
  - `tests/support/certs.py`: `make_cert(tmp: Path, hostname: str, days: int = 30) -> tuple[Path, Path]` (self-signed)

- [ ] **Step 1: Write failing tests:**
  - `test_min_tls12`
  - `test_sni_selects_matching_cert`: a real handshake on localhost with `server_hostname`
  - `test_no_sni_uses_first`
  - `test_wildcard`
  - `test_reload_swaps_without_new_front_context`
  - `test_reload_failure_keeps_old`
  - `test_days_left`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(tls): add certificate store with SNI and reload`.

### Task 19: PTR resolver

**Files:**
- Create: `asspng/net/dns.py`, `tests/unit/net/test_dns.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) PtrResult(name: str | None, temporary: bool)`, with property `xclient_value -> str` returning the name, `"[UNAVAILABLE]"` or `"[TEMPUNAVAIL]"`
  - `class PtrResolver(Protocol)`: `async lookup(addr: IPAddress) -> PtrResult`
  - `class DnsPtrResolver(PtrResolver)`: `__init__(timeout_s: float, cache_ttl_s: int = 3600, clock=time.monotonic, resolver: dns.asyncresolver.Resolver | None = None)`. A name is returned only when it is forward-confirmed (A/AAAA contains the address). NXDOMAIN gives `PtrResult(None, False)`. A timeout or SERVFAIL gives `PtrResult(None, True)`. Results are cached.

- [ ] **Step 1: Write failing tests** with a fake `dns.asyncresolver.Resolver`:
  - `test_forward_confirmed`
  - `test_not_confirmed_is_unavailable`
  - `test_timeout_is_tempunavail`
  - `test_cache_hit`
  - `test_xclient_value`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement** with `dns.asyncresolver`.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(net): add forward-confirmed PTR resolver`.

### Task 20: Backend client and XCLIENT

**Files:**
- Create: `asspng/proxy/xclient.py`, `asspng/proxy/backend.py`, `tests/support/fake_mta.py`, `tests/unit/proxy/test_xclient.py`, `tests/integration/proxy/test_backend.py`

**Interfaces:**
- Consumes: `Reply`, `read_reply`, `Stuffer`, `IPAddress`.
- Produces:
  - `format_xclient(addr: IPAddress, port: int, name: str) -> bytes`: `XCLIENT ADDR=<ip> PORT=<port> NAME=<xtext>\r\n`, with IPv6 written as `ADDR=IPV6:<ip>`. In xtext, bytes outside 0x21–0x7E and the characters `+` and `=` become `+HH`.
  - `class BackendError(Exception)` and its subclasses `BackendTimeout`, `BackendClosed`, `XclientUnsupported`.
  - `class Backend(Protocol)`:
    - `async connect() -> Reply`
    - `async xclient(addr: IPAddress, port: int, name: str, helo_name: str) -> Reply`
    - `async command(line: bytes, timeout_s: float) -> Reply`
    - `async data(chunks: Iterable[bytes], timeout_354_s: float, timeout_final_s: float) -> Reply`: sends `DATA`. A non-354 reply is returned as is. Otherwise the chunks are streamed through `Stuffer` and the final reply is returned.
    - `async close() -> None`: best-effort `QUIT`.
  - `class SmtpBackend(Backend)`: `__init__(host: str, port: int, *, connect_timeout_s: float, banner_timeout_s: float)`.
  - `tests/support/fake_mta.py` contains `class FakeMta`, an asyncio server with these properties:
    - `start()` returns `(host, port)`;
    - EHLO advertises `SIZE 10240000`, `8BITMIME`, `AUTH PLAIN LOGIN`, `XCLIENT NAME ADDR PORT`;
    - it accepts `XCLIENT` from 127.0.0.1 and answers with a new `220`;
    - AUTH succeeds only for user `test` with password `secret`;
    - `RCPT` to `unknown@…` gets `550 5.1.1`;
    - `DATA` gets `250 2.0.0 Ok: queued as FAKE1`;
    - every received line is recorded in `.lines` and every message in `.messages`;
    - knobs: `xclient=False`, `banner_code`, `hang_after`.

- [ ] **Step 1: Write failing tests:**
  - `test_xclient_v4`
  - `test_xclient_v6_prefix`
  - `test_xtext_escapes_plus_and_space`
  - `test_connect_banner`
  - `test_xclient_unsupported_raises`
  - `test_xclient_new_greeting`
  - `test_data_stuffs_and_returns_final`
  - `test_non_354_returned`
  - `test_timeout_raises_backend_timeout`
  - `test_close_sends_quit`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add backend client with XCLIENT`.

### Task 21: AUTH passthrough helpers

**Files:**
- Create: `asspng/proxy/auth.py`, `tests/unit/proxy/test_auth.py`

**Interfaces:**
- Produces:
  - `class AuthSyntaxError(ValueError)`
  - `class AuthExchange`:
    - `__init__(mechanism: str, initial: str | None)`: raises `AuthSyntaxError` for a mechanism other than PLAIN or LOGIN
    - `on_client_line(line: str) -> None`
    - `username: str | None`
    - `cancelled: bool`

    For PLAIN, the username is the `authcid` (second NUL-separated field). For LOGIN, it is the first client response (or the initial response). Bad base64 raises `AuthSyntaxError`. `*` sets `cancelled`. Passwords are never stored on the object.
  - `redact_auth(line: bytes, in_exchange: bool) -> bytes`: `AUTH PLAIN xxx` → `AUTH PLAIN <redacted>`; any line while `in_exchange` → `<redacted>`.

- [ ] **Step 1: Write failing tests:**
  - `test_plain_initial`
  - `test_plain_continuation`
  - `test_login_two_steps`
  - `test_cancel`
  - `test_bad_base64`
  - `test_password_not_in_repr_or_vars`: `"secret" not in repr(ex) and "secret" not in str(vars(ex))`
  - `test_redact`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(proxy): extract AUTH usernames and redact credentials`.

### Task 22: Logging, maillog and redaction

**Files:**
- Create: `asspng/log/__init__.py`, `asspng/log/redact.py`, `asspng/log/maillog.py`, `asspng/log/setup.py`, `tests/unit/log/test_maillog.py`, `tests/unit/log/test_setup.py`

**Interfaces:**
- Produces:
  - `class RedactionFilter(logging.Filter)`: masks `AUTH (PLAIN|LOGIN) \S+` and base64 continuation lines marked with `extra={"auth": True}`.
  - `@dataclass MaillogRecord`:
    `ts: datetime`, `instance: str`, `session: str`, `txn: int | None`, `listener: str`, `ip: str`, `ptr: str`, `helo: str`, `tls: str`, `auth: str`, `mail_from: str`, `rcpts: list[str]`, `size: int | None`, `score: int | None`, `result: str`, `mta: str`, `duration_s: float`
  - `format_maillog(rec: MaillogRecord) -> str`. Format (§8.5):
    `2026-11-12T17:30:01+01:00 mx1 s=7f3a9c2e t=1 l=inbound ip=203.0.113.5 ptr=mail.example.org helo=mail.example.org tls=TLSv1.3 auth=- from=<a@example.org> rcpt=<b@example.com> size=48211 score=0 result=accepted mta="250 2.0.0 Ok: queued as 4XyZ" dur=1.84s`
    - empty values are written as `-`;
    - several recipients are comma-joined;
    - values containing spaces or quotes are quoted, with `"` escaped as `\"`;
    - `t=-` for a session without a message;
    - `result` values: `accepted`, `rejected`, `tempfailed`, `accepted-test`, `closed`, `rejected-connect`, `timeout`, `error`.
  - `configure_logging(level: str, log_dir: Path, *, journal: bool) -> logging.handlers.QueueListener`:
    - logger `asspng` → `assp-ng.log`;
    - logger `asspng.maillog` → `maillog.log` (raw lines, no propagation);
    - WARNING and above also go to journald via `systemd.journal.JournalHandler` when `journal` is true;
    - every handler carries `RedactionFilter`;
    - a `QueueHandler` feeds a `QueueListener` thread;
    - file handlers are `WatchedFileHandler`.

- [ ] **Step 1: Write failing tests:**
  - `test_exact_example_line`: equals the §8.5 example
  - `test_quoting`
  - `test_session_without_message`
  - `test_redaction_masks_auth`
  - `test_queue_listener_writes_files`
  - `test_rotation_followed`: rename the file, log again, and a new file appears
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(log): add maillog format, redaction and non-blocking logging`.

### Task 23: Debug rules, session tap and debug log

**Files:**
- Create: `asspng/log/debug.py`, `tests/unit/log/test_debug.py`

**Interfaces:**
- Produces:
  - `class RuleKind(Enum)` with values `IP`, `FROM`, `RCPT`, `USER`, `LISTENER`, `ALL`.
  - `@dataclass(frozen=True) DebugRule(id: str, kind: RuleKind, value: str, expires_at: float, headers: bool)`
  - `class DebugRules`:
    - `__init__(path: Path, clock, *, default_s: int, max_s: int, max_all_s: int)`
    - `add(kind: RuleKind, value: str, duration_s: int | None, headers: bool) -> DebugRule`: raises `ValueError` above the maximum
    - `remove(rule_id: str) -> bool`, `clear() -> int`, `active() -> list[DebugRule]` (prunes expired rules and persists to `path`)
    - `match_connect(net_key: str, listener: str) -> DebugRule | None`
    - `match_envelope(mail_from: str | None, rcpts: Sequence[str], auth_user: str | None) -> DebugRule | None`
  - `class DebugLog`: `__init__(path: Path, max_bytes: int, on_full: Callable[[], None])` and `write(session_id: str, direction: str, text: str) -> None`. Directions are `"C>P"`, `"P>C"`, `"P>M"`, `"M>P"`, `"CHK"`, `"DNS"`, `"STATE"`. When the size cap is reached, writing stops and `on_full` is called once.
  - `class SessionTap`:
    - `__init__(session_id: str, rules: DebugRules, log: DebugLog, ring_lines: int)`
    - `line(direction: str, text: str) -> None`: the caller passes already redacted text
    - `on_connect(net_key: str, listener: str) -> None`
    - `on_envelope(mail_from, rcpts, auth_user) -> None`: on a new match, flushes the ring buffer first
    - `active: bool`, `headers: bool`

- [ ] **Step 1: Write failing tests:**
  - `test_default_30m_expiry`
  - `test_max_24h_and_all_1h`
  - `test_persist_and_reload`
  - `test_ip_rule_matches_network`
  - `test_envelope_rule_flushes_ring`: the tap's earlier connect and EHLO lines appear before the match
  - `test_ring_limited_to_n`
  - `test_size_cap_calls_on_full_once`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(log): add targeted self-expiring debug rules`.

### Task 24: Session part 1 — connection setup and basic commands

**Files:**
- Create: `asspng/proxy/session.py`, `tests/support/smtp_client.py`, `tests/session/conftest.py`, `tests/session/test_session_basic.py`

**Interfaces:**
- Consumes: everything from Tasks 2–23.
- Produces:
  - `@dataclass SessionDeps`:
    `config: ConfigSnapshot`, `policies: PolicyResolver`, `listener: ListenerConfig`, `backend_factory: Callable[[ListenerConfig], Backend]`, `engine: CheckEngine`, `state: StateController`, `penalty_box: PenaltyBox`, `auth_limits: AuthLimitsCheck`, `domains: Callable[[], DomainIndex]`, `tls: CertificateStore`, `resolver: PtrResolver`, `connections: ConnectionTracker`, `budget: BufferBudget`, `maillog: Callable[[MaillogRecord], None]`, `debug_rules: DebugRules`, `debug_log: DebugLog`, `health: HealthCounters`, `memory_over_limit: Callable[[], bool]`, `clock: Callable[[], float]`
  - `HealthCounters` is a Protocol defined in `session.py` with `record(event: str) -> None` and `backend_result(listener: str, ok: bool) -> int` (returns the consecutive failures). Task 29 implements it.
  - `class Session`: `__init__(deps: SessionDeps, reader: StreamReader, writer: StreamWriter, peer: tuple[str, int])` and `async run() -> None`. `run` never raises. Session ids are `secrets.token_hex(4)`.
  - Test fixture `proxy_with(fake_backend, **overrides)` starts an asyncio server on `127.0.0.1:0` that runs `Session` with in-process fakes. `FakeBackend` (in `tests/session/conftest.py`) implements `Backend` with scripted replies and records `received` lines. The client helper `smtp_dialog(host, port)` in `tests/support/smtp_client.py` offers `send(line) -> Reply`, `expect_banner()` and `starttls(ctx)`.
- Behaviour (§4.2, §4.3, §4.10) in this order:
  1. TEMPFAIL mode or `memory_over_limit()` → `R_TEMPFAIL`, close.
  2. `connections.total ≥ limits.instance.concurrent` → `R_BACKEND_DOWN`, close. This step is never in test mode.
  3. Acquire the connection slot (released in `finally`).
  4. CONNECT phase (rejection → reply and close; the backend is never contacted).
  5. `asyncio.gather(resolver.lookup, backend.connect())`; a backend failure → `R_BACKEND_DOWN` + `health.backend_result(name, False)`.
  6. XCLIENT if enabled; `XclientUnsupported` → `R_BACKEND_DOWN` + error log.
  7. Banner `220 <hostname> ESMTP[ <banner.text>]`.
  8. Command loop with `read_line(limit=2048, timeout=timeouts.command)`:

     | Command | Handling |
     |---|---|
     | EHLO/HELO | HELO phase, then forward and `filter_ehlo`; HELO gets a plain `250 <hostname>` |
     | NOOP, RSET | forward (RSET also clears the transaction) |
     | QUIT | forward, `R_BYE`, close |
     | VRFY/EXPN | `R_VRFY` |
     | HELP | `R_HELP` |
     | XCLIENT, XFORWARD, ETRN, TURN, ATRN, BDAT and unknown verbs | `R_NOT_IMPL`, never forwarded |
     | syntax error | `R_SYNTAX` |
     | over-long line | `R_LINE_TOO_LONG` |

     Each error increments `protocol_errors`. At `limits.session.protocol_errors` the client gets `R_TOO_MANY_ERRORS`, the network gets `abuse.protocol_error_ip_score`, and the session closes.
  9. Idle timeout → `R_IDLE`, maillog `result=timeout`.
  10. An unhandled exception → `R_INTERNAL`, log, `health.record("session_error")`.
  11. A lost backend → `R_BACKEND_LOST`.
  12. Every client/proxy/backend line goes through `SessionTap` (redacted). One maillog record is written at the end when no transaction record was written.

- [ ] **Step 1: Write failing golden-transcript tests:**
  - `test_banner_own_hostname`
  - `test_ehlo_filtered`
  - `test_vrfy_252_not_forwarded`
  - `test_client_xclient_never_forwarded`: `"XCLIENT" not in fake.received_text`
  - `test_unknown_command_502`
  - `test_too_many_errors_421_and_ip_score`
  - `test_connect_reject_never_contacts_backend`
  - `test_tempfail_mode_421_430`
  - `test_backend_down_421_432`
  - `test_xclient_sent_before_banner`
  - `test_xclient_unsupported_fails_closed`
  - `test_idle_timeout`
  - `test_quit`
  - `test_session_exception_421_others_unaffected`
- [ ] **Step 2: Run them.** `python3 -m pytest tests/session -v` → FAIL.
- [ ] **Step 3: Implement** the Session skeleton and these commands.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add session setup and basic command handling`.

### Task 25: Session part 2 — STARTTLS, AUTH, MAIL and RCPT

**Files:**
- Modify: `asspng/proxy/session.py`
- Create: `tests/session/test_session_envelope.py`

**Interfaces:**
- Consumes: Task 24 plus `AuthExchange`, `PolicyResolver`, `DomainIndex`, `AuthLimitsCheck.record_failure`.
- Behaviour (§4.3–§4.6, §4.11):
  - **STARTTLS:**
    - no certificate → `R_TLS_UNAVAILABLE`;
    - TLS already active → `R_TLS_ACTIVE`;
    - otherwise `R_TLS_READY`, then `writer.start_tls(store.front_context(), ssl_handshake_timeout=timeouts.tls_handshake)`, and HELO and the transaction are reset.
  - **AUTH:**
    - listener without `auth` → `R_NOT_IMPL`;
    - no TLS → `R_ENCRYPTION_REQUIRED`;
    - otherwise the AUTH phase runs (`AuthLimitsCheck`), and the exchange is relayed to the backend line by line while tracked by `AuthExchange`;
    - `235` → `session.auth_user` is set and the sender policy is loaded;
    - `5xx` → `record_failure`. A second AUTH in the same session after an `R_AUTH_TEMPFAIL` gets `R_TOO_MANY_ERRORS` and the auth IP score;
    - bad base64 → `R_BAD_ARG`.
  - **MAIL:**
    - submission kinds without auth → `R_AUTH_REQUIRED`;
    - parse error → `R_SYNTAX`;
    - `SIZE` above `max_message_size` → `R_SIZE`;
    - then the MAIL phase, forwarding, and a new `TransactionInfo` on `2xx`.
  - **RCPT**, in this order:
    1. parse;
    2. relay decision:
       - local domain → ok;
       - otherwise authenticated or trusted → ok;
       - otherwise, if the domain index is unavailable → `R_DOMAINS_UNAVAILABLE`;
       - otherwise `R_RELAY_DENIED` + protocol error + `abuse.relay_denied_ip_score`;
    3. policy grouping: the first accepted recipient sets `txn.policy`; a different fingerprint → `R_POLICY_SPLIT` and the recipient is not forwarded;
    4. RCPT phase;
    5. forward;
    6. MTA `550`/`551`/`553` → `invalid_recipients += 1`, which at the limit closes with `R_TOO_MANY_ERRORS` + `abuse.invalid_recipient_ip_score`;
    7. `2xx` → append to `txn.recipients`.
  - `SessionTap.on_envelope` runs after MAIL and after each accepted RCPT.

- [ ] **Step 1: Write failing tests:**
  - `test_starttls_then_ehlo_again`
  - `test_auth_before_tls_538`
  - `test_auth_plain_success_sets_user_and_allows_relay`
  - `test_auth_failure_counts`
  - `test_submission_mail_without_auth_530`
  - `test_relay_denied_554_and_not_forwarded`
  - `test_local_domain_accepted_case_insensitive` (Review Focus 3)
  - `test_trusted_network_may_relay`
  - `test_domains_unavailable_451`
  - `test_policy_split_452_not_forwarded`: `domain.d/b.example.toml` sets `testmode = true`; the rcpt to `a.example` is accepted, the one to `b.example` gets 452
  - `test_same_policy_stays_together`
  - `test_invalid_recipients_limit`
  - `test_size_param_552`
  - `test_password_never_in_debug_log`: a debug `all` rule is active, and `"secret"` and `base64("…secret")` are absent from `debug.log`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add STARTTLS, AUTH passthrough, relay decision and policy grouping`.

### Task 26: Session part 3 — DATA

**Files:**
- Modify: `asspng/proxy/session.py`
- Create: `tests/session/test_session_data.py`

**Interfaces:**
- Consumes: `MessageBuffer`, `DataReceiver`, `split_header`, `strip_fields`, `format_field`, `Backend.data`, `format_maillog`.
- Behaviour (§4.7, §4.8):
  1. No recipients → `R_NO_RCPT`.
  2. Reply `R_DATA_GO` locally and receive into a `MessageBuffer` through `DataReceiver`, applying the data block and total timeouts. Non-empty `leftover` (pipelining) → protocol error.
  3. `oversize` → `R_SIZE` + `RSET` to the backend.
  4. HEADER, then BODY phase.
  5. **REJECT/TEMPFAIL** → the decision's reply, `RSET` to the backend, maillog `rejected`/`tempfailed`, `health.record`.
  6. **Accept:**
     - build new fields:
       - `X-ASSP-NG-ID: <instance>-<session>-<txn>`;
       - `X-ASSP-NG-Score: <score> (<name>=<pts>; …)` when `scoring.add_header` and the score is not 0;
       - `X-ASSP-NG-Warning: score <s> above warning level <w>` when `warn`;
       - `X-ASSP-NG-Test: would reject: <reasons>` when `would_reject` is non-empty;
     - prefix the `Subject` with `scoring.warn_subject_tag` when it is set and `warn`;
     - remove incoming `X-ASSP-NG-*` fields;
     - `backend.data(new_fields + stripped_header + body, …)` and relay the backend's final reply verbatim;
     - maillog `accepted` (`accepted-test` if `would_reject`), `messages += 1`.
  7. Always `buffer.close()` in `finally`.
  8. Client disconnect at any point → the buffer is closed, the backend is closed, and the maillog result is `closed`.

- [ ] **Step 1: Write failing tests:**
  - `test_message_delivered_with_id_header`
  - `test_incoming_assp_headers_stripped`
  - `test_reject_sends_rset_and_554`
  - `test_testmode_adds_test_header_and_delivers`
  - `test_score_header_and_warning`
  - `test_oversize_552_after_full_read`
  - `test_backend_final_reply_relayed`: the fake answers `452`, and the client sees `452`
  - `test_backend_non_354_relayed`
  - `test_large_message_spooled_and_cleaned`
  - `test_client_disconnect_mid_data_cleans_up` (Review Focus 2): spool dir empty, `budget.used == 0`, `connections.total == 0`, the backend received `QUIT` or was closed, and no ERROR log
  - `test_maillog_record_fields`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add buffered DATA handling with header management`.

---

## Milestone 5 — Service

### Task 27: Database schema, migrations and repository

**Files:**
- Create: `asspng/db/__init__.py`, `asspng/db/schema.py`, `asspng/db/migrate.py`, `asspng/db/migrations/env.py`, `asspng/db/migrations/script.py.mako`, `asspng/db/migrations/versions/0001_initial.py`, `asspng/db/repository.py`, `tests/integration/db/test_repository.py`

**Interfaces:**
- Consumes: `DomainEntry`, `normalize_domain`.
- Produces:
  - Tables (§5.9): `local_domain` and `audit_log`, charset `utf8mb4`.
  - `HEAD_REVISION = "0001"`
  - `upgrade(url: str) -> None`: programmatic Alembic config, no ini file
  - `current_revision(url: str) -> str | None`
  - `class DomainRepository`:
    - `__init__(url: str, instance: str)`
    - `add(domain: str, *, include_subdomains: bool, note: str | None, actor: str) -> None`
    - `remove(domain: str, *, actor: str) -> bool`
    - `list() -> list[DomainEntry]`
    - every change also writes `audit_log`
  - `class DatabaseDomainSource`: `__init__(url: str)` and `load() -> list[DomainEntry]` (synchronous, called through `asyncio.to_thread`)
  - `write_audit(url: str, *, instance: str, actor: str, action: str, target: str, details: dict[str, object]) -> None`

- [ ] **Step 1: Write failing tests**, marked `@pytest.mark.skipif(not os.environ.get("ASSPNG_TEST_DB_URL"), reason="set ASSPNG_TEST_DB_URL")`:
  - `test_upgrade_creates_tables_and_revision`
  - `test_add_normalizes_idn`
  - `test_remove_and_audit`
  - `test_source_loads_enabled`
  - `test_duplicate_add_raises`
- [ ] **Step 2: Run them** with a local test DB, `ASSPNG_TEST_DB_URL=mysql+pymysql://asspng_test:…@localhost/asspng_test python3 -m pytest tests/integration/db -v` → FAIL. Document the user and DB creation SQL in `docs/development.md`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(db): add schema, migrations and domain repository`.

### Task 28: Domain refresher

**Files:**
- Create: `asspng/domains/refresher.py`, `tests/unit/domains/test_refresher.py`

**Interfaces:**
- Consumes: `DomainIndex`, `save_snapshot`, `load_snapshot`, `DatabaseDomainSource`-like `load()`, `EventBus`.
- Produces:
  - `class DomainHolder`: `index: DomainIndex`, `origin: str` (`"db"`, `"snapshot"` or `"none"`), `__call__() -> DomainIndex`
  - `class DomainRefresher`:
    - `__init__(source_load: Callable[[], list[DomainEntry]], holder: DomainHolder, snapshot: Path, interval_s: int, on_db_down: Callable[[float], None])`
    - `async refresh() -> None`: a successful load sets `origin = "db"` and saves the snapshot. A failure keeps the current index. If nothing has been loaded yet, the snapshot is used (`origin = "snapshot"`), otherwise `DomainIndex.unavailable()` (`origin = "none"`). The `on_db_down(seconds_down)` callback lets the app raise the "database unreachable > 5 min" alert.
    - `async run() -> None`: periodic
    - `async on_event(msg: str) -> None`: refreshes on `"domains-changed"`

- [ ] **Step 1: Write failing tests:**
  - `test_db_success_writes_snapshot`
  - `test_db_down_at_start_uses_snapshot`
  - `test_db_down_no_snapshot_unavailable`
  - `test_failure_keeps_last_good`
  - `test_event_triggers_refresh`
  - `test_db_down_duration_reported`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(domains): refresh local domains from DB with snapshot fallback`.

### Task 29: Health, systemd notify, alerts and memory

**Files:**
- Create: `asspng/service/__init__.py`, `asspng/service/systemd.py`, `asspng/service/health.py`, `asspng/service/alerts.py`, `asspng/service/memory.py`, `tests/unit/service/test_health.py`, `tests/unit/service/test_alerts.py`, `tests/unit/service/test_memory.py`

**Interfaces:**
- Produces:
  - `notify(message: str) -> None`: wraps `systemd.daemon.notify` and is a no-op when the module is unavailable or `NOTIFY_SOCKET` is unset.
  - `class HealthState` (implements `HealthCounters` from Task 24):
    - `record(event: str) -> None`
    - `backend_result(listener: str, ok: bool) -> int`: returns the consecutive failures
    - `snapshot(*, instance, mode, db_ok, domains_origin, domains_count, sessions, rss_mb, uptime_s, debug_rules, cert_days) -> dict[str, object]`: the §8.4 JSON shape
    - `status_code(snapshot) -> int`: 200 for ok or degraded, 503 for failing. `failing` means TEMPFAIL or every backend down. `degraded` means DEGRADED, the DB down, the domain origin is not `db`, or any backend down.
  - `class HealthServer`: `__init__(host: str, port: int, provider: Callable[[], dict[str, object]])`, `async start()`, `async close()`. It answers HTTP/1.0 `GET /health` with JSON and everything else with 404.
  - `class Alerter`:
    - `__init__(*, email: str, webhook: str, smtp_server: str, min_interval_s: int, clock, send_email=…, post_webhook=…)`
    - `async notify(event: str, message: str) -> bool`: the same event is sent at most once per `min_interval_s`. Delivery runs through `asyncio.to_thread`. Email goes via `smtplib.SMTP(host, port)` with subject `[ASSP-NG <instance>] <event>`. The webhook is an `urllib.request` JSON POST with a 10 s timeout. A delivery failure is logged and never raised.
  - Memory:
    - `rss_mb() -> float`: reads `/proc/self/statm`
    - `malloc_trim() -> bool`: `ctypes.CDLL("libc.so.6").malloc_trim(0)`, `False` when unavailable
    - `class MemoryGuard`: `__init__(soft_limit_mb: float, rss=rss_mb)`, `over_limit() -> bool`
    - `class Housekeeper`: `__init__(sessions: Callable[[], int], expire_caches: Sequence[Callable[[], None]], clock, idle_after_s: int, interval_s: int, low_load: int = 10)` and `tick() -> bool`. It runs after `idle_after_s` without sessions, or every `interval_s` while sessions are fewer than `low_load`. It calls the caches, then `gc.collect()`, then `malloc_trim()`, and logs RSS before and after at DEBUG.

- [ ] **Step 1: Write failing tests:**
  - `test_health_json_shape`: all §8.4 keys including `debug_rules`
  - `test_status_codes`
  - `test_http_get_health_and_404`
  - `test_alert_rate_limited`
  - `test_alert_failure_not_raised`
  - `test_email_uses_smtp_server`: against `FakeMta`
  - `test_guard`
  - `test_housekeeper_idle_and_interval` (fake clock)
  - `test_malloc_trim_returns_bool`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(service): add health endpoint, alerts, systemd notify and memory housekeeping`.

### Task 30: Control socket

**Files:**
- Create: `asspng/service/control.py`, `tests/unit/service/test_control.py`

**Interfaces:**
- Produces:
  - `class ControlServer`:
    - `__init__(path: Path, handlers: Mapping[str, Callable[[dict[str, object]], Awaitable[object]]], group: str | None = "assp-ng")`
    - `async start()`: removes a stale socket, chmods 0660 and chowns to the group when it exists
    - `async close()`
    - protocol: one JSON object per line, `{"cmd": str, "args": {...}}` → `{"ok": true, "result": …}` or `{"ok": false, "error": str}`; unknown commands give an error; requests above 64 KiB are rejected
  - `async control_request(path: Path, cmd: str, args: dict[str, object], timeout_s: float = 5.0) -> object`: raises `RuntimeError(error)` on `ok = false`.
- Commands registered by the app (Task 31): `debug.on {kind, value, duration_s, headers}`, `debug.off {id | all}`, `debug.list {}`, `status {}`.

- [ ] **Step 1: Write failing tests:**
  - `test_roundtrip`
  - `test_unknown_command_error`
  - `test_socket_mode_0660`
  - `test_stale_socket_replaced`
  - `test_oversized_request_rejected`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(service): add local control socket`.

### Task 31: Listeners, application wiring and end-to-end tests

**Files:**
- Create: `asspng/proxy/listener.py`, `asspng/service/app.py`, `asspng/proxy/__main__.py`, `tests/integration/test_end_to_end.py`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `class ListenerManager`:
    - `__init__(listeners: Sequence[ListenerConfig], handler: Callable[[ListenerConfig, StreamReader, StreamWriter], Awaitable[None]], tls: CertificateStore, handshake_timeout_s: float)`
    - `async start()`: one server per enabled family. The IPv6 socket is created manually with `IPV6_V6ONLY = 1`. `submissions` servers use `ssl=tls.front_context()`. The `StreamReader` limit is 64 KiB.
    - `async close()`
    - `addresses() -> list[tuple[str, str, int]]`: `(listener, host, port)`
  - `class Application`:
    - `__init__(config_path: Path, *, backend_factory=None, resolver=None, clock=time.time)`
    - `async start()`, which runs in this order:
      1. `load_config(config_path.parent)`; on error print all errors and exit 2;
      2. configure logging;
      3. `purge_spool`;
      4. build `RedisStore`, `MemoryStore`, `StateController`, the penalty box, the checks and the engine;
      5. load the domain snapshot or DB, start the refresher and the event bus;
      6. check the schema revision (mismatch → alert + snapshot);
      7. TLS store, listeners, health server, control server, housekeeper, state probe loop, certificate-expiry loop (daily, alert below 14 days);
      8. `notify("READY=1")`; then the watchdog loop sends `notify("WATCHDOG=1")` every 10 s and a `STATUS=…` summary.
    - `async reload() -> bool` (§7.5): loads and validates everything first. On failure it keeps the current config, logs, alerts and returns `False`. On success it swaps the snapshot and policies (sessions in progress keep their `SessionDeps` snapshot), reloads TLS, and logs the changed keys with file and level. Listener changes log "restart required".
    - `async shutdown()`: close the listeners, wait up to `timeouts.shutdown` for sessions, send `R_TEMPFAIL` to the rest, close the stores.
    - signal handlers: SIGHUP → `reload`, SIGTERM/SIGINT → `shutdown`.
    - mode changes → `Alerter.notify`, so do backend failures reaching 3 in a row and the memory soft limit (`StateController.force_tempfail` while DEGRADED).
  - `main(argv: list[str] | None = None) -> int`: `python3 -m asspng.proxy --config /etc/assp-ng/assp-ng.toml`.

- [ ] **Step 1: Write failing tests** (real process objects on random ports, `FakeMta` backend, `redis_server` fixture, generated certificates):
  - `test_inbound_delivery_ipv4`
  - `test_inbound_delivery_ipv6_loopback`
  - `test_mapped_ipv4_keyed_as_ipv4` (Review Focus 4): a dual-stack test socket reports `::ffff:127.0.0.1` and the penalty key is `127.0.0.1/32`
  - `test_submission_starttls_auth_relay`
  - `test_submissions_implicit_tls`
  - `test_redis_stopped_degraded_then_recovers`: stop the Redis fixture, mail still flows, health shows `degraded`, start it again, `probe()` → NORMAL
  - `test_backend_down_421`
  - `test_invalid_reload_keeps_config` (Review Focus 5): change `scoring.limit` to an invalid value and reload → `False`, old value active
  - `test_reload_during_transaction_keeps_policy` (Review Focus 5): open a transaction, change `testmode` in `domain.d`, reload, finish DATA → the old policy applied; a new session uses the new one
  - `test_missing_default_toml_refuses_start`
  - `test_spool_overflow_to_disk`
  - `test_domain_snapshot_fallback`
  - `test_debug_via_control_socket_during_redis_outage`
- [ ] **Step 2: Run them.** `python3 -m pytest tests/integration -v` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS. Also run the full suite with coverage: `python3 -m pytest --cov --cov-report=term-missing` and check that the core packages are at or above 85 %.
- [ ] **Step 5: Commit** `feat(service): wire application, listeners and lifecycle`.

---

## Milestone 6 — CLI and packaging

### Task 32: Configuration CLI (init, check, show, set, unset, doc)

**Files:**
- Create: `asspng/config/editor.py`, `asspng/config/docgen.py`, `asspng/cli/__init__.py`, `asspng/cli/__main__.py`, `asspng/cli/main.py`, `asspng/cli/config_cmd.py`, `tests/unit/cli/test_config_cmd.py`, `tests/unit/config/test_editor.py`

**Interfaces:**
- Produces:
  - `set_value(path: Path, key: str, value: object) -> None` and `unset_value(path: Path, key: str) -> bool`. They use `tomlkit` (comments preserved), write atomically through a temporary file and rename, keep `<file>.bak`, and create a missing `domain.d`/`user.d` file.
  - `render_default_toml(registry: Registry) -> str`: every RECIPIENT and SENDER setting commented out, with its description and default.
  - `render_reference(registry: Registry) -> str`: Markdown table of key, type, default, level and description.
  - `main(argv: list[str] | None = None) -> int`: argparse entry point for `assp-ng`, used by `python3 -m asspng.cli`.
  - `config` subcommands (§7.6):
    - `init [--force]`
    - `check`: load, DB connect, Redis ping, each backend `connect` + EHLO (+ XCLIENT capability when enabled), certificate validity
    - `show [<key>] [sys|default|domain:<d>|user:<a>]`: prints `key = value  (source)`
    - `set <key> <value> [scope]` and `unset <key> [scope]`: validate the level and the value, copy `/etc/assp-ng` to a temporary directory, apply the change there, run `load_config` on it, and only then write the real file. Afterwards `systemctl reload assp-ng-proxy` runs when the service is active. Both need root and are audit-logged when the DB is configured.
    - `doc [--output PATH]`
  - The scope syntax is `sys`, `default` (the default when omitted), `domain:<domain>` or `user:<address>`.

- [ ] **Step 1: Write failing tests:**
  - `test_set_preserves_comments`
  - `test_set_creates_user_file_normalized`
  - `test_set_rejects_wrong_level`: `redis.url` with `user:` exits non-zero and leaves the file unchanged
  - `test_set_rejects_invalid_value_file_unchanged`
  - `test_unset`
  - `test_show_reports_source`
  - `test_init_refuses_overwrite`
  - `test_init_output_loads`: `render_default_toml` → `load_config` succeeds
  - `test_doc_contains_every_key`
  - `test_bak_written`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.** Then generate `docs/configuration.md` with `python3 -m asspng.cli config doc --output docs/configuration.md`.
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(cli): add layered configuration commands and reference docs`.

### Task 33: Operations CLI (db, domain, pb, debug, status, notify)

**Files:**
- Create: `asspng/cli/ops_cmd.py`, `tests/unit/cli/test_ops_cmd.py`

**Interfaces:**
- Consumes: `upgrade`, `DomainRepository`, `RedisStore`, `PenaltyBox`, `control_request`, `Alerter`, `network_key`, `parse_ip`, `parse_duration`.
- Produces these subcommands:
  - `db upgrade`
  - `domain add <domain> [--subdomains] [--note N] | remove <domain> | list`: publishes `domains-changed` on `<prefix>events`
  - `pb list | show <ip> | remove <ip> [--forget] | block <ip> --for <duration> [--reason R]`: the IP is converted with the configured prefixes, and every change is audit-logged
  - `debug on <kind>:<value> | all [--for D] [--headers] | off <id> | off --all | list`
  - `status`: the control socket `status` command, printed as a table
  - `notify --event E --message M`: no rate limit, used by the OnFailure unit

  Exit codes: 0 for success, 1 for operation errors, 2 for usage or config errors.

- [ ] **Step 1: Write failing tests** (CLI run in-process with patched dependencies):
  - `test_domain_add_publishes_event`
  - `test_pb_show_uses_network_key`: `2001:db8::1` → `2001:db8::/64`
  - `test_pb_block_duration`
  - `test_debug_on_parses_rule`
  - `test_debug_on_over_max_errors`
  - `test_status_table`
  - `test_notify_calls_alerter`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(cli): add domain, penalty box, debug, status and notify commands`.

### Task 34: Postfix integration assistant

**Files:**
- Create: `asspng/postfix/__init__.py`, `asspng/postfix/inspect.py`, `asspng/postfix/plan.py`, `asspng/postfix/apply.py`, `asspng/cli/postfix_cmd.py`, `tests/unit/postfix/fixtures/` (sample `master.cf` and `postconf -n` output: plain Debian, postscreen + postgrey + rspamd, amavis, ISPConfig-like), `tests/unit/postfix/test_postfix.py`

**Interfaces:**
- Produces:
  - `@dataclass MasterService(name: str, type: str, line_start: int, line_end: int, command: str, options: dict[str, str])`
  - `@dataclass PostfixState(main: dict[str, str], master_text: str, services: list[MasterService], ispconfig: bool, rspamd_dkim: bool, amavis_dkim: bool, ports_in_use: set[int])`
  - `read_state(run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run, etc: Path = Path("/etc/postfix")) -> PostfixState`
  - `@dataclass Finding(kind: str, description: str, replaced_by: str, can_disable: bool)`
  - `detect(state: PostfixState, features: frozenset[str]) -> list[Finding]`. The kinds are listed in the §8.10 table. In this release `FEATURES = frozenset({"listeners"})`, so only the public listeners are `can_disable`; every other filter is reported as "keep for now".
  - `@dataclass Plan(master_text_new: str, notes: list[str])`
  - `build_plan(state, findings, backends: Sequence[tuple[str, int, bool]]) -> Plan`:
    - comments out the public `smtp`/`postscreen` (25), `submission` and `smtps` services, prefixing every line with `#` and inserting `# disabled by assp-ng <YYYY-MM-DD>` above them;
    - appends the two internal services with `# added by assp-ng <date>` and their `-o` options (§8.10);
    - refuses (`ValueError`) when a backend port is already in use by something else.
  - `render_diff(old: str, new: str) -> str` (unified diff).
  - `apply_plan(plan, state, *, backup_root: Path, run=subprocess.run, verify: Callable[[], bool]) -> Path`:
    1. on an ISPConfig host, raise `RuntimeError` with an explanation (plan decision);
    2. back up `/etc/postfix` to `backup_root/postfix-<timestamp>/`;
    3. write `master.cf`;
    4. `postfix check`;
    5. `systemctl restart postfix`;
    6. `systemctl start assp-ng-proxy`;
    7. `verify()`, and on a false result automatically `rollback(backup)` and raise.
  - `rollback(backup_dir: Path, run=subprocess.run) -> None`
  - CLI: `postfix check | plan | apply [--yes] | rollback [--backup DIR]`. `check` prints the findings, including DKIM signer detection ("signing must be migrated before disabling rspamd/amavis — subproject 2"). The default `verify` performs an SMTP EHLO through each ASSP-NG listener and directly to each backend, expecting XCLIENT to be advertised.

- [ ] **Step 1: Write failing tests:**
  - `test_detect_plain_debian`
  - `test_detect_postscreen_postgrey_rspamd_keep_for_now`
  - `test_detect_dkim_signer`
  - `test_plan_comments_out_with_marker`
  - `test_plan_adds_internal_services`
  - `test_plan_refuses_port_conflict`
  - `test_apply_backup_and_rollback_on_verify_failure`
  - `test_apply_refuses_ispconfig`
  - `test_diff_rendered`
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `feat(postfix): add Postfix integration assistant`.

### Task 35: Packaging and documentation

**Files:**
- Create:
  - `packaging/systemd/assp-ng-proxy.service`: exactly the §8.2 unit, including `RuntimeDirectory=assp-ng` and `RuntimeDirectoryPreserve=restart`
  - `packaging/systemd/assp-ng-notify@.service`: `Type=oneshot`, `ExecStart=/usr/local/bin/assp-ng notify --event service-failed --message "%i failed"`
  - `packaging/logrotate/assp-ng`: `maillog.log` and `assp-ng.log` daily with `rotate 30`, `debug.log` daily with `rotate 7`, all with `compress`, `missingok` and `create 0640 assp-ng assp-ng`
  - `packaging/bin/assp-ng`: `exec env PYTHONPATH=/opt/assp-ng python3 -m asspng.cli "$@"`
  - `packaging/certbot/assp-ng-deploy-hook`: copies `$RENEWED_LINEAGE/{fullchain,privkey}.pem` to `/etc/assp-ng/tls/<name>/` with `0640 root:assp-ng` and reloads the service
  - `packaging/config/assp-ng.toml.example`: §7.3 with comments
  - `packaging/install.sh` (§8.9; idempotent, `set -euo pipefail`, must run as root):
    1. apt packages;
    2. the system user and group;
    3. directories;
    4. code copied to `/opt/assp-ng`;
    5. the wrapper to `/usr/local/bin/assp-ng`;
    6. units, logrotate and the deploy hook;
    7. `assp-ng config init` (unless the file exists);
    8. it prints the next steps: DB creation, `db upgrade`, `postfix plan`
  - `docs/installation.md`: install, database, Redis persistence (§6.3), Postfix, certificates, DKIM note (§1.4)
  - `docs/acceptance-checklist.md`: §10.2 layer 6 and §10.4
  - `tests/unit/packaging/test_packaging.py`

- [ ] **Step 1: Write failing tests:**
  - `test_unit_matches_spec_directives`: parse the unit file and assert `Type=notify`, `WatchdogSec=30`, `MemoryMax=512M`, `MemoryHigh=384M`, `Environment` contains `MALLOC_ARENA_MAX=2`, `Wants=` (not `Requires=`) Redis and MariaDB, `RuntimeDirectoryPreserve=restart`, `OnFailure=assp-ng-notify@%n.service`
  - `test_systemd_analyze_verify` (skipped when `systemd-analyze` is missing)
  - `test_shellcheck_scripts` (skipped when `shellcheck` is missing)
  - `test_example_config_loads`: copy the example + `render_default_toml` into a temporary directory → `load_config` succeeds after the certificate paths are replaced with generated test certificates
- [ ] **Step 2: Run them.** → FAIL.
- [ ] **Step 3: Create the files.**
- [ ] **Step 4: Run them.** → PASS.
- [ ] **Step 5: Commit** `build: add systemd units, installer, logrotate and documentation`.

### Task 36: Security suite, load test and CI completion

**Files:**
- Create: `tests/security/test_limits_and_abuse.py`, `tests/security/test_no_secrets_in_logs.py`, `tests/load/run_load.sh`, `docs/performance.md` (template)
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the whole application (end-to-end fixtures from Task 31).

- [ ] **Step 1: Write the failing security tests:**
  - `test_overlong_command_500_then_continue`
  - `test_slow_client_times_out`: `timeouts.command = 1` in the test config
  - `test_connection_flood_hits_per_minute_limit_and_penalty`
  - `test_no_secrets_in_logs`: run AUTH success, AUTH failure and a debug `all` rule with `--headers`, then scan `assp-ng.log`, `maillog.log`, `debug.log` and the captured stderr for the password and its base64 forms
  - `test_relay_attempt_flood_penalised`
- [ ] **Step 2: Run them.** `python3 -m pytest tests/security -v`. Expect a FAIL wherever behaviour is missing, then fix it in the owning module.
- [ ] **Step 3: Write `tests/load/run_load.sh`.** It runs `smtp-sink` as the backend, the proxy with a temporary config, and `smtp-source -s 500 -m 10000` against it. It measures messages per second and RSS at baseline, at peak and 90 s after the end (idle housekeeping). The results go to `docs/performance.md`. `ci.yml` gets:
  - an `integration` job with `redis-server` and `mariadb-server` started in the container and `ASSPNG_TEST_DB_URL` set;
  - a coverage gate `--cov-fail-under=85` for the core packages;
  - a nightly `schedule` job that runs `tests/load/run_load.sh`.
- [ ] **Step 4: Run** the full suite, `flake8`, `mypy` and `bash tests/load/run_load.sh` locally → all pass. Record the numbers in `docs/performance.md`.
- [ ] **Step 5: Commit** `test: add security suite, load test and complete CI`.

---

## Open items requiring the test server (not blocking this plan)

1. Validate the exact Postfix `master.cf` options (§8.10) against Postfix 3.10 on the test server. Then adjust `build_plan` and its fixtures.
2. Verify the ISPConfig custom-template mechanism, then lift the `apply_plan` refusal on ISPConfig hosts in a follow-up change.
3. Acceptance run per `docs/acceptance-checklist.md`, including 14 days in production mode (§10.4).
