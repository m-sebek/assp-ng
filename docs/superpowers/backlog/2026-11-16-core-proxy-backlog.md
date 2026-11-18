# Subproject 1 (core proxy) — deferred findings

| | |
|---|---|
| Source | Task reviews and the final whole-branch review of subproject 1 |
| Date | 2026-11-16 |
| Related | [Plan](../plans/2026-11-14-core-proxy.md), [Rulings](../rulings/2026-11-15-core-proxy-rulings.md) |

The reviewers found these small issues and test gaps and deliberately left them for later. None
of them blocked the merge. "(T12)" names the plan task whose review found the item.

Open items were **not re-checked against the code** after the final review, except where a note
says so. A later change may already have fixed one, so look at the code before working on it.
Items marked ⚠ touch security or privacy.

---

## 1. Final review: "should fix" items left out of the fix wave

- `normalize_domain`: ideographic or full-width dots can leave a trailing `.` in the key (T3).
- Tests are missing for:
  - AUTH inside a transaction (503) (T25);
  - rollback of a domain change when the audit insert fails (T27);
  - the `READY=1`, `WATCHDOG=1` and `STOPPING=1` systemd notifications (T31).
- Postfix assistant (to verify on the test server), from the T34 review notes N3–N6:
  - **N3:** the check that Postfix is active takes one sample; it should poll while Postfix is
    activating or reloading;
  - **N4:** rollback always probes `127.0.0.1` for wildcard services, but `inet_interfaces` may
    exclude loopback;
  - **N5:** risky overrides are counted even when they equal the `main.cf` value (a false
    positive with amavis);
  - **N6:** the message "restore by hand" appears after the files were already restored.
- AUTH handling (protocol details):
  - AUTH before EHLO;
  - a 503 is counted as a failed authentication;
  - 504 for an unsupported mechanism.
- Sender-level defaults without AUTH.
- Spool file I/O runs on the event loop.
- logrotate configuration and `su`.
- `MemoryStore` purges in O(n) when it is full.
- The shutdown budget versus systemd `TimeoutStopSec`.
- `alerts.smtp_server` does not accept `[ipv6]:port`.
- Dead code: `DomainRefresher.run`, `PenaltyBox.blocked_until`, `MessageBuffer.spooled` and
  `MessageBuffer.oversize`, the empty `Housekeeper` caches, `_default_status`.

## 2. Parked at the final review

- An MTA final 421 followed by our RSET gives the client a second 421.
- A relayed MTA 421 other than the final reply does not end the session.
- Session-level check notes and scores are not capped.
- The remote-database TLS check (R66) accepts `ssl_disabled` as a TLS parameter.
- Malformed paths get 500 where 501 would be more exact.
- `shutdown()` called while `start()` is still running is not handled. Signals during start were
  fixed in C3.

## 3. Still to verify on the test server

- The `postfix@-` unit layout and restart order.
- Real `postconf -M` and `postconf -P` captures to replace the canned fixtures. The current
  `-M` stand-ins omit the command arguments (T34).
- The ISPConfig template mechanism.
- `install.sh` at run time. The code swap and its recovery were only checked statically (T35).
- The load job (`smtp-source` → ASSP-NG → `smtp-sink`) has produced CI numbers since
  2026-11-17 (`docs/performance.md`), but none from the test server yet.
  - Its first nightly run (2026-11-17) failed at the start: `smtp-sink` refuses to run as root
    without `-u`, and CI containers run as root.
  - `run_load.sh` now passes `-u nobody` as root, waits for `smtp-sink` before starting the
    proxy, and raises `smtp-sink`'s connection limit.
  - The job can also be started by hand (`workflow_dispatch`).
  - The unit and integration CI jobs passed on 2026-11-16.
  - A manual run on 2026-11-17 passed. RSS stayed 22 MiB above the baseline after the idle wait.
    The investigation on 2026-11-18 found no leak, only CPython's arena plateau (spec 8.7,
    item 4). The script now runs several rounds, and `docs/performance.md` judges whether that
    plateau grows from round to round. The test server still has to produce its numbers.

## 4. Open minor findings by area

### SMTP parsing and protocol

- Source routes are not validated (T3).
- A tab between the path and the parameters of an unbracketed MAIL is accepted (T3).
- `split()` splits on Unicode whitespace (T3).
- There is no pre-check for huge labels (T3).
- `int()` on a SIZE value of more than 4300 digits raises `ValueError` (T5).
- ⚠ AUTH usernames accept U+2028, U+202E, U+200B and U+FEFF (T21).
- `commands.py` chains `AddressError` with the address text (T21).
- The assumption that the MTA handles NUL bytes in DATA is not documented (T6).
- `format_field` limits the value, not the whole line (T6).
- `read_line` keeps a duplicated CRLF strip, and `ReadTimeout` lives in `replies.py` (T4).

### Message buffer

- `BufferBudget.release` silently clamps an over-release (T7).
- A failed buffered write only shows up at read time, without marking the buffer as failed (T7).

### Configuration

- NaN and infinity are accepted for float settings (T8).
- A trailing comma gives an empty list element (T8).
- Setting descriptions could explain more: duration suffixes, the meaning of 0, which modes use
  the IP or message score, and that "network" means prefix grouping (T8).

### Domains and database

- A per-instance `lru_cache` creates a reference cycle, so an old resolver is freed only by the
  cyclic garbage collector (T10).
- There is no directory `fsync` after `os.replace` of the domain snapshot (T11).
- The normalisation of `DomainEntry.domain` is not enforced (T11).
- The `IntegrityError` → `DomainExistsError` translation also wraps the audit insert, so other
  integrity failures are misreported (T27).
- Database layer gaps (T27):
  - `DatabaseDomainSource` has no `close()`;
  - there is no test that the migrations match the metadata;
  - timestamps are naive server-local time, and `onupdate` is applied only by the client;
  - SQLite does not enforce `VARCHAR` lengths.
- The refresher sets `_loaded` and `_down_since` before `DomainIndex(entries)` succeeds; it should
  build the index first (T28).
- Refresher behaviour (T28):
  - in the unloaded state, the fallback re-reads the snapshot on every failure;
  - the `DomainIndex` is built on the event loop.

### State, penalty box and limits

- ⚠ `MemoryStore` `StateTypeError` messages include the key repr, which can leak an address if
  logged. `RedisStore` sanitises it (T14).
- A strict TEMPFAIL raise lacks exception chaining (T14).
- Fallback entries written in NORMAL mode linger until the probe recovers (T14).
- Redis keep-alive (T13):
  - the reply to the quiet-period PING is not checked;
  - TCP keep-alive uses the OS default idle time.
- The `_counter` log uses `key.rsplit`, which truncates IPv6 network keys in the log (T17).
- Redis round trips per connection (found 2026-11-18). With the state in Redis, a saturated proxy
  handles about 595 instead of about 800 messages/s, and spends about 0.45 ms more CPU per
  message (`docs/performance.md`). Each operation is a separate round trip; for example, the
  penalty-box check reads three keys at every connect. A pipeline or one Lua script per check
  would cut that. Not needed for the test server's load.

### TLS and DNS

- The certificate files are read separately for the context and for `not_after`. A renewal
  race could make `days_left` describe another certificate (T18).
- An empty configured hostname is registered silently (T18).
- There is no in-flight deduplication of concurrent PTR lookups for the same IP (T19).

### MTA backend

- The EHLO and XCLIENT timeouts were hard-coded to 30 s. Task 24 may have resolved this through
  the backend timeouts; check (T20).

### Logging, redaction and debug

- `configure_logging` leaks opened `WatchedFileHandler`s if `setLevel` or the systemd import
  fails (T22).
- ⚠ The maillog control-character check ignores C1 characters and U+2028/U+0085 (T22).
- ⚠ Two gaps in the mid-line AUTH redaction (T22, R20):
  - a payload literally equal to `PLAIN` or `LOGIN` is not masked;
  - a payload that starts with a quote (`x AUTH "pw"`) stays unmasked.
- ⚠ `stack_info` redaction shares one `try` with `formatException`. If `formatException`
  fails, `stack_info` stays unredacted (T22).
- Debug rules file (T23):
  - `bool(entry["headers"])` turns `"false"` into True on load;
  - duplicate ids in a hand-edited file are not rejected.
- There is a redundant `os.chmod` after `mkstemp`, and an `fdopen` failure leaks the file
  descriptor (T23).
- ⚠ The value of a LISTENER debug rule is not checked for control characters (T23).
- Truncating the debug log and growing it back past its remembered size is not detected as a
  truncation (T23).
- ⚠ An AUTH continuation line that is 4-letter base64 equal to a known verb (for example `DATA`)
  is tapped in clear. Its entropy is trivial (T25).
- XCLIENT is tapped as `P>M` before `backend.xclient()` runs, which is wrong when XCLIENT is
  unsupported. The MTA's EHLO reply inside `SmtpBackend.xclient` is never tapped (T24).

### Session

- `_check_and_forward` does not restore the tentative `txn.policy` and `current_rcpt` if
  `_forward` raises (T25).
- The `_SUBJECT` regex misses `Subject :` with whitespace before the colon (T26).
- `strip_fields` keeps leading continuation lines when used on its own. Only `_outgoing_head`
  guards against it (T26).
- Optional: skip the RSET after a failed final reply when 354 was seen (T26).

### Service

- Health endpoint (T29):
  - headers over 8 KiB after a valid request line get 200 instead of 400 or 431;
  - the status logic is duplicated in `HealthState.status_code` and `_default_status`;
  - `_safe_url` raises `ValueError` on a bad port, and in that branch it calls `urlsplit` again;
  - `_last` grows by one entry per event name.
- Control socket (T30):
  - the process-wide umask `0o117` is held across an `await` in `start()`. Fix: bind the socket
    synchronously, then call `start_unix_server(sock=…)`;
  - a reply over 1 MiB raises a raw `ValueError`;
  - `_encode` allows NaN;
  - a connection accepted just before `close()` can make `wait_closed` wait 30 s;
  - for a stale root-owned socket, the message only says it cannot probe it; it could tell the
    operator to remove the file.
- In `_serve`'s `finally`, a `CancelledError` during the graceful `wait_closed` skips the cleanup.
  This is harmless, because `close()` aborts the tracked writers (T30).
- A failed start leaves sessions accepted in that window running (T31).
- `main()` prints only `cannot start: OSError` when the OSError has no errno. An example is
  "AF_UNIX path too long" when `paths.run` is longer than the socket path limit allows (found
  2026-11-17). Such messages carry no secrets and could be shown. A config check could also
  reject a `paths.run` that is too long.
- `localhost` in `health.listen` is trusted by name. It is resolved at bind time, and
  `/etc/hosts` is root-controlled (T31).

### CLI

- Messages (T32):
  - the wording "the change is invalid" misleads when the existing config is already broken;
  - the ELOOP message is the raw strerror; it should say the lock file is a symbolic link.
- File handling (T32):
  - `cmd_doc --output` is not atomic;
  - replacing a symlinked config file turns it into a regular file, which is not documented.
- The ops commands print a fixed "invalid config" message instead of the value-free
  `ConfigError` list that the config commands show (T33).
- `domain` and `notify` commands (T33):
  - `domain list` prints an always-empty note column;
  - `domain add` and `domain remove` echo the raw argument instead of the normalised name;
  - a notify failure names only the configured channels, because the Alerter returns one bool;
  - an empty `redis.url` ends in "unexpected" without the Redis hint.
- General address literals (`[Tag:x]`) are now rejected. This is stricter than before (T33).

### Postfix assistant

- Backups do not keep the owner and group (`copy2`) (T34).
- `_restore` creates missing directories with root and the default mode (T34).
- A second Ctrl-C during an automatic rollback escapes without the backup-path message (T34).
- DKIM keys at rspamd's default path are missed (T34).

### Network lists

- A mapped CIDR in a network file (`::ffff:x/120`) never matches (T2).
- `is_private` excludes CGNAT `100.64/10`, as the plan requires. Worth a note for
  whitelisting (T2).

### Packaging and CI

- `ASSPNG_TLS_DIR` in the root-run certbot hook exists only for tests. Make it a positional
  argument, or document it as test-only (T35).
- Packaging checks (T35):
  - the `systemd-analyze` filter for "User"/"Group" may hide unknown-key messages;
  - the `logrotate -d` check is case-sensitive;
  - `config init` runs before `umask 027`;
  - the installer relies on GNU `tar --transform`, and `__init__.py` is its only completeness
    check.
- `installation.md` should name `redis-server` and `mariadb-server` as prerequisites (T35).
- CI workflow:
  - the package list is duplicated between the unit job and `PYTHON_PACKAGES`;
  - the coverage gate is an aggregate, so a single module can be low (`state/base.py` 62 %);
  - `actions/checkout@v4` runs on the deprecated Node.js 20 (a CI annotation on 2026-11-16);
  - `pyproject.toml` declares a dynamic version without a build backend (T1).
- ⚠ The header denylist in the debug header tap is incomplete by nature (`Set-Cookie`,
  `X-Api-Key`, …). Consider logging only the names of unknown headers (T36).

### Test gaps

- `read_line` (T4):
  - no test for a line over 64 KiB without a newline;
  - only 5 of 31 reply constants are asserted.
- Command parsing (T3, T5):
  - no test for the `AUTH=<>` parameter;
  - no mixed-case XCLIENT/XFORWARD regression test;
  - no lowercase AUTH, SIZE-parameter or tab tests.
- A DataReceiver scan-offset mutant survives; it affects performance only (T6).
- A 20 MiB test parameter is allocated at collection time (T6).
- Domain and database tests (T10, T28):
  - no tests for recipients with a quoted local part or `@` in the local part, for an IDN
    sender, or for a cache hit;
  - refresher gaps: the worker thread, a counter that proves no concurrent loads, cancellation
    inside `to_thread`, recovery from snapshot to database.
- `test_ttl_ceil_is_float_safe` uses float-fragile clock arithmetic (T12).
- No test for the quiet-period PING path (T13).
- No "N failures at once" test with `gather` (T14).
- `test_check_propagates_state_error` has an unused `box` parameter (T16).
- The `days_left` test uses the real current time (T18).
- FakeMta tests (T20):
  - nothing asserts that a completed DATA clears the FakeMta envelope;
  - the write-stall test relies on about 20 MB exceeding the loopback buffers.
- Logging tests (T22):
  - `test_setup.py` imports helpers from `test_maillog.py`;
  - no test that log handler I/O runs off the event loop thread.
- Debug log tests poll with a 5 s `wait_for`, a mild flakiness risk on CI (T23).
- Session tests, T24:
  - cancellation during the PTR/connect gather;
  - XCLIENT/ETRN with leading whitespace or tabs;
  - `wait_sessions` uses `return_exceptions`, which hides escaped exceptions.
- Session tests, T25:
  - `test_session_envelope.py` is large; the AUTH tests could move to `test_session_auth.py`;
  - the blocked-user, backend-loss and over-long-line AUTH tests lack no-secret assertions.
- Session tests, T26:
  - cancellation mid-DATA with a spooled message;
  - cleanup assertions on reject, timeout and backend loss;
  - all four own header fields in one message, in §4.8 order.
- Service tests, T29 and T30:
  - loose `_deliver` typing; the notify tests live in `test_memory.py`; a weak `or` assertion;
  - a whitespace-only webhook is untested;
  - control socket: mid-reply disconnect, a client without a newline, concurrent stalled and
    healthy clients, probe timeout or OSError refusal, KeyError/TypeError mapping,
    CancelledError, the monkeypatched `chown` PermissionError.
- Service tests, T31:
  - `test_main_start_failure_exits_1_and_cleans_up` has vacuous cleanup assertions;
  - no application-level test of a failed TLS reload (a corrupt PEM) after `build_runtime`.
- CLI tests, T32:
  - a pre-existing symlink at the target or `.bak`; unusual IDN scopes; `%2f` in an address; a
    failing `.bak` write;
  - the group test cannot tell the parent's gid from the process gid; the lock file's group is
    untested;
  - a dangling-symlink lock file.
- CLI tests, T33:
  - no positive test for adding an IDN or address-literal domain;
  - a timeout assertion only compares with the default.
- Load and redaction tests, T36:
  - the trickle bound of 1.6 s may flake on a loaded CI;
  - a cancelled drip task is not awaited;
  - the mapped-IPv4 test no longer exercises `rl:conn`.
- `fake_clock` itself is untested (T1).

---

## 5. Fixed after being deferred

| Finding | Fixed by |
|---|---|
| ⚠ Third-party loggers bypassed `RedactionFilter`: library records (redis, sqlalchemy, asyncio) went unredacted to logging's last-resort stderr handler (T22) | 2026-11-18: a second queue handler with the redaction filter on the root logger, from WARNING up |
| ⚠ Log queues were unbounded: on a stalled disk, memory grew (T22, T23) | 2026-11-18: the main log queue and the debug log queue hold at most 10 000 entries; further ones are dropped, counted and reported once the writer catches up |
| With the database down at start, the schema check was skipped for good (T31) | 2026-11-18: it runs before the first load instead; a mismatch keeps the snapshot and alerts once, as at start |
| `PenaltyBox.add_score` was a non-atomic read-modify-write, so concurrent threshold crossings could block twice and skip a ladder level, and a manual `block()` could shorten an active block (T16) | 2026-11-18: `StateStore.update_hash` (a Lua script on Redis) adds the score atomically, one `delete` decides the single crossing, and a manual block keeps a longer one in force |
| Redis failures under saturation: 500 sessions at about 770 messages/s kept one core busy, the event loop's lag (up to about 140 ms per step) exceeded the 200 ms `redis.op_timeout_ms`, and every load round switched to DEGRADED; the log named only `StateError` (found 2026-11-18) | 2026-11-18: the default is 1000 ms, and the log names the underlying error type |
| The integration CI job did not check that `ASSPNG_TEST_DB_URL` is set, and `run_load.sh` did not verify the delivered message count (T36) | 2026-11-18: the job fails without the URL; the script counts the accepted messages in the maillog |
| Listeners used asyncio's default listen backlog of 100. A burst of over 100 connections overflowed the accept queue; the kernel fell back to SYN cookies and dropped the connections it could not queue, which clients kept waiting on for a greeting (found 2026-11-18 by the load test) | 2026-11-18: `LISTEN_BACKLOG = socket.SOMAXCONN`, capped by the kernel at `net.core.somaxconn` |
| The proxy imported Alembic only to read the schema revision, about 10 MB of RSS for the life of the service (found 2026-11-18) | 2026-11-18: `current_revision()` reads `alembic_version` with SQLAlchemy; only `db upgrade` imports Alembic |
| Unquoted `@` in the local part accepted (T3) | A5, ruling R61 |
| Negative relay tests missing (T25) | A5, `tests/security/test_relay_routing.py` |
| Session tests did not run the production check order (T36) | A3, ruling R63 |
| `MessageBuffer.close()` could leave the spool file (T7) | C9 |
| No `threshold <= score_cap` validation (T16) | C7 |
| Vacuous front-context reload test, untested SNI callback error path (T18) | C11 |
| PTR test helper stubbed all targets (T19) | C11; the tests now use real dnspython rdata |
| `DebugLog.write` could raise if the thread failed to start (T23) | C6 |
| IP-score exemption duplicated in session and engine (T24) | C13 |
| RSET sent to the MTA before the refusal reply (T26) | C10 |
| `HealthServer.close` waited before cancelling connections (T29) | C5 |
| `_closed.set()` not in `finally` (T31) | C2 |
| Signals during `start()` took the default action (T31) | C3 |
| `cannot start: OSError` without errno (T31) | C4 (errno and strerror are shown when present) |
| Credential concern for listeners with AUTH and a remote backend (T34) | A4, ruling R65 |
| ⚠ A DB test assertion could print the database URL on failure (T27) | The assertion no longer exists (re-checked 2026-11-16) |
| ⚠ `config show` printed secrets in URL query parameters, such as `?password=` or `ssl_key_password=` (T32) | 2026-11-16: only known harmless parameters are shown, all others as `***` |
| The MariaDB suite had not run (T27) | Runs locally and in CI |
| CI jobs had not run, and the workflow had no `permissions` block (T36, T1) | CI green since 2026-11-16, `permissions: contents: read` |
| Implicit-TLS handshake not bounded (R59), debug taps missing (R68), reload switched `paths.spool` (C8) | The release-blocker fixes (see the rulings) |
