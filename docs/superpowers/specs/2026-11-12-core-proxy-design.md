# ASSP-NG — Subproject 1: Core SMTP Proxy — Design

| | |
|---|---|
| Status | Draft for review |
| Date | 2026-11-12, revised 2026-11-14 |
| Related | [Decisions for later subprojects](2026-11-14-later-subprojects-decisions.md) |
| License | GPL-3.0-or-later |
| Target platform | Debian 13 (trixie), Python 3.12+ (Debian 13 ships 3.13) |

---

## 1. Context

### 1.1 What ASSP-NG is

ASSP-NG ("Next Generation") is a successor to **ASSP v1** (Anti-Spam SMTP Proxy, final release
1.10.1 from 2014). It keeps the v1 principle: a **transparent SMTP proxy in front of the real
mail server (MTA)**. The proxy relays the SMTP dialogue between the client and the MTA command by
command, intercepts it where needed and rejects spam **during the SMTP session**. Unwanted mail is
never accepted, so the system never has to bounce it, and no backscatter is produced. The final
`250` for a message always comes from the MTA itself.

ASSP-NG reimplements v1 **behaviour**, not its code or its 791 configuration options. It uses a new,
clean configuration and data model. A later tool will import data from v1.

### 1.2 Goals (in priority order)

1. **Security**
2. **Reliability**
3. **Low resource usage**
4. **Processing speed**

### 1.3 Project-wide decisions

| Topic | Decision |
|---|---|
| Language | Python 3.12+, `asyncio` |
| Dependencies | **Only packages from the official Debian 13 repositories** (apt). No pip, no Docker. Distribution: install script first, `.deb` package later. |
| Persistent data | MySQL/MariaDB via SQLAlchemy Core + Alembic. PostgreSQL may follow later. |
| Hot state | Redis |
| Configuration | Layered files in `/etc/assp-ng/`: system, default policy, per-domain, per-mailbox. **Not** stored in the database. |
| Lists and learning data | Whitelist, blacklist and other lists, plus Bayes data, live in MySQL and are shared between instances. |
| Processes | `proxy` (SMTP), `web` (UI), `worker` (scheduled jobs). Supervised by systemd. |
| Language of code and docs | English (code, comments, documentation, commit messages) |
| License | GPL-3.0-or-later |

### 1.4 Deployment assumption

ASSP-NG is the **only spam filter** on the host. The only companion service is ClamAV (`clamd`),
which ASSP-NG will call itself (subproject 3). Postfix runs without postscreen, postgrey,
`reject_rbl_client`, rspamd, amavis or other content filters, and keeps only basic sanity
restrictions. This has three consequences:

- No verifier sits behind ASSP-NG. ASSP-NG is responsible for SPF, DKIM and DMARC evaluation.
- DKIM **signing** of outbound mail is not spam filtering and must keep working. Today ISPConfig
  usually does it with rspamd. The replacement is **OpenDKIM in sign-only mode as a Postfix
  milter**, which also signs mail that never passes through ASSP-NG (local `sendmail`, PHP
  `mail()`). The Postfix assistant sets it up with the existing keys (8.10).
- Hosts **without ISPConfig** are fully supported. ISPConfig is one optional source of data
  (DKIM keys now, local domains later), never a requirement.
- While only subproject 1 is deployed, the test server has no spam filtering apart from limits
  and the penalty box.

### 1.5 Subproject decomposition

Each subproject gets its own design → implementation plan → implementation cycle.

1. **Core proxy (this document)**
2. v1 checks: HELO, sender, DNSBL/RWL, SPF, DKIM and DMARC verification, MX, PTR, regex filters,
   greylisting, lists (whitelist, blacklist), automatic whitelist, reply tracking
3. Content and learning: Bayes and its rebuild, ClamAV, attachments, URIBL, message collections,
   decoding of TNEF (`winmail.dat`) into regular MIME attachments, marketing-mail classification
   and the `bulkblock` list
4. Outbound protection: per-user anomaly detection, automatic account lock
5. Web interface: administration, reporting and learning, data management, one-click unsubscribe
   on the user's behalf
6. Modern extensions: ARC, Spamhaus DQS, AI phishing check, ISPConfig domain source

Subprojects 1 and 2 together form the first release that "works like ASSP".

---

## 2. Scope of subproject 1

### 2.1 In scope

- The `asspng-proxy` process: an asyncio SMTP proxy.
- Listeners for port 25 (inbound), 587 (submission, STARTTLS) and 465 (submissions, implicit TLS).
  IPv4 and IPv6 can each be enabled or disabled per listener.
- One backend (MTA) connection per client session, with optional **XCLIENT** (Postfix).
- SMTP session handling: lockstep relay of commands, EHLO capability filtering, local STARTTLS,
  AUTH passthrough (PLAIN, LOGIN), relay decision, buffered DATA with checks before delivery.
- Check framework: phases, modes, scoring, decisions, global test mode.
- Core checks: connection and session limits, rate limiting, AUTH failure limits and the
  **penalty box with escalation**.
- State in Redis, with a degraded in-memory mode and fallback to temporary failure.
- Local domains in MySQL, with an on-disk snapshot used as a fallback.
- Layered configuration (system, default, domain, mailbox) with validation, safe reload, a CLI that
  edits the files, and policy-based recipient grouping.
- Logging (maillog and application log), a temporary targeted debug switch, alerts, health
  endpoint, memory management.
- Admin CLI `assp-ng`.
- systemd units, install script for Debian 13, Postfix integration assistant.
- A complete test suite and CI.

### 2.2 Out of scope (later subprojects)

- All v1 spam checks except limits and the penalty box (subproject 2 and later)
- Reply tracking, ClamAV, Bayes, URIBL
- Outbound anomaly detection and automatic account lock (subproject 4)
- `web` and `worker` processes. The application health monitor moves into the worker later.
- PostgreSQL, import from ASSP v1, ISPConfig integration
- SMTP `PIPELINING` and `CHUNKING`/`BDAT`
- The v1 "relay port" workflow (MTA → ASSP → smarthost)
- AUTH mechanisms other than PLAIN and LOGIN

---

## 3. Architecture

### 3.1 Runtime

A **single asyncio process** handles all listeners and sessions. One coroutine serves each client
session. Shared state lives in Redis, so the design already allows several processes on the same
ports (`SO_REUSEPORT`) or several hosts later without changes (see 3.4).

The process runs as the unprivileged user `assp-ng`. systemd grants only
`CAP_NET_BIND_SERVICE` for binding ports below 1024.

### 3.2 Package layout

```
asspng/
  config/    layered TOML loader (system/default/domain/user), typed settings registry with
             levels, policy resolver, validation, docs generator, comment-preserving editor
  smtp/      protocol primitives: line reader with limits, command parser, reply parser,
             address parser (SMTPUTF8, IDN), EHLO capability filter, dot-stuffing codec
  proxy/     listener manager, Session state machine, BackendClient, MessageBuffer, XCLIENT
  tls/       SSL context factory, certificate store, SNI, reload
  checks/    Check protocol, phases, results, scoring engine; core checks
  state/     StateStore protocol, RedisStore, MemoryStore, degraded-mode controller
  db/        SQLAlchemy Core tables, Alembic migrations, repositories, DomainSource
  net/       IP helpers (network keys), async DNS wrapper (PTR for XCLIENT)
  log/       maillog writer, application logging, debug rules and debug log, secret redaction
  service/   systemd notify/watchdog, health endpoint, control socket, signals,
             memory housekeeping, alerts
  cli/       admin CLI
packaging/   systemd units, install script, default config, logrotate, Postfix example
docs/        user and developer documentation
tests/       unit, session, integration, security, load
```

### 3.3 Design principles

- **Small units with clear interfaces.** `Session` depends only on the protocols
  `BackendClient`, `CheckEngine` and `StateStore`, so it can be tested with fakes.
- **The database stays out of the mail hot path.** Configuration comes from files. Local domains
  are cached in memory. Redis is the only external dependency touched per session.
- **Fail safe, not fail open.** When ASSP-NG cannot decide (missing data, internal error), it
  answers with a temporary failure (4xx) and never with a permanent rejection (5xx). It never
  passes unchecked mail as if it had been checked.
- **Our own errors never block mail.** A check that raises or times out counts as neutral, is
  logged, and is counted in the health status.

### 3.4 Multi-instance readiness

Several ASSP-NG instances (for example a primary and a backup MX) may point to the **same MySQL
database and the same Redis**. They then share local domains, penalty box state, escalation
history and rate-limit counters. This works because:

- every instance has a name (`instance`, default: `hostname`), which appears in logs,
  `X-ASSP-NG-ID` and the audit log;
- all Redis keys carry a configurable prefix (default `asspng:`), so unrelated deployments can
  share one Redis;
- concurrent-session counters are kept per instance in process memory. They protect the
  instance's own resources and must not leak across instances when a process crashes;
- on start the proxy checks the database schema version. If it does not match the code, the proxy
  logs an error, raises an alert and continues from the domain snapshot. `assp-ng db upgrade` runs
  once per shared database;
- configuration files stay per instance. Admins keep them in sync with their own tools
  (etckeeper, git, Ansible).

Connections to a remote MySQL or Redis must use TLS and authentication. Sharing of Bayes data
(subproject 3) will follow the same model: a shared token database in MySQL, local hot caches,
and a single rebuild leader chosen with a lock.

---

## 4. SMTP session

### 4.1 Listener kinds

| Kind | Default port | TLS | AUTH | Relay without AUTH | Penalty-box gate at connect |
|---|---|---|---|---|---|
| `smtp` | 25 | optional STARTTLS | not offered (configurable) | only from trusted networks | yes |
| `submission` | 587 | STARTTLS, **required before AUTH** | required before `MAIL` | no | no (AUTH limits apply) |
| `submissions` | 465 | implicit TLS | required before `MAIL` | no | no (AUTH limits apply) |

The penalty-box gate is skipped on submission ports. Otherwise a legitimate roaming user whose
shared IP (NAT, hotel, mobile carrier) landed in the penalty box could not send mail at all. On
those ports, brute force is handled by the AUTH limits and the per-network connection rate limit.

Every listener has its own `backend` (MTA address), `xclient` flag and `auth` flag. `auth`
defaults to `false` for `smtp` and to `true` for the submission kinds, and cannot be disabled on
them. Recommended Postfix backends: `127.0.0.1:10125` for `smtp` (no AUTH) and
`127.0.0.1:10587` for both submission kinds (AUTH enabled).

### 4.2 Connection setup

1. Accept the connection. For `submissions`, perform the TLS handshake (timeout 30 s) right
   after step 2.
2. Run the **CONNECT** phase checks: per-network concurrent sessions and connection rate, global
   session limit, penalty-box gate (where applicable), trusted-network flag, memory/tempfail
   state. A rejection sends `421`/`554` and closes the connection **without contacting the MTA**.
3. Resolve the client's PTR name asynchronously, with forward confirmation and a 3 s timeout,
   **in parallel with step 4**. It is used for XCLIENT and the maillog. Results are cached in
   memory for 1 hour.
4. Connect to the backend (timeout 10 s) and wait for its `220` banner (timeout 30 s). On failure
   the client gets `421 4.3.2 Service temporarily unavailable` and the failure is counted for
   health and alerts.
5. If `xclient = true`, send `EHLO <hostname>` to the MTA. If the MTA does not advertise
   `XCLIENT`, treat it as a backend failure (`421`) and log an error. **XCLIENT failures always
   fail closed**, because without XCLIENT the MTA would see `127.0.0.1` and might allow relaying.
   Otherwise send `XCLIENT ADDR=<ip> PORT=<port> NAME=<ptr|[UNAVAILABLE]|[TEMPUNAVAIL]>`
   (IPv6 as `ADDR=IPV6:<ip>`) and read the new `220` greeting.
6. Send ASSP-NG's own banner to the client: `220 <hostname> ESMTP <banner text>`. The MTA's
   banner is never shown, so its software stays hidden.

Order note (ruling R59): on `submissions` the CONNECT limits run before the TLS handshake, so
they also bound pending handshakes; a client refused there is disconnected without a reply.

### 4.3 Command handling

Commands are processed strictly one at a time (no pipelining).

| Command | Handling |
|---|---|
| `EHLO` / `HELO` | Run HELO-phase checks. Forward to the MTA. Filter the MTA's capabilities (4.4). Answer with ASSP-NG's hostname on the first line. |
| `STARTTLS` | Handled locally: `220 2.0.0 Ready to start TLS`, TLS upgrade of the client stream. Session state is reset, and the client must send `EHLO` again (RFC 3207). Refused with `454` if no certificate is configured, `503` if TLS is already active. |
| `AUTH` | See 4.5. |
| `MAIL FROM` | On submission kinds: `530 5.7.0 Authentication required` unless authenticated. Parse the address and parameters. Check `SIZE=` against the limit (`552 5.3.4`). Run MAIL-phase checks. Forward. |
| `RCPT TO` | Relay decision (4.6). Recipients-per-message limit (`452 4.5.3`). Policy grouping (4.11). RCPT-phase checks. Forward. MTA rejections (`550`) count as invalid recipients. |
| `DATA` | See 4.7. `BDAT` → `502`. |
| `RSET` | Forward. Reset transaction state. |
| `NOOP` | Forward, which keeps the MTA's idle timer alive. |
| `QUIT` | Forward, answer `221`, close both connections. |
| `VRFY`, `EXPN` | Answered locally with `252 2.5.2 Cannot VRFY user`. Never forwarded. |
| `HELP` | Answered locally with `214`. |
| `XCLIENT`, `XFORWARD`, `ETRN`, `TURN`, `ATRN`, anything else | Answered locally with `502 5.5.1 Command not implemented` (or `500` for syntax garbage). **Never forwarded.** A client must not be able to control the MTA. |

Protocol errors (unknown commands, bad syntax, wrong sequence) are counted per session. Above the
limit the client gets `421 4.7.0 Too many errors` and the network gets penalty points.

### 4.4 EHLO capability filtering

From the MTA's EHLO response:

- **Removed:** `STARTTLS`, `AUTH`, `PIPELINING`, `CHUNKING`, `BINARYMIME`, `XCLIENT`,
  `XFORWARD`, `ETRN`, `ATRN`, and any other `X…` extension.
- **Kept:** `SIZE` (rewritten to `min(MTA SIZE, max_message_size)`), `8BITMIME`, `SMTPUTF8`,
  `ENHANCEDSTATUSCODES`, `DSN`.
- **Added:** `STARTTLS` when TLS is available and not active. `AUTH PLAIN LOGIN` when TLS is active,
  the listener allows AUTH, and the MTA itself advertised AUTH.

The first response line uses ASSP-NG's `hostname`.

### 4.5 AUTH passthrough

- Allowed only when TLS is active (`538 5.7.11 Encryption required` otherwise) and the listener
  allows AUTH (`502` otherwise).
- Only `PLAIN` and `LOGIN`, including initial responses and cancel (`*`). Bad base64 → `501`.
- The exchange is forwarded to the MTA, which verifies the credentials. ASSP-NG extracts only the
  **username** (`authcid` for PLAIN, the first response for LOGIN). The password is discarded at
  once and **never logged, stored or kept** beyond the forwarding buffer.
- `235` from the MTA marks the session as authenticated with that username. Authenticated
  sessions may relay and are exempt from inbound reputation checks.
- `535` and other failures count toward AUTH limits per network and per username (5.6). Above the
  limits: `454 4.7.0 Temporary authentication failure`, then `421` with penalty points.

### 4.6 Relay decision

ASSP-NG decides locally at `RCPT TO`:

1. If the recipient domain is local (5.8), accept and forward.
2. Otherwise, if the session is authenticated or comes from a trusted network, accept and forward.
3. Otherwise reply `554 5.7.1 Relay access denied`, count it as a protocol error and add penalty
   points. Do not forward.

Thanks to XCLIENT, the MTA sees the real client address and applies its own relay restrictions as
a second line of defence.

`RCPT TO:<postmaster>` without a domain is always treated as local (RFC 5321).

If the local domain list is unavailable (no database and no snapshot), unauthenticated recipients
get `451 4.3.0` instead of `554`.

### 4.7 DATA handling

1. Without at least one accepted recipient, reply `554 5.5.1 No valid recipients`.
2. ASSP-NG answers `354` itself. **Nothing is sent to the MTA yet.**
3. The message is read into a `MessageBuffer`:
   - in memory up to `buffer.memory_per_message` (default 1 MiB), as long as the global in-memory
     budget `buffer.memory_total` (default 128 MiB) is not exhausted;
   - otherwise in a spool file in `/var/lib/assp-ng/spool/` (directory 0700, file 0600, random
     name, deleted right after delivery or rejection, leftovers deleted on start);
   - above `max_message_size`, ASSP-NG reads the rest and discards it, then answers
     `552 5.3.4 Message size exceeds limit`.
4. **End of data is recognised only as `CRLF.CRLF`.** A bare `CR` or `LF` inside the data is
   normalised to `CRLF`. Lines are dot-unstuffed for checks and dot-stuffed again when sent to the
   MTA. Any line that becomes a lone `.` after normalisation is therefore sent as `..`. This
   neutralises **SMTP smuggling** (different end-of-data interpretations between proxy and MTA).
5. Run the HEADER and BODY phase checks. Then decide:
   - **Accept.** Remove all incoming `X-ASSP-NG-*` header fields to prevent spoofing. Prepend
     ASSP-NG's own fields (4.8). Send `DATA` to the MTA, expect `354`, stream the message, send
     the final `.` and relay the **MTA's final reply** to the client.
   - **Reject.** Reply `554 5.7.1 <reason>`, or `451 4.7.1 <reason>` for temporary reasons, to the
     client. Send `RSET` to the MTA.
   - **Test mode / monitor.** Accept as above and add an `X-ASSP-NG-Test` field.
6. If the MTA does not answer `354` to `DATA`, relay its reply to the client.

### 4.8 Header fields added by ASSP-NG

| Field | When | Example |
|---|---|---|
| `X-ASSP-NG-ID` | always | `mx1-7f3a9c2e-1` (instance, session, transaction) |
| `X-ASSP-NG-Score` | `scoring.add_header = true` (default) and score ≠ 0 | `12 (conn_rate=5; pb_score=7)` |
| `X-ASSP-NG-Warning` | score in the warning band | `score 40 above warning level 35` |
| `X-ASSP-NG-Test` | test or monitor would have rejected | `would reject: penalty_box (score 55)` |

The warning band may also prefix the Subject (`scoring.warn_subject_tag`, default empty, so
disabled).

### 4.9 Timeouts (defaults, configurable)

| Timeout | Default |
|---|---|
| TLS handshake | 30 s |
| Backend connect | 10 s |
| Backend banner and XCLIENT greeting | 30 s |
| Client command (idle) | 300 s |
| Client data block | 180 s |
| Whole DATA transfer | 600 s |
| Backend reply to a command | 300 s |
| Backend final reply after `.` | 600 s |
| Graceful shutdown | 30 s |

### 4.10 Error handling

- **Backend connection lost during a session:** the client gets `421 4.4.2 Connection to mail
  server lost` and both sides are closed. The sender retries, so nothing is lost.
- **Unhandled exception in a session:** only that session ends (`421 4.3.0`). The exception is
  logged with the session id and counted in health. Other sessions are unaffected.
- **Client disconnect:** the backend gets `QUIT` (or is closed) and the spool file is deleted.
- **Input limits:** command line ≤ 2048 bytes (`500 5.5.2 Line too long`), ≤ 10 parameters per
  command, total message size as configured.

### 4.11 Per-recipient policy and recipient grouping

Recipient-level settings (scores, check modes, test mode, subject tags; see 7.2) can differ per
domain and per mailbox. After `DATA`, SMTP gives **one** final reply for all recipients of a
transaction, so a message cannot be accepted for one recipient and rejected for another.
ASSP-NG therefore keeps every transaction **policy-homogeneous**:

1. For each accepted recipient, resolve its **effective policy** (mailbox → domain → default →
   built-in) and compute a fingerprint from the recipient-level settings that affect the
   transaction decision.
2. The first accepted recipient fixes the transaction's policy fingerprint.
3. A later recipient with a different fingerprint gets `452 4.5.3 Too many recipients, try again`
   and is **not** forwarded. RFC 5321 requires the client to deliver the remaining recipients in a
   further transaction, which mail servers do right away, and that transaction carries its own
   policy.
4. Recipients that share a policy stay together (for example a whole domain without overrides),
   so ordinary mail is not split.
5. Recipients rejected at `RCPT` (relay denied, unknown user, blacklisted) do not count.

The transaction's effective policy is exposed to checks through `CheckContext`.

Settings that depend on the **authenticated sender** (for example outbound rate limits for a
newsletter mailbox) are resolved once per session from the AUTH username. They do not affect
grouping.

---

## 5. Checks, scoring and limits

### 5.1 Check protocol

```python
class Phase(Enum):
    CONNECT = 1; HELO = 2; AUTH = 3; MAIL = 4; RCPT = 5; HEADER = 6; BODY = 7

class Check(Protocol):
    name: str
    phase: Phase
    async def run(self, ctx: CheckContext) -> CheckResult: ...

@dataclass(frozen=True)
class CheckResult:
    hit: bool
    msg_score: int = 0          # added to the message score
    ip_score: int = 0           # added to the penalty box score of the network
    reason: str = ""
    reply: SmtpReply | None = None   # reply to use when the check blocks
    temporary: bool = False          # block with 4xx instead of 5xx
```

`CheckContext` gives read access to the session (client address and network key, listener kind,
TLS, authentication, HELO, envelope, buffered message), the transaction's effective policy (4.11),
the state store, the clock and the check's own configuration. Each check has its own
configuration. These settings are recipient-level, so a domain or mailbox can override them:

- `mode`: `off | block | monitor | score | test`
- `score`: `[message, ip]` pair, like v1 `*ValencePB`
- `timeout`
- `exempt`: `trusted`, `authenticated`

### 5.2 Decision rules (v1 behaviour)

- **block:** a hit rejects immediately with the check's reply (5xx, or 4xx if `temporary`).
- **score:** the hit's message score is added. After each phase the total is compared:
  - `≥ scoring.limit` (default 50) → reject `554 5.7.1 Message score too high`;
  - `≥ scoring.warn` (default 35) → mark (4.8) and continue.
- **monitor:** log only. No score, no rejection.
- **test:** log "would reject" and continue. `testmode = true` in the effective policy (default,
  domain or mailbox) turns every block and score rejection of a check into test behaviour. A new
  domain can therefore run in test mode while the others are live. Connection-level checks
  (before any recipient is known) follow `testmode` in `default.toml`. **Resource protection is
  never in test mode:**
  the instance session limit, the memory soft limit, TEMPFAIL, input limits and timeouts are
  always enforced.
- **IP score** goes to the penalty box (5.5) regardless of the message decision. It is skipped for
  private addresses, trusted networks, exempt networks and authenticated sessions.
- **Errors and timeouts** of a check count as neutral, are logged and are counted in health.
- Checks run in configured order within a phase, cheapest first. Evaluation stops as soon as a
  decision is reached.

### 5.3 Network key

All IP-based state is keyed by network: IPv4 `/32`, IPv6 `/64` (both configurable:
`network.ipv4_prefix`, `network.ipv6_prefix`). IPv4-mapped IPv6 addresses are treated as IPv4.

### 5.4 Core checks in subproject 1

| Check | Phase | Purpose |
|---|---|---|
| `conn_limits` | CONNECT | per-network concurrent sessions and connections per minute, global session limit |
| `penalty_box` | CONNECT | refuse blocked networks (`smtp` listeners only) |
| `session_limits` | MAIL, RCPT, any command | messages per session, protocol errors, invalid recipients, recipients per message |
| `auth_limits` | AUTH | failures per network and per username |
| `user_rate` | MAIL/RCPT | per authenticated user message and recipient rates |

### 5.5 Penalty box

Per network key:

- **Score record** `pb:<net>`: score, last reason, hit count, first and last hit time. The record
  expires `penalty_box.score_ttl` (24 h) after the last hit. The score is capped at
  `penalty_box.score_cap` (100).
- When the score reaches `penalty_box.threshold` (50), a **block** `pb:block:<net>` is created and
  the score record is cleared.
- **Escalation:** the block length depends on how many blocks the network already had within the
  history window, using the ladder `penalty_box.ladder` (default `["24h", "7d", "30d"]`): the 1st
  block lasts 24 h, the 2nd 7 days, the 3rd and later 30 days.
- **History** `pb:hist:<net>` counts blocks and expires `penalty_box.history` (90 days) after
  the most recent block. A network with no new block for 90 days starts again at level 1.
- At CONNECT on `smtp` listeners a blocked network gets `421 4.7.0 Try again later`. This is a
  temporary refusal: a legitimate sender who was blocked by mistake delivers after the block
  expires.
- The admin CLI can list, inspect, remove (`--forget` also clears history) and add manual blocks.
  Every manual change is written to the audit log.

### 5.6 Limits (defaults, configurable)

| Scope | Limit | Default | Response |
|---|---|---|---|
| network | concurrent sessions (per instance) | 5 | `421 4.7.0` + IP score |
| network | connections per minute | 30 | `421 4.7.0` + IP score |
| instance | concurrent sessions | 500 | `421 4.3.2` |
| session | messages | 50 | `421 4.7.0` |
| session | protocol errors | 5 | `421 4.7.0` + IP score |
| session | invalid recipients (`550` from MTA) | 5 | `421 4.7.0` + IP score |
| message | recipients | 100 | `452 4.5.3` (RFC 5321) |
| AUTH | failures per network / 15 min | 5 | `454 4.7.0`, then `421` + IP score |
| AUTH | failures per username across networks / 15 min | 10 | `454 4.7.0` |
| authenticated user | messages per minute / hour | 30 / 300 | `451 4.7.1` |
| authenticated user | recipients per hour | 1000 | `451 4.7.1` |

Rate limits use fixed windows in Redis (`INCR`, then `EXPIRE` on the first increment): one round
trip per check, and expiry is handled by Redis. Networks listed in `exempt-networks.txt` skip the
network-level connection limits.

### 5.7 Trusted and exempt networks

`/etc/assp-ng/trusted-networks.txt` lists networks that may **relay without AUTH** (v1
`acceptAllMail`). `/etc/assp-ng/exempt-networks.txt` lists networks exempt from connection
limits. Both files hold one CIDR per line, with `#` comments. Both are security policy, so they
live in files that only root can change, not in the database.

The IP lists `whitelistip`, `blacklistip` and `nodelayip` (subproject 2) live in the database and
**never grant relaying** or exemption from connection limits.

### 5.8 Local domains

- Table `local_domain` (5.9). Domains are compared lowercase and in IDNA/punycode form.
  `include_subdomains` covers all subdomains.
- `DomainSource` protocol. Subproject 1 implements `DatabaseDomainSource`. ISPConfig and others
  come later.
- The proxy keeps the list in memory. It reloads it on a Redis pub/sub message
  (`<prefix>events`, payload `domains-changed`), which the CLI publishes after a change, and also
  every 5 minutes.
- After each successful load the list is written to
  `/var/lib/assp-ng/cache/local-domains.json`. If MySQL is unavailable at start, the snapshot is
  used and health reports `db: degraded`. With neither, see 4.6.

### 5.9 Database schema (subproject 1)

Charset `utf8mb4`, managed by Alembic.

```
local_domain(id PK, domain VARCHAR(253) UNIQUE NOT NULL, include_subdomains BOOL NOT NULL DEFAULT 0,
             enabled BOOL NOT NULL DEFAULT 1, note VARCHAR(255), created_at, updated_at)
audit_log(id PK, ts, instance VARCHAR(64), actor VARCHAR(64), action VARCHAR(64),
          target VARCHAR(255), details JSON)
alembic_version(...)
```

---

## 6. State and degraded mode

### 6.1 StateStore

The `StateStore` protocol offers counters with windows, hashes with TTL and pub/sub. It has two
implementations: `RedisStore` (using `redis.asyncio`) and `MemoryStore`, an in-process store with
TTLs and a bounded entry count (default 200 000) that evicts the oldest entries when full.

Redis keys (prefix `asspng:` omitted):

| Key | Type | TTL |
|---|---|---|
| `pb:<net>` | hash | `score_ttl`, sliding |
| `pb:block:<net>` | hash (until, level, reason) | block length |
| `pb:hist:<net>` | integer | `history` |
| `rl:<limit>:<subject>:<window-start>` | integer | window length |
| `events` | pub/sub channel | — |

### 6.2 Modes

```
NORMAL --(3 consecutive Redis failures or Redis unreachable > 2 s)--> DEGRADED
DEGRADED --(Redis healthy again, checked every 10 s)--> NORMAL   (memory state is discarded)
DEGRADED --(MemoryStore failure or memory soft limit reached)--> TEMPFAIL
TEMPFAIL --(Redis healthy again)--> NORMAL
```

- A Redis operation has a 200 ms timeout. A single slow reply does not change the mode.
- **DEGRADED:** all checks keep running on `MemoryStore`. Health reports `degraded` and an alert
  is raised.
- **TEMPFAIL:** new connections get `421 4.3.0 Service temporarily unavailable` at the greeting.
  SMTP requires `421` when refusing at connect time. Sessions already in progress get
  `451 4.3.0` at their next `MAIL`, `RCPT` or `DATA`. An alert is raised.
- `state.on_redis_failure = "degraded"` (default) or `"tempfail"` for strict operation, which goes
  straight to TEMPFAIL.

### 6.3 Redis persistence (recommendation for docs)

Redis keeps serving requests while it persists data. RDB snapshots are written by a forked child
process, and the fork pause is negligible at ASSP-NG's data size (megabytes). AOF `everysec`
fsyncs in the background. The documentation will recommend keeping Debian's default RDB setup,
optionally enabling AOF `everysec`, and setting `vm.overcommit_memory = 1` so that the fork
cannot fail.

---

## 7. Configuration

### 7.1 Files and layers

```
/etc/assp-ng/                         root:assp-ng 0750
  assp-ng.toml                        system: instance, listeners, TLS, DB, Redis, paths, resources,
                                      connection-level limits, penalty box, alerts, logging
                                      (0640, contains DB/Redis credentials)
  default.toml                        default policy: check modes, scores, thresholds, test mode,
                                      tags, sender-level limits
  domain.d/<domain>.toml              per-domain policy overrides, e.g. domain.d/example.com.toml
  user.d/<mailbox>.toml               per-mailbox policy overrides, e.g. user.d/jano@example.com.toml
  trusted-networks.txt                networks allowed to relay without AUTH
  exempt-networks.txt                 networks exempt from connection limits
```

File names in `domain.d/` and `user.d/` are the lowercase IDNA (punycode) form of the domain or
address. Files contain only values that differ from the level below.

**Resolution order** for policy settings: mailbox → domain → `default.toml` → built-in default.

### 7.2 Settings registry and levels

Every setting is defined once in code: dotted name, type, built-in default, allowed range or
values, **level**, and an English description.

| Level | Allowed in | Resolved by | Examples |
|---|---|---|---|
| `system` | `assp-ng.toml` | — | listeners, TLS, DB, Redis, memory, connection limits, penalty box, alerts |
| `recipient` | `default.toml`, `domain.d/`, `user.d/` | recipient address (4.11) | `testmode`, check modes and scores, `scoring.limit`, `scoring.warn`, subject tags; later greylisting on/off, `whitelist.auto_scope`, `bayes.collect` |
| `sender` | `default.toml`, `domain.d/`, `user.d/` | authenticated username | per-user outbound message and recipient rates |

- **Unknown keys and settings at a level where they are not allowed are errors**, so typos and
  misplaced settings cannot pass silently.
- `assp-ng config check`: validates all files, DB, Redis, every backend (including XCLIENT
  support) and certificates. A submission listener without a usable certificate is an error,
  because AUTH requires TLS.
- `assp-ng config doc`: generates `docs/configuration.md` from the registry, including each
  setting's level, so the documentation cannot drift from the code.

### 7.3 Examples

`/etc/assp-ng/assp-ng.toml` (system):

```toml
instance = "mx1"
hostname = "mx1.example.com"

[database]
url = "mysql+pymysql://asspng:secret@localhost/asspng"

[redis]
url = "redis://localhost:6379/0"
key_prefix = "asspng:"

[[listener]]
name = "inbound"
kind = "smtp"
port = 25
ipv4 = true
ipv6 = true
backend = "127.0.0.1:10125"
xclient = true

[[listener]]
name = "submission"
kind = "submission"
port = 587
ipv4 = true
ipv6 = true
backend = "127.0.0.1:10587"
xclient = true

[[tls.certificate]]
name = "mx1"
hostnames = ["mx1.example.com"]
cert = "/etc/assp-ng/tls/mx1.example.com/fullchain.pem"
key  = "/etc/assp-ng/tls/mx1.example.com/privkey.pem"

[penalty_box]
threshold = 50
ladder = ["24h", "7d", "30d"]

[alerts]
email = "admin@example.com"
webhook = ""
```

`/etc/assp-ng/default.toml` (default policy):

```toml
testmode = false

[scoring]
limit = 50
warn = 35

[limits.user]
messages_per_minute = 30
messages_per_hour = 300
```

`/etc/assp-ng/domain.d/newcustomer.sk.toml` (new domain onboarded in test mode):

```toml
testmode = true
```

`/etc/assp-ng/user.d/newsletter@example.com.toml` (sender-level override):

```toml
[limits.user]
messages_per_hour = 5000
```

`[[tls.certificate]]` is a shared certificate store. SMTP listeners pick the certificate by SNI
and fall back to the first entry. The web interface (subproject 5) will reference an entry by
`name`.

### 7.4 Missing or invalid files

| Situation | At start | At reload |
|---|---|---|
| `assp-ng.toml` missing or invalid | refuse to start, clear error | keep running configuration, alert |
| `default.toml` missing or invalid | **refuse to start**, clear error naming `assp-ng config init` | keep running configuration, alert |
| a file in `domain.d/` or `user.d/` invalid | refuse to start, the error names the file | keep running configuration, alert |
| `domain.d/` or `user.d/` empty or absent | normal (no overrides) | normal |

ASSP-NG never recreates a missing file itself. The service cannot write to `/etc` (the sandbox
forbids it, and it should). Silently falling back to built-in defaults could also turn, for
example, a test-mode installation into one that rejects mail permanently. Refusing to start is the
safe choice: senders queue their mail and the admin gets the `OnFailure` alert.

`assp-ng config init` writes a complete `default.toml` with every policy setting present,
commented out and documented. The installer runs it.

### 7.5 Reload

`systemctl reload assp-ng-proxy` (SIGHUP), also triggered by every CLI change:

1. Load and **fully validate** all configuration files and network files.
2. If anything is invalid, **keep the running configuration**, log the error and raise an alert.
   A typo never stops mail.
3. If valid, swap it in atomically and log which settings changed (with file and level).
   Certificates are re-read. Running transactions keep the settings they started with.
4. Changes to listeners (ports, bind addresses, IPv4/IPv6) need a restart. Reload logs a warning
   that they are pending.

### 7.6 CLI for configuration

```
assp-ng config set   scoring.limit 60                           # default.toml
assp-ng config set   scoring.limit 80  domain:example.com       # domain.d/example.com.toml
assp-ng config set   scoring.limit 99  user:someone@example.com # user.d/someone@example.com.toml
assp-ng config set   redis.url "redis://..."  sys               # assp-ng.toml
assp-ng config unset scoring.limit domain:example.com
assp-ng config show  scoring.limit user:someone@example.com     # effective value and its source
assp-ng config show  [sys | default | domain:<d> | user:<a>]    # whole effective configuration
assp-ng config init | check | doc
```

- `set` validates the value and its level **before** writing, writes atomically (temp file,
  then rename), keeps a `.bak` of the previous file, and triggers a reload.
- Files are edited with `tomlkit` (Debian package `python3-tomlkit`), which **preserves comments and
  formatting**. Editing the files by hand is equally supported.
- `show` prints where each effective value comes from (`user`, `domain`, `default` or
  `built-in`).
- Every change made through the CLI is written to the audit log.

---

## 8. Operations

### 8.1 Filesystem layout

```
/opt/assp-ng/                 program code (install script; a .deb will use standard paths later)
/etc/assp-ng/                 configuration
/var/lib/assp-ng/             StateDirectory, assp-ng 0750
  spool/                      message buffers (0700)
  cache/                      local-domains.json snapshot
/var/log/assp-ng/             LogsDirectory
  maillog.log                 one line per message / session
  assp-ng.log                 application log
  debug.log                   output of active debug rules only (8.11)
/run/assp-ng/                 RuntimeDirectory, root:assp-ng 0750, kept across service restarts
  control.sock                local control socket for the CLI (0660)
  debug-rules.json            active debug rules
```

### 8.2 systemd unit (outline)

```ini
[Unit]
Description=ASSP-NG SMTP proxy
Wants=network-online.target redis-server.service mariadb.service
After=network-online.target redis-server.service mariadb.service
OnFailure=assp-ng-notify@%n.service

[Service]
Type=notify
User=assp-ng
Group=assp-ng
ExecStart=/usr/bin/python3 -m asspng.proxy --config /etc/assp-ng/assp-ng.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
WatchdogSec=30
TimeoutStopSec=45
Environment=MALLOC_ARENA_MAX=2 PYTHONPATH=/opt/assp-ng
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
StateDirectory=assp-ng
LogsDirectory=assp-ng
RuntimeDirectory=assp-ng
RuntimeDirectoryPreserve=restart
MemoryHigh=384M
MemoryMax=512M
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

`Wants=` + `After=` (not `Requires=`) orders the start after Redis and MariaDB. A Redis or MariaDB
restart (for example an apt upgrade) then does not stop ASSP-NG, which handles the outage itself
(6.2).

### 8.3 Signals

| Signal | Action |
|---|---|
| `SIGHUP` | reload (7.5) |
| `SIGTERM` / `SIGINT` | graceful stop: close listeners, give sessions up to 30 s, then `421` to the rest |

### 8.4 Watchdog and health

- The event loop sends `WATCHDOG=1` every 10 s. If the loop blocks, systemd kills and restarts the
  process. `READY=1` is sent after the listeners are up, and `STATUS=` carries a short summary.
- The health endpoint listens on `127.0.0.1:8025` (configurable, localhost only, read-only). It
  answers `GET /health` with HTTP 200 (ok/degraded) or 503 (failing):

```json
{"status": "degraded", "instance": "mx1", "mode": "DEGRADED",
 "redis": "down", "db": "ok", "domains": {"source": "db", "count": 2},
 "backends": {"inbound": "ok", "submission": "ok"},
 "sessions": 12, "rss_mb": 74, "uptime_s": 86400, "debug_rules": 1,
 "certificates": {"mx1": {"days_left": 61}},
 "counters": {"accepted": 1520, "rejected": 8411, "tempfailed": 37}}
```

### 8.5 Logging

- **maillog.log:** `key=value` lines that are easy to parse with grep, fail2ban or logwatch. One
  line per message, plus one per session that ended without a message:

```
2026-11-12T17:30:01+01:00 mx1 s=7f3a9c2e t=1 l=inbound ip=203.0.113.5 ptr=mail.example.org helo=mail.example.org tls=TLSv1.3 auth=- from=<a@example.org> rcpt=<b@example.com> size=48211 score=0 result=accepted mta="250 2.0.0 Ok: queued as 4XyZ" dur=1.84s
```

- **assp-ng.log:** application messages at a configurable, permanent level (`log.level` in
  `assp-ng.toml`).
- **debug.log:** only the output of temporary debug rules (8.11).
- **journald:** warnings and errors only, so `systemctl status` shows problems.
- Writes go through a queue to a writer thread (`QueueHandler`/`QueueListener`), so disk I/O never
  blocks the event loop. `WatchedFileHandler` follows logrotate. A logrotate configuration ships
  with the install.
- **Redaction:** a logging filter removes AUTH payloads from every log level. Tests verify that a
  known test password never appears in any output.

### 8.6 Alerts (subproject 1)

The `assp-ng notify --event <name> --message <text>` CLI (and the same code inside the proxy)
sends an alert by email and optionally by webhook (`alerts.webhook`, HTTP POST JSON using the
standard library). The second channel matters when the mail system itself is broken. The same
event is sent at most once per 30 minutes.

Email goes by SMTP (`smtplib`) to `alerts.smtp_server` (default `127.0.0.1:10125`, the internal
Postfix service) and is addressed to `alerts.email`. ASSP-NG does not use the local `sendmail`
binary. Postfix's `sendmail` relies on a setgid helper (`postdrop`), which `NoNewPrivileges=yes`
in the sandbox would block.

Events raised by the proxy:

- entering and leaving DEGRADED, entering TEMPFAIL;
- a backend unreachable 3 times in a row (per listener);
- reload failed;
- memory soft limit reached;
- certificate expires in less than 14 days (checked daily);
- database unreachable for more than 5 minutes;
- schema version mismatch.

The systemd template unit `assp-ng-notify@.service` calls the same command with event
`service-failed`. The worker's health monitor (subproject 2+) takes over and extends this later.

### 8.7 Memory management

1. **Message buffers:** at most 1 MiB in memory per message and 128 MiB in total. Beyond that,
   spool to disk (4.7).
2. **Soft limit:** when RSS exceeds `memory.soft_limit_mb` (default 360, about 70 % of
   `MemoryMax`), new connections get `421 4.3.0`, running sessions finish normally, and an alert
   is raised. In DEGRADED mode this also triggers TEMPFAIL.
3. **systemd `MemoryHigh`** (384 MB) throttles and reclaims. **`MemoryMax`** (512 MB) is the hard
   last resort: the kernel kills the process and systemd restarts it. Admins adjust these with a
   drop-in.
4. **Idle housekeeping:** after 60 s without sessions, or every 10 minutes under low load, the proxy
   expires cache entries, runs `gc.collect()` and calls glibc `malloc_trim(0)` through `ctypes`, so
   that memory freed in the glibc heap returns to the OS. RSS before and after is logged at debug
   level and RSS is exposed in `/health`. Trimming does not reach CPython's small-object
   allocator: it keeps a 1 MiB arena for as long as any object in it lives, so after a load peak
   RSS settles at a plateau set by the peak concurrency, not at the baseline. Later load reuses
   those arenas, so the plateau must not grow from one load to the next; growth would be a leak.
   (Measured 2026-11-18 with 500 sessions: arenas 37 → 72, live Python objects unchanged at
   about 38 MB, RSS 77 → 113.5 MB, the same after four rounds. `PYTHONMALLOC=malloc` lowered the
   plateau to about 94 MB for about 9 % more CPU and was not adopted.)
5. `MALLOC_ARENA_MAX=2` keeps glibc from creating extra arenas for helper threads.

### 8.8 CLI `assp-ng`

| Command | Purpose |
|---|---|
| `config init \| check \| doc` | create `default.toml`, validate everything, generate reference docs |
| `config set \| unset \| show <key> [sys \| domain:<d> \| user:<a>]` | edit and inspect layered configuration (7.6) |
| `debug on <rule> [--for <duration>] [--headers] \| off <id> \| off --all \| list` | temporary debug rules (8.11) |
| `db upgrade` | run Alembic migrations |
| `domain add <domain> [--subdomains] \| remove <domain> \| list` | manage local domains (audit-logged, publishes `domains-changed`) |
| `pb list \| show <ip> \| remove <ip> [--forget] \| block <ip> --for <duration>` | penalty box (audit-logged) |
| `status` | query `/health` and print a summary |
| `notify --event --message` | send an alert (8.6) |
| `postfix check \| plan \| apply \| rollback` | Postfix integration assistant (8.10) |

The CLI reads `/etc/assp-ng/assp-ng.toml`. Configuration changes need root, because they write to
`/etc/assp-ng`. Read-only commands and `debug` also work for members of the `assp-ng` group.
Commands that act on the running proxy (`debug`, `status`) use the control socket, so they keep
working while Redis or MySQL is down.

### 8.9 Installation (Debian 13)

`packaging/install.sh`:

1. `apt install` the runtime packages: python3, python3-dnspython, python3-redis, python3-pymysql,
   python3-sqlalchemy, python3-alembic, python3-systemd and python3-cryptography.
2. Create the `assp-ng` system user and group, `/etc/assp-ng` with a commented `assp-ng.toml`,
   `default.toml` (via `assp-ng config init`) and empty `domain.d/` and `user.d/`, and
   `/opt/assp-ng` with the code. Also install `python3-tomlkit` for the CLI.
3. Install the systemd units and the logrotate configuration.
4. Install a certbot deploy hook. It copies renewed certificates to `/etc/assp-ng/tls/<name>/`
   with group `assp-ng` read access and runs `systemctl reload assp-ng-proxy`.
5. Run `assp-ng db upgrade` (the DB and user are created by the admin, documented).
6. Run the Postfix integration assistant (8.10).

### 8.10 Postfix integration assistant

`assp-ng postfix check | plan | apply | rollback` moves Postfix behind ASSP-NG and removes
filters that ASSP-NG makes redundant.

**Target Postfix setup.** The exact parameters are validated on the test server before release.

- Postfix no longer listens publicly on 25/587/465.
- Two internal `smtpd` services in `master.cf`:
  - `127.0.0.1:10125`: SASL disabled, `smtpd_authorized_xclient_hosts=127.0.0.1`.
  - `127.0.0.1:10587`: SASL enabled, `smtpd_tls_auth_only=no` (the connection is local; TLS with
    the client is held by ASSP-NG), `smtpd_authorized_xclient_hosts=127.0.0.1`,
    `smtpd_client_restrictions=permit_sasl_authenticated,reject`.
- The default ports 10125/10587 avoid the ports that amavis setups commonly use (10024, 10025,
  10027). The assistant checks that the chosen ports are free.

**Detection** is read-only. It uses `postconf -n`, `postconf -M` and `postconf -P` rather than
parsing files by hand.

| Finding | Detected by | Replaced by ASSP-NG feature |
|---|---|---|
| public `smtpd`/`postscreen` on 25, `submission`, `smtps` | `master.cf` services | listeners (subproject 1) |
| `postscreen` and its DNSBL settings | `master.cf`, `postscreen_*` | connection limits, DNSBL |
| `reject_rbl_client`, `reject_rhsbl_*` | `smtpd_*_restrictions` | DNSBL check |
| postgrey (`check_policy_service` to port 10023 or the postgrey socket) | `smtpd_*_restrictions` | greylisting |
| rspamd milter | `smtpd_milters`, `non_smtpd_milters` | spam checks |
| amavis (`content_filter`, `smtp-amavis`/`amavis` services, reinjection listeners) | `main.cf`, `master.cf` | spam and antivirus checks |
| clamav-milter | milters | ClamAV check |
| DKIM signing done by rspamd or amavis | rspamd/amavis DKIM configuration | DKIM signer (see below) |

**Rules:**

- **Capability-aware.** Every ASSP-NG release declares which features it provides. The assistant
  proposes to disable a filter only when the installed ASSP-NG provides its replacement.
  Otherwise it reports "keep for now". With subproject 1 alone, only the listeners move. postgrey,
  DNSBL in Postfix and rspamd can be disabled once subproject 2 is installed, and amavis and
  clamav-milter once subproject 3 is installed.
- **DKIM signing is never disabled** unless another signer is active and verified. Signing must
  also cover mail that never passes through ASSP-NG (local `sendmail`, for example PHP `mail()`
  on web hosting servers).
- **`plan`** prints every change as a diff, plus the services that would be stopped.
- **`apply`** requires confirmation (or `--yes`) and runs these steps:
  1. Back up `/etc/postfix` to `/var/backups/assp-ng/postfix-<timestamp>/` (moved from
     /var/lib/assp-ng/backup: the service user must not control root-restored files).
  2. Edit with `postconf -e`/`-X`/`-M`. `master.cf` entries are **commented out, never deleted**,
     and marked `# disabled by assp-ng <date>`.
  3. Run `postfix check`.
  4. Restart Postfix, then start ASSP-NG.
  5. Verify a test SMTP dialogue through ASSP-NG to each backend.
  6. **Roll back automatically** if verification fails.

  Stopping and disabling replaced services (postgrey, rspamd, amavis) needs a separate
  confirmation.
- **`rollback`** restores the last backup and restarts Postfix and ASSP-NG.
- **DKIM signer migration** is delivered with the first release that allows disabling rspamd or
  amavis (subproject 2):
  - **Target:** OpenDKIM (Debian package `opendkim`) in `Mode s` (sign only), added to both
    `smtpd_milters` and `non_smtpd_milters`, with `milter_default_action = accept`.
    `InternalHosts` contains only the loopback addresses. Because Postfix receives the real client
    address through XCLIENT, OpenDKIM signs only:
    - SASL-authenticated mail (AUTH is passed through to `127.0.0.1:10587`);
    - locally submitted mail (`non_smtpd`).

    It never signs inbound mail that merely claims a local sender. This behaviour is verified on
    the test server.
  - **Key sources:** the assistant reads the existing configuration and writes OpenDKIM's
    `KeyTable` and `SigningTable`. Keys are copied to `/etc/opendkim/keys/` with mode 0600 for the
    `opendkim` user.

    | Source | When | Notes |
    |---|---|---|
    | `ispconfig` | ISPConfig detected | domains, selectors and keys from ISPConfig; a systemd timer (`assp-ng-dkim-sync.timer`, every 10 min) picks up new or changed domains and reloads OpenDKIM only on change. The exact ISPConfig data location (key files or database) is verified on the test server. |
    | `rspamd` | rspamd `dkim_signing` configured, no ISPConfig | key paths and selectors from the rspamd configuration |
    | `amavis` | `dkim_key(...)` entries in amavis configuration | key paths and selectors from those entries |
    | existing OpenDKIM or other milter signer | already present | left untouched |
    | none | no signer found | warning only. The documentation explains how to create keys with `opendkim-genkey` and publish the DNS records. |

  - The old signer is disabled only after OpenDKIM is running and a test message is verified to
    carry a valid signature.
- **ISPConfig hosts** (`/usr/local/ispconfig` present):
  - ISPConfig can regenerate the Postfix configuration during updates. The assistant warns about
    this and stores its changes through ISPConfig's custom template mechanism, so they survive.
    The exact mechanism is verified against the ISPConfig version on the test server before
    implementation.
  - Health monitoring alerts when a backend becomes unreachable, for example after Postfix
    reverts to public ports.

### 8.11 Debug switch

Temporary, **targeted** debug logging for diagnostics, switched on and off at runtime without a
reload or restart.

```
assp-ng debug on ip:203.0.113.5            # one client network (IPv4 /32, IPv6 /64)
assp-ng debug on from:someone@example.org  # envelope sender
assp-ng debug on rcpt:jano@example.com     # recipient
assp-ng debug on user:jano@example.com     # authenticated mailbox
assp-ng debug on listener:submission       # one listener
assp-ng debug on all --for 5m              # whole instance
assp-ng debug list | off <id> | off --all
```

- **Every rule expires.** The default is 30 minutes. A targeted rule may last at most 24 h and
  `all` at most 1 h. Several rules can be active at once, and `/health` reports their number.
- **Output** goes to `/var/log/assp-ng/debug.log`:
  - the full SMTP dialogue in both directions (client ↔ ASSP-NG and ASSP-NG ↔ MTA);
  - every check decision with details and timings;
  - DNS queries, state-store mode and Redis errors;
  - message headers only with `--headers`.
- **Never logged, even in debug:** AUTH payloads (the redaction filter has no exceptions) and
  message bodies (privacy).
- **Retroactive capture:** each session keeps its last 50 dialogue lines in a small ring buffer.
  When a `from:` or `rcpt:` rule matches later in the session, the buffered lines (connect, TLS,
  EHLO) are written first, so the whole session is visible.
- **Control channel:** the CLI talks to the proxy over the Unix socket `/run/assp-ng/control.sock`
  (mode 0660, `root:assp-ng`), not through Redis, so debugging works during a Redis outage. A
  localhost HTTP endpoint was rejected: any local user could reach it and capture other people's
  mail dialogues.
- **Persistence:** active rules are stored in `/run/assp-ng/debug-rules.json`. They survive a
  service restart (`RuntimeDirectoryPreserve=restart`), which helps when debugging crashes, and
  disappear on reboot.
- **Safety limits:** when `debug.log` reaches `debug.max_size_mb` (default 100), all rules are
  switched off and a warning is logged. `debug.log` contains personal data, so logrotate keeps it
  for only 7 days.

---

## 9. Security summary

- Unprivileged user with only `CAP_NET_BIND_SERVICE`, and the systemd sandbox (8.2).
- Configuration and relay policy only in root-owned files. A future web compromise cannot open a
  relay or disable checks.
- TLS 1.2 minimum, a modern cipher list (Mozilla "intermediate"), no TLS compression, no
  renegotiation. AUTH only over TLS.
- AUTH passwords are never logged or stored. Redaction is tested.
- `XCLIENT`, `XFORWARD` and other MTA-control commands from clients are never forwarded. XCLIENT
  support problems fail closed.
- SMTP smuggling is neutralised by strict end-of-data detection, normalisation and re-stuffing.
- Incoming `X-ASSP-NG-*` header fields are stripped.
- Strict input limits (line length, parameters, message size, timeouts, connection rates).
- Spool files are private and short-lived, and are purged on start.
- The health endpoint binds to localhost only. The control socket is restricted to root and the
  `assp-ng` group by file permissions.
- Debug logging never contains AUTH payloads or message bodies, always expires, and is size-capped.
- The service cannot write its own configuration. Only root, through the CLI or an editor, changes
  `/etc/assp-ng`.
- Dependencies come only from Debian packages, so security updates arrive through apt.

---

## 10. Testing

### 10.1 Tooling (Debian 13 packages)

`python3-pytest` (8.3), `python3-pytest-asyncio`, `python3-hypothesis`, `python3-pytest-cov`,
`python3-mypy`, `python3-flake8`, `python3-aiosmtpd` (test MTA), `redis-server`, `swaks`, and
`postfix` (`smtp-source`/`smtp-sink` for load tests).

### 10.2 Test layers

1. **Unit:**
   - parsers (commands, multi-line replies, addresses with SMTPUTF8/IDN), the EHLO filter, the
     dot-stuffing codec and normalisation;
   - AUTH username extraction and redaction, network keys;
   - the scoring engine (modes × results), penalty-box escalation with a fake clock, rate windows;
   - config validation (unknown keys, ranges, settings at a forbidden level), layered
     resolution (mailbox → domain → default → built-in) and the reported source of each value;
   - policy fingerprints and recipient grouping decisions;
   - comment-preserving `config set`/`unset` (round trip keeps comments), atomic write and `.bak`;
   - debug rule matching and expiry with a fake clock, the ring buffer;
   - `MemoryStore`.

   Parsers and the codec also get **property-based tests** (`hypothesis`): no crash on any input,
   and stuff/unstuff round trips.
2. **Session (golden transcripts):** full SMTP dialogues against a fake backend, with an exact
   expected transcript:
   - relay denied, VRFY `252`, client `XCLIENT` never reaching the backend;
   - state reset after STARTTLS, AUTH before TLS refused, AUTH required on submission;
   - rejection in DATA followed by `RSET` to the backend;
   - recipients with different policies: the second gets `452 4.5.3` and never reaches the
     backend; recipients with the same policy stay together;
   - `552`, `452`, `421` after errors.
3. **Integration:** the real proxy on random ports with an `aiosmtpd` backend that records
   everything it receives (including XCLIENT), a temporary `redis-server` started by the test
   fixture and a test database. Covers:
   - TLS with certificates generated during the test, IPv4 and `::1`;
   - Redis stopped mid-test (DEGRADED, then recovery);
   - backend down (`421`);
   - invalid config on reload (old config kept), including an invalid `user.d/` file;
   - missing `default.toml` at start (refuses to start with the expected error);
   - debug rules through the control socket during a Redis outage, and socket permissions;
   - buffer budget overflow (spool to disk);
   - domain snapshot fallback.

   Database tests run when `ASSPNG_TEST_DB_URL` is set and are skipped with a notice otherwise.
4. **Security:**
   - every published SMTP smuggling variant (`\n.\n`, `\r.\r`, `\r\n.\r`, `\n.\r\n`, …) must reach
     the backend as one message with the content stuffed;
   - over-long lines and commands, slow clients (timeouts), connection floods;
   - the test password must be absent from all log output.
5. **Load and memory** (manual or nightly): `smtp-source` → proxy → `smtp-sink`, 500 concurrent
   sessions. Measures throughput, latency, and RSS at baseline, at peak and after idle
   housekeeping. Results are recorded in `docs/`.
6. **Test server acceptance** (manual checklist in `docs/`): real Postfix with XCLIENT, a Let's
   Encrypt certificate, test mode first, `swaks` scenarios, real clients (Thunderbird, Outlook,
   mobile) on 587/465.

### 10.3 Development rules

- Test first for every feature.
- Type hints everywhere. `mypy --strict` for `smtp/`, `proxy/`, `checks/` and `state/`.
- Coverage ≥ 85 % for the core packages. Full coverage of the relay decision, end-of-data handling
  and AUTH handling.
- CI on GitHub runs in a `debian:trixie` container with apt packages only: flake8, mypy and test
  layers 1–4 on every push, layer 5 nightly.

### 10.4 Definition of done

1. All automated tests pass in CI.
2. On the test server, mail for 1–2 domains flows in production mode for **14 days** with no lost
   mail and no restart caused by a crash.
3. Memory and throughput are measured and documented.
4. Installation following the documentation works on a clean Debian 13.

---

## 11. Hooks for later subprojects

Decisions already taken for later subprojects are recorded in
[2026-11-14-later-subprojects-decisions.md](2026-11-14-later-subprojects-decisions.md).

The core must not preclude:

- v1 checks plugging into the HELO/MAIL/RCPT/HEADER/BODY phases (subproject 2);
- concurrent execution of independent DNS-based checks within a phase (`asyncio.gather`);
- reply tracking (store outgoing Message-IDs on accepted authenticated messages);
- the AI phishing check as a BODY-phase check with a strict timeout and a "tag only" mode;
- **message transformations** between the checks and delivery. Because the whole message is
  buffered (4.7), a transformer chain can rewrite it before it is sent to the MTA. The first
  transformer will decode TNEF (`winmail.dat`) into regular MIME attachments (subproject 3):
  - It will be a pure-Python parser following Microsoft's open specifications [MS-OXTNEF] and
    [MS-OXRTFCP]. Debian has no Python TNEF library, and the available C decoders (`tnef`,
    `libytnef`) parse untrusted input in memory-unsafe code.
  - It will run with strict limits (attachment count, decoded size, nesting) and be fuzz-tested.
  - It never modifies signed or encrypted messages (`multipart/signed`, `application/pkcs7-mime`,
    PGP).
  - Rewriting an inbound message invalidates the sender's DKIM signature. With no verifier
    behind ASSP-NG (1.4), this matters only when a mailbox **forwards** mail to an external
    provider, which may then fail DMARC for the forwarded copy. ASSP-NG verifies DKIM/DMARC
    before any rewrite. Whether DKIM-signed inbound messages are converted or skipped is decided
    in the subproject 3 design. Outbound conversion has no such problem, because signing happens
    after ASSP-NG.
  - The BODY-phase attachment and antivirus checks use the same decoder, so they also inspect the
    files inside `winmail.dat` and nothing can hide in it;
- per-user outbound anomaly detection, using AUTH events and `user_rate` counters;
- the web interface reusing the TLS certificate store and the database;
- `ISPConfigDomainSource` behind the `DomainSource` protocol;
- PostgreSQL through SQLAlchemy Core.

---

## 12. Decision log

| Decision | Reason |
|---|---|
| Same behaviour as v1, new configuration and data model | 791 options are unmanageable to configure and to build a UI for |
| Buffer the whole message before delivery | full-content checks, headers can be added after checks, simple and robust logic |
| Clients submit through ASSP-NG (587/465) | as in v1; gives username, client IP and AUTH failures early |
| ASSP-NG terminates TLS | needed to see AUTH and to filter the SMTP dialogue |
| XCLIENT to Postfix, failing closed | the MTA sees the real client IP, which avoids blind trust in the proxy |
| Configuration in files, data in the database | config changes rarely, works without the DB, and a web compromise cannot change policy |
| Trusted networks in files | they decide relaying, so they are security policy |
| MySQL out of the hot path | a MySQL outage does not stop mail |
| Redis outage: degraded in-memory mode, then tempfail | keeps protection up, never passes unchecked mail |
| Penalty-box escalation 24 h → 7 d → 30 d, history 90 d | repeat offenders stay out longer, and the admin can override |
| No penalty-box gate on submission ports | roaming users behind shared IPs must still be able to send |
| systemd as watchdog, not a custom process | restarts, hang detection and failure hooks without a new component |
| `Wants=`/`After=` instead of `Requires=` | a Redis or MariaDB restart must not stop mail |
| Debian packages only | security updates via apt, no breakage from upstream API removals |
| ASSP-NG is the only spam filter; the Postfix assistant disables redundant filters | one component, low resources; filters are disabled only when ASSP-NG replaces them |
| DKIM signing by OpenDKIM (sign-only milter), keys from ISPConfig/rspamd/amavis | also signs local `sendmail`/PHP `mail()` traffic, which never passes through ASSP-NG |
| ISPConfig optional | ASSP-NG must work on any Debian 13 Postfix server |
| Layered configuration: system, default, domain, mailbox | per-domain and per-mailbox policy without hundreds of global options |
| Recipient grouping with `452 4.5.3` | one SMTP transaction has one final reply, so its recipients must share one policy |
| Refuse to start without `default.toml` | never silently fall back to a different policy; the service must not write to `/etc` |
| CLI edits configuration files with `tomlkit` | convenient changes without losing the admin's comments; hand editing stays equal |
| Targeted, self-expiring debug rules over a Unix control socket | diagnostics without flooding logs, works during Redis outages, access limited by file permissions |
