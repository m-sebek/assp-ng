# Installation (Debian 13)

This guide installs ASSP-NG in front of an existing Postfix on Debian 13 (trixie). ASSP-NG uses
only Debian packages: no pip, no virtualenv, no Docker. It is the only spam filter on the host
(see [DKIM signing](#dkim-signing) for what that means for outbound mail).

## Release-blocking items

The design leaves three details that **must be confirmed on the test server before the first
release**, because they depend on real Postfix and ISPConfig installations. Until then, treat the
Postfix assistant output as a proposal that you read and check by hand.

- **The `postfix@-` unit.** Debian starts Postfix through `postfix.service`, which wraps the
  per-instance unit `postfix@-.service`. Confirm which unit `assp-ng postfix apply` must restart
  and reload on Debian 13, and that the restart ordering (Postfix first, then ASSP-NG) holds.
- **Real `postconf -M` and `postconf -P` captures.** The assistant reads `master.cf` services
  with `postconf -M` and per-service parameters with `postconf -P`. Capture the real output of
  both on the test server (plain Debian and an ISPConfig host) and confirm that the parser and
  the rendered plan match it.
- **The ISPConfig template mechanism.** ISPConfig regenerates the Postfix configuration during
  updates, so the assistant's changes must be stored through ISPConfig's custom template
  mechanism. Confirm the exact mechanism and file locations for the installed ISPConfig version.

## 1. Install the program

Run the installer as root from a checkout of the repository:

```
sudo ./packaging/install.sh
```

It is safe to run again. It:

1. installs the runtime packages (`python3-dnspython`, `python3-redis`, `python3-pymysql`,
   `python3-sqlalchemy`, `python3-alembic`, `python3-systemd`, `python3-cryptography`,
   `python3-tomlkit`);
2. creates the `assp-ng` system user and group;
3. creates `/etc/assp-ng` (`root:assp-ng`, mode 0750) with `domain.d/`, `user.d/` and `tls/`;
4. copies the code to `/opt/assp-ng` and installs the `/usr/local/bin/assp-ng` command;
5. installs the systemd units, the logrotate configuration and the certbot deploy hook;
6. creates `/etc/assp-ng/assp-ng.toml` from the example and `default.toml` with
   `assp-ng config init`, but only if they do not exist yet. Existing files are never changed.
   Files are `root:assp-ng`, mode 0640.

It does not touch Postfix, it does not create database users, and it does not start the service.

## 2. Database

Create the database and its user in MariaDB. Replace `PASSWORD` with a strong password:

```
CREATE DATABASE asspng CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'asspng'@'localhost' IDENTIFIED BY 'PASSWORD';
GRANT ALL PRIVILEGES ON asspng.* TO 'asspng'@'localhost';
FLUSH PRIVILEGES;
```

Put the same password into `database.url` in `/etc/assp-ng/assp-ng.toml`, then validate the
configuration and create the tables:

```
assp-ng config check
assp-ng db upgrade
```

`assp-ng config check` validates every file in `/etc/assp-ng`. `assp-ng config doc` writes the
reference of all settings.

A database on another host must be reached over TLS with a password: the configuration is
refused otherwise. Give the TLS options as `ssl_*` query parameters of the URL, for example
`mysql+pymysql://asspng:PASSWORD@db.example.com/asspng?ssl_ca=/etc/ssl/certs/ca-certificates.crt`.
A loopback host (`localhost`, `127.0.0.1`, `::1`) or a Unix socket (`?unix_socket=...`) needs
no TLS.

## 3. Redis persistence

ASSP-NG keeps rate counters and penalty-box scores in Redis. Redis serves requests while it
persists data: RDB snapshots are written by a forked child process, and the fork pause is
negligible at ASSP-NG's data size (megabytes). Recommended setup:

- Keep Debian's default RDB snapshots (the `save` lines in `/etc/redis/redis.conf`).
- Optionally enable AOF with background fsync, in `/etc/redis/redis.conf`:

  ```
  appendonly yes
  appendfsync everysec
  ```

- Set `vm.overcommit_memory = 1` so that the fork cannot fail on a busy host. Create
  `/etc/sysctl.d/90-redis.conf` containing `vm.overcommit_memory = 1`, then run
  `sysctl --system` and `systemctl restart redis-server`.

If Redis is down, ASSP-NG keeps working in a degraded mode with in-memory state.

A Redis on another host must use TLS and a password, so `redis.url` must then look like
`rediss://:PASSWORD@redis.example.com:6380/0`; the configuration is refused otherwise. A
loopback host or a Unix socket (`unix:///run/redis/redis-server.sock?db=0`) needs neither.

## 4. TLS certificates

ASSP-NG reads certificates from `/etc/assp-ng/tls/<name>/{fullchain,privkey}.pem`, as listed in
the `[[tls.certificate]]` entries of `assp-ng.toml`. The installer puts a certbot deploy hook in
`/etc/letsencrypt/renewal-hooks/deploy/assp-ng`. After every renewal it copies the lineage
`/etc/letsencrypt/live/<name>/` to `/etc/assp-ng/tls/<name>/` (`root:assp-ng`, 0640, replaced
atomically) and reloads the service if it is running.

Obtain the certificate with certbot as you normally do, then copy it once by hand:

```
certbot certonly --standalone -d mx1.example.com
RENEWED_LINEAGE=/etc/letsencrypt/live/mx1.example.com /etc/letsencrypt/renewal-hooks/deploy/assp-ng
```

The lineage name must contain only letters, digits, `.`, `_` and `-`, and must not start with a
dot; the hook refuses anything else. Make sure `hostname` and the `[[tls.certificate]]` entry in
`/etc/assp-ng/assp-ng.toml` match.

## 5. Configuration

`/etc/assp-ng/assp-ng.toml` holds the system settings: instance name, database, Redis, listeners,
certificates, penalty box and alerts. The example created by the installer follows the design.
Policy lives in `default.toml`, `domain.d/<domain>.toml` and `user.d/<mailbox>.toml`.

Start in test mode, so that rejections are only logged:

```
assp-ng config set testmode true
assp-ng config show testmode
```

Register your local domains:

```
assp-ng domain add example.com
assp-ng domain list
```

Run `assp-ng config set testmode false` once the logs show no false positives.

### Trusted and exempt networks

Two optional files in `/etc/assp-ng` are security policy, so only root may change them:

- `trusted-networks.txt`: clients in these networks may **relay without AUTH**. They are also
  spared the penalty box and never collect IP score.
- `exempt-networks.txt`: clients in these networks skip the per-network connection limits
  (concurrent connections and connections per minute) and never collect IP score. This does
  **not** allow relaying.

Both hold one network per line in CIDR notation, IPv4 or IPv6, for example `192.0.2.0/24` or
`2001:db8:1::/48`. A bare address is a single host. Host bits must be zero (`192.0.2.0/24`, not
`192.0.2.1/24`). `#` starts a comment and blank lines are ignored. An invalid line makes the
whole configuration invalid; `assp-ng config check` names the file and the line. After a
change, check and reload:

```
assp-ng config check
systemctl reload assp-ng-proxy
```

New sessions use the new lists; sessions in progress keep the lists they started with.

**Postfix `mynetworks`.** ASSP-NG passes the real client address to Postfix with XCLIENT, so
Postfix applies its own relay rules (`permit_mynetworks`) to that address. A trusted network
that should relay without AUTH must therefore also be in Postfix's `mynetworks`, or Postfix
refuses the relay that ASSP-NG allowed. `assp-ng postfix check` prints a note listing the
trusted networks that `mynetworks` does not cover; it changes nothing. To add one:

```
postconf mynetworks
postconf -e "mynetworks = 127.0.0.0/8 [::1]/128 192.0.2.0/24"
systemctl reload postfix
```

## 6. Postfix

The assistant moves Postfix behind ASSP-NG: Postfix stops listening on 25, 587 and 465, and two
internal `smtpd` services accept mail from ASSP-NG on `127.0.0.1:10125` (inbound) and
`127.0.0.1:10587` (submission, with SASL). Review before you change anything. The first two
commands are read-only:

```
assp-ng postfix check
assp-ng postfix plan
```

`check` reports what ASSP-NG can take over, `plan` shows the `master.cf` changes as a diff. When
you agree, and the release-blocking items above are confirmed:

```
assp-ng postfix apply
```

`apply` backs up `/etc/postfix`, comments out (never deletes) the replaced `master.cf` entries,
runs `postfix check`, restarts Postfix, starts ASSP-NG and verifies a test dialogue to each
backend. It rolls back automatically if the verification fails, and you can roll back by hand:

```
assp-ng postfix rollback
```

The backups are kept in `/var/backups/assp-ng/postfix-<timestamp>/` (root only, mode 0700).
Root restores files from there, so `apply` and `rollback` refuse a backup path in which any
directory from `/` down is a symlink, is not owned by root, or is writable by group or others.

On an ISPConfig host, ISPConfig can regenerate the Postfix configuration during updates; see the
release-blocking item about its template mechanism.

## 7. Start and verify

```
systemctl enable assp-ng-proxy
systemctl status assp-ng-proxy
assp-ng status
```

`assp-ng status` queries the health endpoint on `127.0.0.1:8025`. Logs are in
`/var/log/assp-ng/`: `maillog.log` (one line per message), `assp-ng.log` (application log) and
`debug.log` (output of temporary debug rules only). logrotate keeps 30 days of the first two and
7 days of `debug.log`, which contains personal data. To trace one client temporarily:

```
assp-ng debug on ip:203.0.113.5 --for 15m
assp-ng debug list
assp-ng debug off --all
```

Each `debug.log` line carries the time, the session id and a direction: the SMTP dialogue
(`C>P` client to ASSP-NG, `P>C`, `P>M` ASSP-NG to the MTA, `M>P`), `SES` for the session's
`connect ip=… ptr=… listener=…` and `TLS <version>` lines, `CHK` for each check decision (phase,
check, outcome, scores and duration in ms), `DNS` for the PTR lookup and `STATE` for the state
mode at connect and on each change. AUTH payloads and message bodies are never written.

Warnings and errors of the libraries ASSP-NG uses (Redis, SQLAlchemy, asyncio) also go to
`assp-ng.log`, with the same redaction. If the disk stalls, at most 10 000 log records and
10 000 debug lines wait in memory. Further ones are dropped, and once the writer catches up a
line says how many: `… log records dropped` in `assp-ng.log`, or a `debug.log` line with
direction `!`.

The control socket `/run/assp-ng/control.sock` and the directories under `/var/lib/assp-ng` and
`/var/log/assp-ng` are not reachable by other users (mode 0750). Members of the `assp-ng` group
may use `assp-ng debug` and `assp-ng status`.

If a service failure should alert you, set `alerts.email` (and optionally `alerts.webhook`).
You can test the channel with:

```
assp-ng notify --event test --message "alert test" --force
```

`assp-ng notify` reads only `instance`, `hostname` and the `alerts.*` settings from
`assp-ng.toml`, and ignores what it cannot use there, so a broken configuration never stops a
failure alert. Each event is sent at most once per `alerts.min_interval` (default 30 minutes),
also across runs: the time of the last attempt is kept in `/run/assp-ng-notify/` (root only;
the `assp-ng-notify@.service` unit, or else the first run, creates it). Within the interval the command prints
`suppressed (rate limit)` and exits 0; `--force` sends anyway. `assp-ng status` and
`assp-ng debug` likewise need only `paths.run` and keep working while another configuration
file is broken.

## DKIM signing

ASSP-NG is the only spam filter on the host, so it is responsible for SPF, DKIM and DMARC
**evaluation** of inbound mail. DKIM **signing** of outbound mail is a different job and must keep
working. If rspamd signs your mail today (the usual ISPConfig setup), the planned replacement is
OpenDKIM in sign-only mode as a Postfix milter, which also signs mail that never passes through
ASSP-NG (local `sendmail`, PHP `mail()`). The Postfix assistant migrates it with the existing
keys in a later release. Until then, **do not disable your current DKIM signer**. Hosts without
ISPConfig are fully supported.
