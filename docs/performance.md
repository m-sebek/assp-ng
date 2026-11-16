# Performance and memory

This page is the template for the load and memory results required by the design spec (10.2,
layer 5, and 10.4 item 3). The numbers are measured on the test server and by the nightly CI
job, never on a development machine.

## Method

`tests/load/run_load.sh` runs three programs on one host, all on random loopback ports:

1. `smtp-sink` (Postfix) as the backend mail server.
2. ASSP-NG with a temporary configuration (no connection limits in the way, the local domain
   `example.com` in a temporary SQLite database, its own `redis-server`).
3. `smtp-source` sending `LOAD_MESSAGES` messages (default 10000) of `LOAD_SIZE` bytes (default
   2000) through `LOAD_SESSIONS` concurrent sessions (default 500) to a local domain.

The script measures:

- **Messages per second**: the message count divided by the wall-clock time of `smtp-source`.
- **RSS of the ASSP-NG process** (`VmRSS`) at three points: at **baseline** (started, idle),
  at **peak** (the highest value, sampled every 0.5 s while `smtp-source` runs) and
  `LOAD_IDLE_WAIT` seconds (default 90) **after the end**, once idle housekeeping has had
  time to trim memory (`memory.idle_trim_after_s`, spec 8.7).

Run it as `tests/load/run_load.sh [results.md]`. It needs `postfix` (for `smtp-source` and
`smtp-sink`) and `redis-server`; without them it prints `SKIP: smtp-source/smtp-sink not
installed` and exits 0. It writes the results as a Markdown table to stdout or to the file
given. Do not install Postfix on a development machine just for this: run it on the test
server or let the nightly CI job do it.

## Targets

The spec sets no throughput target. It sets these memory figures (8.2, 8.7):

| Figure | Value |
|---|---|
| Concurrent sessions in the test | 500 |
| `memory.soft_limit_mb` (new connections get `421 4.3.0` above it) | 360 MB |
| systemd `MemoryHigh` | 384 MB |
| systemd `MemoryMax` | 512 MB |

The peak RSS with 500 concurrent sessions must stay below the soft limit, and the RSS after the
idle wait must fall back close to the baseline. Throughput and latency are only recorded: the
aim is a documented figure for the 14-day production trial (spec 10.4).

## Results

| Run | Messages | Sessions | Message size (bytes) | Messages/s | RSS baseline (MiB) | RSS peak (MiB) | RSS 90 s after the end (MiB) |
|---|---|---|---|---|---|---|---|
| Test server | pending: run on the test server / nightly CI | | | | | | |
| Nightly CI | pending: run on the test server / nightly CI | | | | | | |
