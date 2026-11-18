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
   2000) through `LOAD_SESSIONS` concurrent sessions (default 500) to a local domain, in
   `LOAD_ROUNDS` rounds (default 2). After each round the proxy idles for `LOAD_IDLE_WAIT`
   seconds (default 90).

The proxy runs with `MALLOC_ARENA_MAX=2`, as under the systemd unit.

The script measures:

- **Messages per second**: all messages divided by the wall-clock time of the `smtp-source`
  runs.
- **RSS of the ASSP-NG process** (`VmRSS`): at **baseline** (started, idle), at **peak** (the
  highest value, sampled every 0.5 s while `smtp-source` runs), and after the idle wait of the
  **first** and of the **last round**, once idle housekeeping has had time to trim memory
  (`memory.idle_trim_after_s`, spec 8.7).

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
idle wait of the last round must not be higher than after the first round, beyond a few MiB of
noise. Throughput and latency are only recorded: the aim is a documented figure for the 14-day
production trial (spec 10.4).

The RSS after the idle wait does not fall back to the baseline, and is not expected to (spec
8.7, item 4). `malloc_trim` returns free memory of the glibc heap, but CPython's small-object
allocator keeps each 1 MiB arena for as long as any object in it lives. The first load peak
therefore lifts RSS once, to a plateau set by the peak concurrency; later load reuses those
arenas. A plateau that keeps rising from round to round would be a leak.

Measured on a development machine on 2026-11-18 (4 rounds, 500 sessions; for the explanation
only, not as a result): baseline 77 MiB, peak about 120 MiB, after the idle wait 112.9, 113.5,
113.5 and 113.5 MiB. Python's arena statistics showed 37 arenas before the load and 72 after it,
with the live Python objects unchanged at about 38 MB. `MALLOC_ARENA_MAX=2` made no
difference. `PYTHONMALLOC=malloc` lowered the plateau to about 94 MiB but cost about 9 % more
CPU, so it was not adopted. Once the proxy stopped importing Alembic (about 10 MiB), the script
(with stand-ins for `smtp-source` and `smtp-sink`) measured, with its defaults and 3 rounds:
baseline 68.4 MiB, peak 109.5 MiB, and 102.7 and 102.9 MiB after the first and the last round.

Compare rounds only when they are long enough to reach the full concurrency. With 3000 messages
per round (and a 65 s idle wait), the RSS after the second round was 7 MiB above the first.

## Results

| Run | Messages per round | Rounds | Sessions | Message size (bytes) | Messages/s | RSS baseline (MiB) | RSS peak (MiB) | RSS 90 s after round 1 (MiB) | RSS 90 s after the last round (MiB) |
|---|---|---|---|---|---|---|---|---|---|
| Test server | pending: run on the test server | | | | | | | | |
| Nightly CI, 2026-11-17 (manual run, before rounds existed) | 10000 | 1 | 500 | 2000 | 199 | 77.1 | 103.1 | 99.3 | – |
| Nightly CI, 2026-11-18 (manual run) | 10000 | 2 | 500 | 2000 | 827 | 68.1 | 108.8 | 102.7 | 102.7 |
| Nightly CI, 2026-11-18 (scheduled run) | 10000 | 2 | 500 | 2000 | 779 | 68.0 | 107.7 | 101.0 | 101.8 |
| Nightly CI, 2026-11-18 (manual run, after the pre-deployment fixes) | 10000 | 2 | 500 | 2000 | 552 | 68.2 | 104.0 | 100.1 | 100.1 |

The 2026-11-17 run predates two changes: the listeners still used a listen backlog of 100,
which `smtp-source`'s 500 sessions overflowed, and the proxy still imported Alembic (about
10 MiB). The backlog fix most likely explains the higher rate; CI runners vary, so the rate
is only indicative.

The last run is slower because of one of the pre-deployment fixes: `redis.op_timeout_ms` went
from 200 to 1000 ms. At this load the proxy keeps one CPU core busy, and its event loop lags by
more than 200 ms. With the old timeout, Redis operations therefore failed, and the proxy switched
to its local memory store several times per run. That store is faster but not shared between
instances. Now the state stays in Redis. A comparison on a development machine, with the
current code and only the timeout changed (two runs each, 2 rounds of 10000 messages):

| `redis.op_timeout_ms` | Messages/s | Proxy CPU per 10000 messages | Failed Redis operations | Switches to DEGRADED |
|---|---|---|---|---|
| 200 | about 800 | 12.6 s | about 1400 per run | 3 per run |
| 1000 | about 595 | 17 s | 0 | none |

Redis-backed state thus costs about 0.45 ms of CPU per message at saturation. Fewer Redis round
trips per connection would win part of it back (backlog: State, penalty box and limits).
