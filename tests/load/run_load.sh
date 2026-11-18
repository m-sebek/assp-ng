#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Load and memory test (spec 10.2, layer 5): smtp-source -> ASSP-NG -> smtp-sink.
#
# Needs Postfix's smtp-source and smtp-sink (package "postfix"), redis-server and the
# ASSP-NG dependencies. Without smtp-source/smtp-sink it prints SKIP and exits 0.
#
# Usage: tests/load/run_load.sh [results.md]
#
# Sends the messages in LOAD_ROUNDS rounds, each followed by an idle wait, and writes a
# Markdown table (messages per second and the proxy's RSS at baseline, at peak and after the
# idle wait of the first and of the last round) to the file given, or to stdout. Settings
# through the environment:
#   LOAD_MESSAGES   messages to send per round (default 10000)
#   LOAD_SESSIONS   concurrent sessions        (default 500)
#   LOAD_SIZE       message size in bytes      (default 2000)
#   LOAD_ROUNDS     rounds                     (default 2)
#   LOAD_IDLE_WAIT  seconds idle after each round before its RSS reading (default 90)
set -euo pipefail

# Postfix installs smtp-source and smtp-sink in /usr/sbin, which a non-root PATH lacks.
PATH="/usr/sbin:/sbin:$PATH"
export PATH

if ! command -v smtp-source >/dev/null 2>&1 || ! command -v smtp-sink >/dev/null 2>&1; then
    echo "SKIP: smtp-source/smtp-sink not installed"
    exit 0
fi
if ! command -v redis-server >/dev/null 2>&1; then
    echo "SKIP: redis-server not installed"
    exit 0
fi

messages=${LOAD_MESSAGES:-10000}
sessions=${LOAD_SESSIONS:-500}
size=${LOAD_SIZE:-2000}
rounds=${LOAD_ROUNDS:-2}
idle_wait=${LOAD_IDLE_WAIT:-90}
results=${1:-}

if ! [[ $rounds =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: LOAD_ROUNDS must be a positive integer, not '$rounds'" >&2
    exit 2
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/assp-ng-load.XXXXXX")
pids=()

cleanup() {
    local pid
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$work"
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# Resident set size of a process in MiB.
rss_mb() {
    awk '/^VmRSS:/ { printf "%.1f", $2 / 1024 }' "/proc/$1/status"
}

mkdir -p "$work"/{etc,spool,cache,run,logs,redis}
redis_port=$(free_port)
sink_port=$(free_port)
proxy_port=$(free_port)
health_port=$(free_port)

redis-server --port "$redis_port" --bind 127.0.0.1 --dir "$work/redis" --save "" \
    --appendonly no >"$work/redis.out" 2>&1 &
pids+=($!)

# smtp-sink refuses to run as root without -u (CI containers run as root). -m raises its
# limit of simultaneous connections (default 256) above the number of test sessions.
sink_opts=(-c -m "$((sessions + 50))")
if [ "$(id -u)" -eq 0 ]; then
    sink_opts+=(-u nobody)
fi
smtp-sink "${sink_opts[@]}" 127.0.0.1:"$sink_port" 1024 >"$work/sink.out" 2>&1 &
sink=$!
pids+=("$sink")

# Wait until a process accepts connections on a port; fail with its output if it dies or
# never comes up.
wait_for_port() {
    local name=$1 pid=$2 port=$3 out=$4
    for _ in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "ERROR: $name did not start:" >&2
            cat "$out" >&2
            exit 1
        fi
        sleep 0.2
    done
    echo "ERROR: $name does not accept connections on port $port after 20 s:" >&2
    cat "$out" >&2
    exit 1
}

wait_for_port smtp-sink "$sink" "$sink_port" "$work/sink.out"

# A temporary configuration: no limits in the way, the local domain in a SQLite database.
cat >"$work/etc/assp-ng.toml" <<TOML
instance = "load"
hostname = "proxy.load.test"
"database.url" = "sqlite:///$work/domains.sqlite"
"redis.url" = "redis://127.0.0.1:$redis_port/0"
"redis.key_prefix" = "load:"
"paths.spool" = "$work/spool"
"paths.cache" = "$work/cache"
"paths.run" = "$work/run"
"paths.log_dir" = "$work/logs"
"health.listen" = "127.0.0.1:$health_port"
"limits.net.concurrent" = $((sessions * 2))
"limits.net.connections_per_minute" = 1000000
"limits.instance.concurrent" = $((sessions * 2))
"limits.session.messages" = $messages
"checks.conn_limits.mode" = "off"
"timeouts.ptr" = 1

[[listener]]
name = "inbound"
kind = "smtp"
port = $proxy_port
ipv6 = false
bind4 = "127.0.0.1"
backend = "127.0.0.1:$sink_port"
xclient = false
TOML
: >"$work/etc/default.toml"

(cd "$repo" && python3 - "$work/domains.sqlite" <<'PY'
import sys
from asspng.db.migrate import upgrade
from asspng.db.repository import DomainRepository

url = f"sqlite:///{sys.argv[1]}"
upgrade(url)
repo = DomainRepository(url, "load")
repo.add("example.com", include_subdomains=False, note=None, actor="load")
repo.close()
PY
)

# The same allocator setting as the systemd unit (spec 8.7).
(cd "$repo" && MALLOC_ARENA_MAX=2 exec python3 -m asspng.proxy \
    --config "$work/etc/assp-ng.toml") >"$work/proxy.out" 2>&1 &
proxy=$!
pids+=("$proxy")

wait_for_port "the proxy" "$proxy" "$proxy_port" "$work/proxy.out"

sleep 2
baseline=$(rss_mb "$proxy")

peak=$baseline
source_seconds=0
after=()

# One round: smtp-source sends the messages while the proxy's RSS is sampled for the peak,
# then the proxy idles for the idle wait, so housekeeping can trim (memory.idle_trim_after_s),
# and its RSS is read.
run_round() {
    local round=$1 out="$work/source.$1.out" source start end current status=0
    start=$(date +%s.%N)
    smtp-source -c -l "$size" -m "$messages" -s "$sessions" -f sender@remote.test \
        -t user@example.com 127.0.0.1:"$proxy_port" >"$out" 2>&1 &
    source=$!
    while kill -0 "$source" 2>/dev/null; do
        current=$(rss_mb "$proxy")
        peak=$(awk -v a="$peak" -v b="$current" 'BEGIN { print (b > a) ? b : a }')
        sleep 0.5
    done
    wait "$source" || status=$?
    end=$(date +%s.%N)
    if [ "$status" -ne 0 ]; then
        echo "ERROR: smtp-source failed in round $round:" >&2
        cat "$out" >&2
        echo "--- smtp-sink output:" >&2
        cat "$work/sink.out" >&2
        echo "--- end of the proxy log:" >&2
        tail -n 30 "$work/logs/assp-ng.log" >&2 2>/dev/null || true
        exit 1
    fi
    source_seconds=$(awk -v t="$source_seconds" -v a="$start" -v b="$end" \
        'BEGIN { printf "%.3f", t + b - a }')
    sleep "$idle_wait"
    after+=("$(rss_mb "$proxy")")
}

for round in $(seq 1 "$rounds"); do
    run_round "$round"
done

# smtp-source does not fail on every lost message: check that the proxy handed each one to
# smtp-sink (one maillog line with result=accepted per message).
expected=$((messages * rounds))
delivered=$(grep -c ' result=accepted ' "$work/logs/maillog.log" 2>/dev/null || true)
if [ "${delivered:-0}" -ne "$expected" ]; then
    echo "ERROR: the proxy passed ${delivered:-0} of $expected messages to smtp-sink" >&2
    echo "--- end of the proxy log:" >&2
    tail -n 30 "$work/logs/assp-ng.log" >&2 2>/dev/null || true
    exit 1
fi

rate=$(awk -v n="$expected" -v t="$source_seconds" 'BEGIN { printf "%.0f", n / t }')

table=$(cat <<TABLE
| Messages per round | Rounds | Sessions | Message size (bytes) | Messages/s | RSS baseline (MiB) | RSS peak (MiB) | RSS ${idle_wait} s after round 1 (MiB) | RSS ${idle_wait} s after round $rounds (MiB) |
|---|---|---|---|---|---|---|---|---|
| $messages | $rounds | $sessions | $size | $rate | $baseline | $peak | ${after[0]} | ${after[-1]} |
TABLE
)

if [ -n "$results" ]; then
    printf '%s\n' "$table" >"$results"
else
    printf '%s\n' "$table"
fi
