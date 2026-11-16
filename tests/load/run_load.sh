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
# Writes a Markdown table (messages per second and the proxy's RSS at baseline, at peak and
# after the idle wait) to the file given, or to stdout. Settings through the environment:
#   LOAD_MESSAGES   messages to send          (default 10000)
#   LOAD_SESSIONS   concurrent sessions       (default 500)
#   LOAD_SIZE       message size in bytes     (default 2000)
#   LOAD_IDLE_WAIT  seconds idle before the last RSS reading (default 90)
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
idle_wait=${LOAD_IDLE_WAIT:-90}
results=${1:-}

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

smtp-sink -c 127.0.0.1:"$sink_port" 1024 >"$work/sink.out" 2>&1 &
pids+=($!)

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

(cd "$repo" && exec python3 -m asspng.proxy --config "$work/etc/assp-ng.toml") \
    >"$work/proxy.out" 2>&1 &
proxy=$!
pids+=("$proxy")

for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$proxy_port") 2>/dev/null; then
        break
    fi
    if ! kill -0 "$proxy" 2>/dev/null; then
        echo "ERROR: the proxy did not start:" >&2
        cat "$work/proxy.out" >&2
        exit 1
    fi
    sleep 0.2
done

sleep 2
baseline=$(rss_mb "$proxy")

source_start=$(date +%s.%N)
smtp-source -c -l "$size" -m "$messages" -s "$sessions" -f sender@remote.test \
    -t user@example.com 127.0.0.1:"$proxy_port" >"$work/source.out" 2>&1 &
source=$!

peak=$baseline
while kill -0 "$source" 2>/dev/null; do
    current=$(rss_mb "$proxy")
    peak=$(awk -v a="$peak" -v b="$current" 'BEGIN { print (b > a) ? b : a }')
    sleep 0.5
done
source_status=0
wait "$source" || source_status=$?
source_end=$(date +%s.%N)

if [ "$source_status" -ne 0 ]; then
    echo "ERROR: smtp-source failed:" >&2
    cat "$work/source.out" >&2
    exit 1
fi

rate=$(awk -v n="$messages" -v a="$source_start" -v b="$source_end" \
    'BEGIN { printf "%.0f", n / (b - a) }')

sleep "$idle_wait"
after=$(rss_mb "$proxy")

table=$(cat <<TABLE
| Messages | Sessions | Message size (bytes) | Messages/s | RSS baseline (MiB) | RSS peak (MiB) | RSS ${idle_wait} s after the end (MiB) |
|---|---|---|---|---|---|---|
| $messages | $sessions | $size | $rate | $baseline | $peak | $after |
TABLE
)

if [ -n "$results" ]; then
    printf '%s\n' "$table" >"$results"
else
    printf '%s\n' "$table"
fi
