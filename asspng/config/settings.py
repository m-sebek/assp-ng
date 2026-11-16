# SPDX-License-Identifier: GPL-3.0-or-later
"""Every ASSP-NG setting: type, default, level, range and description.

The descriptions are the source of the user documentation and of default.toml.
"""
from __future__ import annotations

from asspng.config.registry import Level, Registry, Setting

REGISTRY = Registry()

S, R, U = Level.SYSTEM, Level.RECIPIENT, Level.SENDER
MODES = ("off", "block", "monitor", "score", "test")


def _add(key: str, kind: str, default: object, desc: str, level: Level = S, *,
         choices: tuple[str, ...] | None = None, minimum: float | None = None,
         maximum: float | None = None, non_empty: bool = False) -> None:
    REGISTRY.register(Setting(
        key, kind, default, level, desc, choices=choices, minimum=minimum, maximum=maximum,
        fingerprint=level is Level.RECIPIENT, non_empty=non_empty))


def _count(key: str, default: int, desc: str, level: Level = S, minimum: int = 0) -> None:
    _add(key, "int", default, desc, level, minimum=minimum)


def _check(name: str, ip_score: int, desc: str, level: Level = S) -> None:
    p = f"checks.{name}"
    _add(f"{p}.mode", "str", "block",
         f"Mode of the {desc} check: off disables it, block rejects when it fails, "
         "monitor only logs, score adds msg_score to the message score, test logs what "
         "block would do. ip_score applies in every mode except off.",
         level, choices=MODES)
    _add(f"{p}.ip_score", "int", ip_score,
         f"Penalty-box score added to the client IP when the {desc} check fails, in every "
         "mode except off; 0 adds nothing.",
         level, minimum=0)
    _add(f"{p}.msg_score", "int", 0,
         f"Score added to the message when the {desc} check fails; used only in score "
         "mode, where 0 adds nothing.",
         level, minimum=0)
    _add(f"{p}.timeout_ms", "int", 1000,
         f"Maximum time in milliseconds the {desc} check may take before it is skipped.",
         level, minimum=1)


# --- identity -------------------------------------------------------------
_add("instance", "str", "", "Name of this ASSP-NG instance, used in logs and alerts.")
_add("hostname", "str", "",
     "Host name announced in the SMTP banner and headers; empty means the system FQDN.")
_add("banner.text", "str", "", "Extra text appended to the SMTP greeting banner.")

# --- storage ----------------------------------------------------------------
_add("database.url", "str", "", "Database connection URL for persistent data.")
_add("redis.url", "str", "redis://localhost:6379/0", "Redis connection URL for shared state.")
_add("redis.key_prefix", "str", "asspng:", "Prefix for every key ASSP-NG stores in Redis.")
_add("redis.op_timeout_ms", "int", 200,
     "Maximum time in milliseconds for one Redis operation.", minimum=1)
_add("state.on_redis_failure", "str", "degraded",
     "Behaviour when Redis fails: degraded keeps working on local memory, "
     "tempfail answers with a temporary SMTP error.",
     choices=("degraded", "tempfail"))
_count("state.failures_to_degrade", 3,
       "Consecutive Redis failures after which the state backend switches to degraded mode.",
       minimum=1)
_count("state.unreachable_to_degrade_s", 2,
       "Seconds Redis may stay unreachable before the state backend switches to degraded mode; "
       "0 switches at the first failure.")
_count("state.probe_interval_s", 10,
       "Seconds between probes that check whether Redis has recovered.", minimum=1)
_count("state.memory_max_entries", 200000,
       "Maximum number of entries kept in the local in-memory state fallback.", minimum=1)

# --- network ----------------------------------------------------------------
_add("network.ipv4_prefix", "int", 32,
     "IPv4 prefix length that groups client addresses into one \"network\" for limits and "
     "the penalty box; 32 treats every address on its own, 0 puts all of them in one.",
     minimum=0, maximum=32)
_add("network.ipv6_prefix", "int", 64,
     "IPv6 prefix length that groups client addresses into one \"network\" for limits and "
     "the penalty box; 128 treats every address on its own, 0 puts all of them in one.",
     minimum=0, maximum=128)

# --- limits -----------------------------------------------------------------
_count("limits.net.concurrent", 5,
       "Maximum simultaneous connections from one client network (the addresses grouped by "
       "network.ipv4_prefix and network.ipv6_prefix).", minimum=1)
_count("limits.net.connections_per_minute", 30,
       "Maximum new connections per minute from one client network (grouped by "
       "network.ipv4_prefix and network.ipv6_prefix).", minimum=1)
_count("limits.instance.concurrent", 500,
       "Maximum simultaneous connections accepted by this instance.", minimum=1)
_count("limits.session.messages", 50,
       "Maximum messages accepted in one SMTP session.", minimum=1)
_count("limits.session.protocol_errors", 5,
       "Protocol errors tolerated in one SMTP session before it is closed.", minimum=1)
_count("limits.session.invalid_recipients", 5,
       "Invalid recipients tolerated in one SMTP session before it is closed.", minimum=1)
_count("limits.message.recipients", 100,
       "Maximum recipients accepted for one message.", minimum=1)
_count("limits.auth.failures_per_net", 5,
       "Failed authentication attempts allowed per client network (grouped by "
       "network.ipv4_prefix and network.ipv6_prefix) within limits.auth.window.",
       minimum=1)
_count("limits.auth.failures_per_user", 10,
       "Failed authentication attempts allowed per user name within limits.auth.window.",
       minimum=1)
_add("limits.auth.window", "duration", "15m",
     "Time window in which failed authentication attempts are counted; a duration such as "
     "90, 30s, 15m, 1h or 7d (a bare number is seconds).", minimum=1)
_count("limits.user.messages_per_minute", 30,
       "Maximum messages one authenticated user may send per minute.", U, minimum=1)
_count("limits.user.messages_per_hour", 300,
       "Maximum messages one authenticated user may send per hour.", U, minimum=1)
_count("limits.user.recipients_per_hour", 1000,
       "Maximum recipients one authenticated user may address per hour.", U, minimum=1)

# --- penalty box --------------------------------------------------------------
_count("penalty_box.threshold", 50,
       "IP score at which a client network is put into the penalty box.", minimum=1)
_count("penalty_box.score_cap", 100,
       "Highest score an IP can accumulate.", minimum=1)
_add("penalty_box.score_ttl", "duration", "24h",
     "Time after which an IP score decays to zero without new offences; a duration such as "
     "30m, 24h or 7d (a bare number is seconds).", minimum=1)
_add("penalty_box.ladder", "list[duration]", ["24h", "7d", "30d"],
     "Ban durations for the first, second and later offences of the same client; a list "
     "of durations such as [\"24h\", \"7d\", \"30d\"] (a bare number is seconds). The last "
     "one repeats for further offences.",
     minimum=1, non_empty=True)
_add("penalty_box.history", "duration", "90d",
     "How long past offences are remembered when choosing the next ban duration; a duration "
     "such as 30d or 90d (a bare number is seconds).", minimum=1)
_count("abuse.protocol_error_ip_score", 10,
       "Score added to the client IP when a session exceeds its protocol error limit; "
       "0 adds nothing.")
_count("abuse.invalid_recipient_ip_score", 10,
       "Score added to the client IP when a session exceeds its invalid recipient limit; "
       "0 adds nothing.")
_count("abuse.relay_denied_ip_score", 10,
       "Score added to the client IP for an attempt to relay to a non-local domain; "
       "0 adds nothing.")
_count("abuse.auth_failure_ip_score", 10,
       "Score added to the client IP when it tries to authenticate again after a "
       "temporary authentication failure; 0 adds nothing.")

# --- checks -------------------------------------------------------------------
_check("conn_limits", 5, "connection limits")
_check("penalty_box", 0, "penalty box")
_check("session_limits", 0, "session limits")
_check("auth_limits", 20, "authentication limits")
_check("user_rate", 0, "per-user rate limit", U)

# --- scoring and test mode ----------------------------------------------------
_add("testmode", "bool", False,
     "When true, messages are only tagged and logged and never rejected.", R)
_add("scoring.limit", "int", 50,
     "Message score at or above which the message is rejected.", R, minimum=0)
_add("scoring.warn", "int", 35,
     "Message score at or above which the message is marked as suspicious.", R, minimum=0)
_add("scoring.add_header", "bool", True,
     "Add an X-ASSP-NG header with the score and reasons to accepted messages.", R)
_add("scoring.warn_subject_tag", "str", "",
     "Text prepended to the subject of suspicious messages; empty disables tagging.", R)

# --- timeouts -----------------------------------------------------------------
_count("timeouts.tls_handshake", 30, "Seconds allowed for a TLS handshake.", minimum=1)
_count("timeouts.backend_connect", 10,
       "Seconds allowed to connect to the backend mail server.", minimum=1)
_count("timeouts.backend_banner", 30,
       "Seconds to wait for the backend greeting banner.", minimum=1)
_count("timeouts.command", 300,
       "Seconds a client may be idle between SMTP commands.", minimum=1)
_count("timeouts.data_block", 180,
       "Seconds allowed between data blocks while a message is received.", minimum=1)
_count("timeouts.data_total", 600,
       "Seconds allowed to receive one complete message.", minimum=1)
_count("timeouts.backend_command", 300,
       "Seconds to wait for the backend to answer an SMTP command.", minimum=1)
_count("timeouts.backend_final", 600,
       "Seconds to wait for the backend answer after the end of message data.", minimum=1)
_count("timeouts.shutdown", 30,
       "Seconds that open sessions get to finish when the service stops.", minimum=1)
_count("timeouts.ptr", 3,
       "Seconds allowed for the reverse DNS lookup of the client address.", minimum=1)

# --- buffers and size ---------------------------------------------------------
_count("buffer.memory_per_message", 1048576,
       "Bytes of one message kept in memory before it spills to the spool directory.",
       minimum=1)
_count("buffer.memory_total", 134217728,
       "Total bytes of message data kept in memory across all sessions.", minimum=1)
_count("max_message_size", 52428800, "Maximum accepted message size in bytes.", minimum=1)

# --- paths --------------------------------------------------------------------
_add("paths.spool", "str", "/var/lib/assp-ng/spool", "Directory for spooled message data.")
_add("paths.cache", "str", "/var/lib/assp-ng/cache", "Directory for cached data.")
_add("paths.run", "str", "/run/assp-ng", "Directory for runtime files such as sockets.")
_add("paths.log_dir", "str", "/var/log/assp-ng", "Directory for log files.")

# --- health, alerts, logging ----------------------------------------------------
_add("health.listen", "str", "127.0.0.1:8025",
     "Address and port of the health check endpoint, as host:port.")
_add("alerts.email", "str", "", "Email address that receives alerts; empty disables email alerts.")
_add("alerts.webhook", "str", "", "Webhook URL that receives alerts; empty disables the webhook.")
_add("alerts.smtp_server", "str", "127.0.0.1:10125",
     "SMTP server, as host:port, used to deliver alert email.")
_add("alerts.min_interval", "duration", "30m",
     "Minimum time between two alerts about the same problem; a duration such as 30m or 1h "
     "(a bare number is seconds).", minimum=1)
_add("log.level", "str", "info", "Minimum severity written to the log.",
     choices=("debug", "info", "warning", "error"))
_count("debug.max_size_mb", 100, "Maximum total size of debug logs in megabytes.", minimum=1)
_add("debug.default_duration", "duration", "30m",
     "How long a debug session lasts when no duration is given; a duration such as 30m or 2h "
     "(a bare number is seconds).", minimum=1)
_add("debug.max_duration", "duration", "24h",
     "Longest allowed debug session for a single client or user; a duration such as 24h "
     "(a bare number is seconds).", minimum=1)
_add("debug.max_duration_all", "duration", "1h",
     "Longest allowed debug session covering all traffic; a duration such as 1h "
     "(a bare number is seconds).", minimum=1)
_count("debug.ring_lines", 50,
       "Number of recent log lines kept per session for debug output; 0 keeps none.")

# --- memory and domains -----------------------------------------------------------
_count("memory.soft_limit_mb", 360,
       "Process memory in megabytes above which caches are trimmed.", minimum=1)
_count("memory.idle_trim_after_s", 60,
       "Seconds without open sessions after which freed memory is returned to the system; "
       "0 trims as soon as the instance is idle.")
_count("memory.trim_interval_s", 600,
       "Seconds between periodic memory trims.", minimum=1)
_count("domains.refresh_interval_s", 300,
       "Seconds between reloads of the list of local domains.", minimum=1)
