# SPDX-License-Identifier: GPL-3.0-or-later
import json
import logging
import os
import re
import threading
import time
from pathlib import Path

import pytest

from asspng.log.debug import DEBUG_QUEUE_MAX, DebugLog, DebugRules, RuleKind, SessionTap

PASSWORD = "s3cr3t-Pa55word"


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_rules(tmp_path: Path, clock: Clock | None = None) -> DebugRules:
    return DebugRules(
        tmp_path / "rules.json",
        clock or Clock(),
        default_s=1800,
        max_s=86400,
        max_all_s=3600,
    )


def make_log(tmp_path: Path, max_bytes: int = 10_000_000, on_full=lambda: None) -> DebugLog:
    return DebugLog(tmp_path / "debug.log", max_bytes, on_full)


def read_lines(tmp_path: Path) -> list[str]:
    return (tmp_path / "debug.log").read_text().splitlines()


def test_default_30m_expiry(tmp_path):
    clock = Clock()
    rules = make_rules(tmp_path, clock)
    rule = rules.add(RuleKind.FROM, "a@example.org", None, False)
    assert rule.expires_at == clock.now + 1800
    clock.now += 1799
    assert rules.active() == [rule]
    clock.now += 1
    assert rules.active() == []
    assert json.loads((tmp_path / "rules.json").read_text()) == []


def test_max_24h_and_all_1h(tmp_path):
    rules = make_rules(tmp_path)
    rules.add(RuleKind.USER, "bob", 86400, False)
    with pytest.raises(ValueError):
        rules.add(RuleKind.USER, "bob", 86401, False)
    rules.add(RuleKind.ALL, "", 3600, False)
    with pytest.raises(ValueError):
        rules.add(RuleKind.ALL, "", 3601, False)
    for bad in (0, -5):
        with pytest.raises(ValueError):
            rules.add(RuleKind.USER, "bob", bad, False)


def test_persist_and_reload(tmp_path):
    clock = Clock()
    rules = make_rules(tmp_path, clock)
    keep = rules.add(RuleKind.RCPT, "Dest@Example.com", 600, True)
    rules.add(RuleKind.USER, "bob", 10, False)
    clock.now += 100
    again = make_rules(tmp_path, clock)
    assert again.active() == [keep]
    assert keep.value == "dest@example.com"
    assert again.remove(keep.id) is True
    assert again.remove(keep.id) is False
    assert make_rules(tmp_path, clock).active() == []


def test_persistence_writes_mode_0600(tmp_path):
    rules = make_rules(tmp_path)
    rules.add(RuleKind.ALL, "", 60, False)
    assert (os.stat(tmp_path / "rules.json").st_mode & 0o777) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["rules.json"]


def test_corrupt_rules_file_loads_empty(tmp_path, caplog):
    (tmp_path / "rules.json").write_text("{not json")
    with caplog.at_level(logging.WARNING, logger="asspng.debug"):
        rules = make_rules(tmp_path)
    assert rules.active() == []
    assert "corrupt" in caplog.text


def test_invalid_entry_skipped_on_load(tmp_path):
    good = {"id": "aa", "kind": "ALL", "value": "", "expires_at": 2_000_000.0, "headers": False}
    bad = {"id": "bb", "kind": "NOPE", "value": "x", "expires_at": 2_000_000.0, "headers": False}
    (tmp_path / "rules.json").write_text(json.dumps([bad, good, 7]))
    assert [r.id for r in make_rules(tmp_path).active()] == ["aa"]


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (RuleKind.IP, "not-an-ip"),
        (RuleKind.FROM, "  "),
        (RuleKind.FROM, "a b@example.org"),
        (RuleKind.RCPT, "a\x01@example.org"),
        (RuleKind.USER, ""),
        (RuleKind.LISTENER, ""),
    ],
)
def test_invalid_values_raise(tmp_path, kind, value):
    with pytest.raises(ValueError):
        make_rules(tmp_path).add(kind, value, None, False)


def test_ip_rule_matches_network(tmp_path):
    rules = make_rules(tmp_path)
    rules.add(RuleKind.IP, "203.0.113.5", None, False)
    assert rules.match_connect("203.0.113.5/32", "inbound") is not None
    assert rules.match_connect("203.0.113.6/32", "inbound") is None


def test_ipv6_rule_matches_slash64(tmp_path):
    rules = make_rules(tmp_path)
    rules.add(RuleKind.IP, "2001:db8:1:2::1", None, False)
    other = "2001:db8:1:2:ffff::9"
    from asspng.net.ipnet import network_key, parse_ip

    assert rules.match_connect(network_key(parse_ip(other)), "inbound") is not None
    assert rules.match_connect(network_key(parse_ip("2001:db8:1:3::1")), "inbound") is None


def test_listener_and_all_match_connect(tmp_path):
    rules = make_rules(tmp_path)
    rule = rules.add(RuleKind.LISTENER, "submission", None, False)
    assert rules.match_connect("198.51.100.1/32", "submission") == rule
    assert rules.match_connect("198.51.100.1/32", "inbound") is None


def test_envelope_matching(tmp_path):
    rules = make_rules(tmp_path)
    rules.add(RuleKind.FROM, "Sender@Example.org", None, False)
    assert rules.match_envelope("SENDER@example.org", [], None) is not None
    assert rules.match_envelope("other@example.org", [], None) is None
    rules.add(RuleKind.RCPT, "x@example.com", None, False)
    assert rules.match_envelope("o@example.org", ["A@b.c", "X@Example.com"], None) is not None
    rules.add(RuleKind.USER, "bob", None, False)
    assert rules.match_envelope("o@example.org", ["a@b.c"], "BOB") is not None
    assert rules.match_envelope("o@example.org", ["a@b.c"], None) is None


def test_null_sender_from_rule(tmp_path):
    rules = make_rules(tmp_path)
    rule = rules.add(RuleKind.FROM, "<>", None, False)
    assert rules.match_envelope(None, [], None) == rule
    assert rules.match_envelope("", [], None) == rule
    assert rules.match_envelope("a@example.org", [], None) is None


def test_envelope_rule_flushes_ring(tmp_path):
    rules = make_rules(tmp_path)
    rules.add(RuleKind.FROM, "a@example.org", None, True)
    log = make_log(tmp_path)
    tap = SessionTap("s1", rules, log, 50)
    tap.on_connect("198.51.100.1/32", "inbound")
    assert not tap.active
    tap.line("P>C", "220 ready")
    tap.line("C>P", "EHLO client")
    tap.on_envelope("a@example.org", ["b@example.com"], None)
    assert tap.active and tap.headers
    tap.line("C>P", "QUIT")
    log.close()
    lines = read_lines(tmp_path)
    assert [ln.split(" ", 3)[1:] for ln in lines] == [
        ["s1", "P>C", "220 ready"],
        ["s1", "C>P", "EHLO client"],
        ["s1", "C>P", "QUIT"],
    ]


def test_inactive_tap_writes_nothing(tmp_path):
    rules = make_rules(tmp_path)
    log = make_log(tmp_path)
    tap = SessionTap("s1", rules, log, 5)
    tap.line("C>P", "EHLO x")
    tap.on_envelope("a@example.org", [], None)
    log.close()
    assert not (tmp_path / "debug.log").exists()
    assert not tap.active and not tap.headers


def test_ring_limited_to_n(tmp_path):
    rules = make_rules(tmp_path)
    rules.add(RuleKind.ALL, "", None, False)
    log = make_log(tmp_path)
    tap = SessionTap("s1", rules, log, 3)
    for i in range(10):
        tap.line("C>P", f"line {i}")
    tap.on_connect("198.51.100.1/32", "inbound")
    log.close()
    assert [ln.split(" ", 3)[3] for ln in read_lines(tmp_path)] == ["line 7", "line 8", "line 9"]


def test_buffered_line_keeps_original_timestamp(tmp_path, monkeypatch):
    import asspng.log.debug as mod

    rules = make_rules(tmp_path)
    rules.add(RuleKind.ALL, "", None, False)
    log = make_log(tmp_path)
    tap = SessionTap("s1", rules, log, 5)
    monkeypatch.setattr(mod.time, "time", lambda: 1_700_000_000.0)
    tap.line("C>P", "early")
    monkeypatch.setattr(mod.time, "time", lambda: 1_700_000_500.0)
    tap.on_connect("198.51.100.1/32", "inbound")
    log.close()
    stamp = read_lines(tmp_path)[0].split(" ")[0]
    from datetime import datetime

    assert datetime.fromisoformat(stamp).timestamp() == pytest.approx(1_700_000_000.0, abs=0.001)


def test_size_cap_calls_on_full_once(tmp_path):
    calls: list[int] = []
    log = make_log(tmp_path, max_bytes=300, on_full=lambda: calls.append(1))
    for i in range(30):
        log.write("s1", "C>P", f"line {i}")
    log.close()
    assert calls == [1]
    path = tmp_path / "debug.log"
    assert 0 < path.stat().st_size <= 300


def test_full_state_resets_after_rotation(tmp_path):
    calls: list[int] = []
    path = tmp_path / "debug.log"
    log = DebugLog(path, 200, lambda: calls.append(1))
    for i in range(10):
        log.write("s1", "C>P", f"line {i}")
    log.close()
    assert calls == [1]
    path.unlink()
    log2 = DebugLog(path, 200, lambda: calls.append(1))
    for i in range(10):
        log2.write("s1", "C>P", f"line {i}")
    log2.close()
    assert calls == [1, 1]


def test_reopens_after_rotation(tmp_path):
    path = tmp_path / "debug.log"
    log = make_log(tmp_path)
    log.write("s1", "C>P", "before")
    deadline_lines = 0
    while deadline_lines < 1:  # wait until the first line is on disk
        deadline_lines = len(path.read_text().splitlines()) if path.exists() else 0
    path.rename(tmp_path / "debug.log.1")
    log.write("s1", "C>P", "after")
    log.close()
    assert read_lines(tmp_path)[0].endswith("after")
    assert (tmp_path / "debug.log.1").read_text().rstrip().endswith("before")


def test_log_file_mode_0640(tmp_path):
    log = make_log(tmp_path)
    log.write("s1", "C>P", "x")
    log.close()
    assert (os.stat(tmp_path / "debug.log").st_mode & 0o750) == 0o640


def test_crlf_stays_on_one_line(tmp_path):
    log = make_log(tmp_path)
    log.write("s1", "C>P", "a\r\nb\x00c\x7f")
    log.close()
    lines = read_lines(tmp_path)
    assert len(lines) == 1
    assert lines[0].endswith("a\\x0d\\x0ab\\x00c\\x7f")
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d s1 C>P ", lines[0])


def test_auth_payload_redacted_by_writer(tmp_path):
    log = make_log(tmp_path)
    log.write("s1", "C>P", f"AUTH PLAIN {PASSWORD}")
    log.close()
    content = (tmp_path / "debug.log").read_text()
    assert PASSWORD not in content
    assert "AUTH PLAIN <redacted>" in content


def test_write_after_close_is_noop(tmp_path):
    log = make_log(tmp_path)
    log.write("s1", "C>P", "one")
    log.close()
    log.close()
    log.write("s1", "C>P", "two")
    assert len(read_lines(tmp_path)) == 1


def test_on_full_exception_does_not_kill_writer(tmp_path, caplog):
    def boom() -> None:
        raise RuntimeError("secret line content")

    log = make_log(tmp_path, max_bytes=100, on_full=boom)
    with caplog.at_level(logging.WARNING, logger="asspng.debug"):
        for i in range(5):
            log.write("s1", "C>P", f"line {i}")
        log.close()
    assert "on_full" in caplog.text
    assert "secret line content" not in caplog.text


# ---- fix round 1 ----------------------------------------------------------------------

def write_rules_file(tmp_path: Path, entries: list[dict]) -> None:
    (tmp_path / "rules.json").write_text(json.dumps(entries))


def entry(kind: str, value: str, expires_at: object, rule_id: str = "aa") -> dict:
    return {"id": rule_id, "kind": kind, "value": value, "expires_at": expires_at,
            "headers": False}


def test_ip_rules_survive_reload(tmp_path):
    from asspng.net.ipnet import network_key, parse_ip

    clock = Clock()
    rules = make_rules(tmp_path, clock)
    rules.add(RuleKind.IP, "203.0.113.5", 600, False)
    rules.add(RuleKind.IP, "2001:db8:1:2::1", 600, False)
    again = make_rules(tmp_path, clock)
    assert len(again.active()) == 2
    assert again.match_connect("203.0.113.5/32", "x") is not None
    key6 = network_key(parse_ip("2001:db8:1:2:9::9"))
    assert again.match_connect(key6, "x") is not None


@pytest.mark.parametrize("value", ["203.0.113.5", "203.0.113.0/24", "2001:db8::/48",
                                   "203.0.113.5/33", "2001:db8:1:2::/32", "junk"])
def test_load_rejects_non_canonical_ip_value(tmp_path, value):
    write_rules_file(tmp_path, [entry("IP", value, 1_001_000.0)])
    assert make_rules(tmp_path).active() == []


def test_load_clamps_far_future_expiry(tmp_path):
    write_rules_file(tmp_path, [
        entry("USER", "bob", 1e12, "u1"),
        entry("ALL", "", 1e12, "a1"),
    ])
    by_id = {r.id: r for r in make_rules(tmp_path).active()}
    assert by_id["u1"].expires_at == 1_000_000.0 + 86400
    assert by_id["a1"].expires_at == 1_000_000.0 + 3600


def test_load_skips_non_finite_expiry(tmp_path):
    (tmp_path / "rules.json").write_text(
        '[{"id":"i","kind":"USER","value":"bob","expires_at":1e999,"headers":false},'
        '{"id":"n","kind":"USER","value":"bob","expires_at":NaN,"headers":false}]'
    )
    assert make_rules(tmp_path).active() == []


def test_load_never_raises_on_hostile_json(tmp_path):
    big = "9" * 400
    (tmp_path / "rules.json").write_text(
        '[{"id":"i","kind":"USER","value":"bob","expires_at":' + big + ',"headers":false}]'
    )
    assert make_rules(tmp_path).active() == []
    (tmp_path / "rules.json").write_text("[" * 100000)
    assert make_rules(tmp_path).active() == []


def wait_for(predicate, timeout: float = 5.0) -> None:
    import time

    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("condition not reached")


def test_full_stays_full_for_short_line_after_rejected_long_one(tmp_path):
    calls: list[int] = []
    path = tmp_path / "debug.log"
    log = DebugLog(path, 250, lambda: calls.append(1))
    log.write("s1", "C>P", "x" * 10)
    wait_for(lambda: path.exists() and path.stat().st_size > 0)
    size = path.stat().st_size
    log.write("s1", "C>P", "y" * 400)  # rejected, enters the full state
    wait_for(lambda: calls == [1])
    log.write("s1", "C>P", "z")  # would fit, but the log is full
    log.write("s1", "C>P", "y" * 400)
    log.close()
    assert calls == [1]
    assert path.stat().st_size == size


def test_rotation_rearms_same_instance(tmp_path):
    calls: list[int] = []
    path = tmp_path / "debug.log"
    log = DebugLog(path, 250, lambda: calls.append(1))
    log.write("s1", "C>P", "first")
    log.write("s1", "C>P", "y" * 400)
    wait_for(lambda: calls == [1])
    path.rename(tmp_path / "debug.log.1")
    log.write("s1", "C>P", "second")
    wait_for(lambda: path.exists() and path.stat().st_size > 0)
    log.write("s1", "C>P", "y" * 400)
    log.close()
    assert calls == [1, 1]
    assert read_lines(tmp_path)[0].endswith("second")


def test_truncation_resumes_same_instance(tmp_path):
    calls: list[int] = []
    path = tmp_path / "debug.log"
    log = DebugLog(path, 250, lambda: calls.append(1))
    log.write("s1", "C>P", "first")
    log.write("s1", "C>P", "y" * 400)
    wait_for(lambda: calls == [1])
    os.truncate(path, 0)
    log.write("s1", "C>P", "after")
    log.close()
    assert [ln.split(" ", 3)[3] for ln in read_lines(tmp_path)] == ["after"]


def test_writer_thread_start_failure_never_reaches_the_session(tmp_path, monkeypatch, caplog):
    """C6: write() and close() must not raise when the writer thread cannot start."""
    import threading

    def refuse(self):
        raise RuntimeError("can't start new thread")

    log = DebugLog(tmp_path / "debug.log", 10_000, lambda: None)
    real_start = threading.Thread.start
    monkeypatch.setattr(threading.Thread, "start", refuse)
    with caplog.at_level(logging.WARNING):
        log.write("s1", "C>P", "line one")  # dropped, logged by type
    assert "RuntimeError" in caplog.text and "line one" not in caplog.text
    monkeypatch.setattr(threading.Thread, "start", real_start)
    log.write("s1", "C>P", "line two")  # a later write starts the thread
    log.close()
    text = (tmp_path / "debug.log").read_text()
    assert "line two" in text and "line one" not in text


def test_close_after_a_failed_thread_start_does_not_raise(tmp_path, monkeypatch):
    import threading

    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    log = DebugLog(tmp_path / "debug.log", 10_000, lambda: None)
    log.write("s1", "C>P", "line")
    log.close()


def test_debug_queue_is_bounded(tmp_path):
    assert make_log(tmp_path)._queue.maxsize == DEBUG_QUEUE_MAX == 10_000


def test_full_debug_queue_drops_lines_and_says_so(tmp_path, monkeypatch):
    # A stalled disk stops the writer thread: lines beyond the bound are dropped and counted.
    gate = threading.Event()
    log = DebugLog(tmp_path / "debug.log", 10_000_000, lambda: None, max_queued=2)
    handle = log._handle

    def slow(item):
        gate.wait(5)
        handle(item)

    monkeypatch.setattr(log, "_handle", slow)
    log.write("s1", "C>P", "first")
    deadline = time.monotonic() + 5
    while not log._queue.empty() and time.monotonic() < deadline:
        time.sleep(0.01)
    for i in range(5):
        log.write("s1", "C>P", f"line {i}")
    gate.set()
    log.close()
    texts = [line.split(" ", 3)[1:] for line in read_lines(tmp_path)]
    assert texts == [
        ["s1", "C>P", "first"],
        ["-", "!", "3 debug lines dropped: the debug log writer fell behind"],
        ["s1", "C>P", "line 0"],
        ["s1", "C>P", "line 1"],
    ]
