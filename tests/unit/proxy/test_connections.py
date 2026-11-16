# SPDX-License-Identifier: GPL-3.0-or-later
from asspng.proxy.connections import ConnectionTracker


def test_acquire_release_counts() -> None:
    t = ConnectionTracker()
    assert t.acquire("10.0.0.1/32") == 1
    assert t.acquire("10.0.0.1/32") == 2
    assert t.acquire("10.0.0.2/32") == 1
    assert (t.count("10.0.0.1/32"), t.total) == (2, 3)
    t.release("10.0.0.1/32")
    assert (t.count("10.0.0.1/32"), t.total) == (1, 2)


def test_release_never_goes_negative() -> None:
    t = ConnectionTracker()
    t.release("unknown")
    t.acquire("a")
    t.release("a")
    t.release("a")
    assert (t.count("a"), t.total) == (0, 0)
    assert t.acquire("a") == 1
