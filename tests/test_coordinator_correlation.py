"""Phase 4b §4b.F — coordinator correlation logic tests.

Seven tests. The headline assertion is test_two_workers_same_top_src_within
_window_DOES_trigger_drop_rule — the project's Phase 4b narrative kernel.
Two regression guards (per user note b) lock the design decisions:

    - test_correlation_across_bucket_boundary: the current+previous bucket
      lookup pattern in CoordinatorServer.correlate() catches messages
      that straddle a bucket boundary. Without this pattern, two messages
      100ms apart could silently miss correlation just because they
      landed in different floor() buckets.

    - test_overlapping_partition_dpids_raises: CoordinatorServer.__init__
      validates that no dpid appears in two workers' partition_dpids
      lists. Prevents the silent-failure mode where "cross-worker"
      correlation degrades into self-correlation.

All tests use injectable clocks so the tolerance window is exercised
deterministically without real sleeps. Locked Q5: no socket spin-up;
the correlate() entry point is unit-testable directly with an
in-memory sender callable.
"""

from __future__ import annotations

import pytest

from ddos_sdn.coordinator.protocol import MessageType
from ddos_sdn.coordinator.server import CoordinatorServer

# Standard two-worker partition layout used across the tests.
TWO_WORKER_CONFIG = [
    {"worker_id": "worker-1", "partition_dpids": [1, 2]},
    {"worker_id": "worker-2", "partition_dpids": [3, 4]},
]


def _make_server(now: float = 0.0, tolerance: float = 1.0) -> tuple[CoordinatorServer, list]:
    """Build a server with an injectable clock and a list-based sender.

    Returns (server, dispatched). dispatched is a list mutated by the
    sender callback so tests can inspect what was sent.
    """
    dispatched: list[tuple[str, dict]] = []
    server = CoordinatorServer(
        tolerance_window_seconds=tolerance,
        min_corroborating_workers=2,
        workers=TWO_WORKER_CONFIG,
        clock=lambda: now,
    )
    return server, dispatched


def _record(top_src: str, verdict: str = "ATTACK", dpid: int = 1) -> dict:
    """Minimal telemetry record for correlate() input. Mirrors the 13-field
    contract but only carries the fields correlate() actually reads."""
    return {
        "t": 0.0,
        "window_packets": 250,
        "entropy_dst": 5.91,
        "entropy_src": 0.0,
        "entropy_size": 0.0,
        "pps": 287,
        "pca_mahalanobis": None,
        "rf_proba": None,
        "verdict_entropy": verdict,
        "verdict_pca": None,
        "verdict_rf": None,
        "top_dst": "10.0.0.64",
        "top_src": top_src,
        "dpid": dpid,
        "in_port": 3,
        "hard_timeout": 30,
    }


def test_single_worker_attack_does_NOT_trigger_drop_rule() -> None:
    """One worker reporting ATTACK on a top_src is not enough; need >=2 distinct."""
    server, dispatched = _make_server()
    issued = server.correlate(
        _record("10.0.0.1"), "worker-1", sender=lambda w, c: dispatched.append((w, c))
    )
    assert issued == []
    assert dispatched == []


def test_two_workers_same_top_src_within_window_DOES_trigger_drop_rule() -> None:
    """HEADLINE: two workers reporting the same top_src + ATTACK trigger mitigation.

    This is the Phase 4b narrative kernel. If this test ever fails the
    project's Phase 4b story (cross-worker correlation → coordinator-issued
    drop rule) has regressed.
    """
    server, dispatched = _make_server()
    sender = lambda w, c: dispatched.append((w, c))  # noqa: E731

    # worker-1 reports ATTACK on top_src=10.0.0.1 — nothing fires yet.
    issued1 = server.correlate(_record("10.0.0.1", dpid=1), "worker-1", sender=sender)
    assert issued1 == []
    assert dispatched == []

    # worker-2 reports ATTACK on the SAME top_src in the SAME bucket — fires.
    issued2 = server.correlate(_record("10.0.0.1", dpid=3), "worker-2", sender=sender)
    assert (
        len(issued2) == 2
    ), f"expected 2 DROP_RULE_COMMAND (one per corroborating worker), got {len(issued2)}"
    targets = {w for w, _ in dispatched}
    assert targets == {
        "worker-1",
        "worker-2",
    }, f"both workers must receive a drop-rule command, got {targets}"
    for _w, cmd in dispatched:
        assert cmd["type"] == MessageType.DROP_RULE_COMMAND.value
        assert cmd["nw_src"] == "10.0.0.1"
        assert cmd["hard_timeout"] == 30
        # Each command's reason names both corroborating workers
        assert "worker-1" in cmd["reason"] and "worker-2" in cmd["reason"]


def test_two_workers_different_top_src_does_NOT_trigger_drop_rule() -> None:
    """Two workers reporting DIFFERENT top_srcs are uncorrelated."""
    server, dispatched = _make_server()
    sender = lambda w, c: dispatched.append((w, c))  # noqa: E731

    server.correlate(_record("10.0.0.1"), "worker-1", sender=sender)
    issued = server.correlate(_record("10.0.0.2"), "worker-2", sender=sender)
    assert issued == []
    assert dispatched == []


def test_correlation_window_expiry() -> None:
    """A record older than current_bucket - 1 is evicted; same top_src in a
    far-future bucket does NOT correlate."""
    dispatched: list[tuple[str, dict]] = []
    sender = lambda w, c: dispatched.append((w, c))  # noqa: E731
    now = [0.0]
    server = CoordinatorServer(
        tolerance_window_seconds=1.0,
        min_corroborating_workers=2,
        workers=TWO_WORKER_CONFIG,
        clock=lambda: now[0],
    )

    # worker-1 reports at t=0.0 — lands in bucket 0.
    server.correlate(_record("10.0.0.1"), "worker-1", sender=sender)
    # Advance clock past 2 * tolerance so worker-1's bucket (0) is now
    # too old for the current+previous lookup from bucket 3.
    now[0] = 3.5
    issued = server.correlate(_record("10.0.0.1"), "worker-2", sender=sender)
    assert issued == [], "expired bucket should not corroborate"
    assert dispatched == []


def test_two_workers_one_benign_does_NOT_trigger_drop_rule() -> None:
    """Same top_src across two workers but one reports BENIGN — no command."""
    server, dispatched = _make_server()
    sender = lambda w, c: dispatched.append((w, c))  # noqa: E731

    server.correlate(_record("10.0.0.1", verdict="BENIGN"), "worker-1", sender=sender)
    issued = server.correlate(_record("10.0.0.1", verdict="ATTACK"), "worker-2", sender=sender)
    assert issued == [], "BENIGN report from worker-1 must not count as corroboration"
    assert dispatched == []


def test_correlation_across_bucket_boundary() -> None:
    """Two messages 100ms apart that straddle a bucket boundary still correlate.

    # Worker-1's record lands in bucket floor((tolerance - 0.05) / tolerance) = 0.
    # Worker-2's record lands in bucket floor((tolerance + 0.05) / tolerance) = 1.
    # Without the current+previous bucket lookup pattern in §4b.B, these two
    # would correlate against DIFFERENT buckets and no DROP_RULE_COMMAND would
    # fire — silently missing a real cross-worker attack because the messages
    # straddled a bucket boundary.
    # The current+previous lookup pattern (correlate() checks both bucket B
    # and bucket B-1) catches this. If this test fails, the lookup pattern
    # has regressed to single-bucket and needs to be restored.
    """
    tolerance = 1.0
    dispatched: list[tuple[str, dict]] = []
    sender = lambda w, c: dispatched.append((w, c))  # noqa: E731
    now = [tolerance - 0.05]  # bucket 0, near its high end
    server = CoordinatorServer(
        tolerance_window_seconds=tolerance,
        min_corroborating_workers=2,
        workers=TWO_WORKER_CONFIG,
        clock=lambda: now[0],
    )

    server.correlate(_record("10.0.0.1"), "worker-1", sender=sender)
    assert server._bucket_index(now[0]) == 0  # sanity: bucket 0
    assert dispatched == []  # only one worker so far

    # Advance the clock by 100ms — into bucket 1.
    now[0] = tolerance + 0.05
    assert server._bucket_index(now[0]) == 1  # sanity: now in bucket 1

    issued = server.correlate(_record("10.0.0.1"), "worker-2", sender=sender)
    assert len(issued) == 2, (
        "boundary-crossing lookup must catch worker-1's record from bucket 0 "
        f"when worker-2 arrives in bucket 1; got {len(issued)} commands"
    )
    targets = {w for w, _ in dispatched}
    assert targets == {"worker-1", "worker-2"}


def test_overlapping_partition_dpids_raises() -> None:
    """Coordinator startup validation: same dpid in two workers' lists must raise.

    Regression guard for the silent-failure mode where two workers both
    think they own dpid 3 and 'cross-worker' correlation degrades into
    self-correlation. Per user note (b).
    """
    bad_config = [
        {"worker_id": "worker-1", "partition_dpids": [1, 3]},
        {"worker_id": "worker-2", "partition_dpids": [3, 4]},  # 3 overlaps
    ]
    with pytest.raises(ValueError, match="dpid=3 assigned to both"):
        CoordinatorServer(
            tolerance_window_seconds=1.0,
            min_corroborating_workers=2,
            workers=bad_config,
            clock=lambda: 0.0,
        )
