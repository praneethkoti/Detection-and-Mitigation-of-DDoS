"""Phase 4a §4a.E: module-smoke tests for dashboard.py.

These do NOT spin up a Streamlit server. The Streamlit reactive runtime is
heavy and CI doesn't need it. Instead the contract between the dashboard
and the rest of the project is what we lock:

  1. dashboard.py imports cleanly with no top-level side effects (no auto-run
     of main() under pytest).
  2. The four named panel render functions exist and are callable.
  3. replay_pcap_to_records produces 13-field telemetry records matching
     TelemetryEmitter.FIELDS, the cross-phase schema contract.

Phase 4d.1 extends this module (it does not rewrite it) with the multi-class
selector, the RF class column, the pcap-clock parameter, and the coordinator
fixture. Same smoke pattern throughout: no Streamlit server, function-local
imports, pure functions over committed inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ddos_sdn.detector.telemetry import TelemetryEmitter

REPO_ROOT = Path(__file__).resolve().parent.parent
NORMAL_PCAP = REPO_ROOT / "samples" / "normal.pcap"
ATTACK_PCAP = REPO_ROOT / "samples" / "attack.pcap"
SLOWLORIS_PCAP = REPO_ROOT / "samples" / "attack_slowloris.pcap"
COORDINATOR_FIXTURE = REPO_ROOT / "samples" / "coordinator_replay.jsonl"


def test_dashboard_module_imports() -> None:
    """`import dashboard` succeeds and main() is callable but not auto-invoked."""
    import dashboard

    assert callable(dashboard.main), "dashboard.main must be callable"


def test_dashboard_panel_functions_exist() -> None:
    """The four panel renderers are defined with the names the plan locked."""
    import dashboard

    for name in (
        "render_entropy_timeseries",
        "render_verdict_grid",
        "render_pca_scatter",
        "render_flow_mod_table",
    ):
        assert hasattr(dashboard, name), f"dashboard missing panel function: {name}"
        assert callable(getattr(dashboard, name)), f"dashboard.{name} not callable"


def test_dashboard_replays_pcaps_into_records() -> None:
    """replay_pcap_to_records returns 13-field telemetry records.

    Locks the dashboard ↔ telemetry contract: any future refactor that drops
    a field from the dashboard's per-window record will fail this test
    before it lands in CI.
    """
    if not NORMAL_PCAP.is_file() or not ATTACK_PCAP.is_file():
        pytest.skip("samples/*.pcap not present; run `make samples` to regenerate")

    import dashboard

    records = dashboard.replay_pcap_to_records(NORMAL_PCAP)
    assert len(records) >= 1, "no records emitted from normal.pcap replay"
    expected_keys = set(TelemetryEmitter.FIELDS)
    for r in records:
        assert set(r.keys()) == expected_keys, (
            f"dashboard record schema drift: extra={set(r.keys()) - expected_keys}, "
            f"missing={expected_keys - set(r.keys())}"
        )


# ---------------------------------------------------------------------------
# Phase 4d.1 §4d.1.H
# ---------------------------------------------------------------------------
def test_attack_class_selector_options_include_all_four() -> None:
    """The selector offers all four Phase 4c attack classes, UDP flood first.

    Index 0 is the Streamlit selectbox default, and the working agreement makes
    any regression to the no-interaction view a blocker. If someone reorders
    this registry, the default dashboard stops being the Phase 3/4a experience.
    """
    import dashboard

    labels = list(dashboard.ATTACK_CLASSES)
    assert len(labels) == 4, f"expected four attack classes, got {labels}"
    assert labels[0].startswith("UDP flood"), (
        f"UDP flood must be index 0 so the default view maps to samples/attack.pcap; "
        f"got {labels[0]!r}"
    )
    assert dashboard.ATTACK_CLASSES[labels[0]]["pcap"] == "attack.pcap"
    for label, meta in dashboard.ATTACK_CLASSES.items():
        assert meta["pcap"].endswith(".pcap"), f"{label} has no pcap mapping"
        assert meta["blurb"].strip(), f"{label} has no descriptive blurb"


def test_rf_class_column_renders_in_panel_2() -> None:
    """render_verdict_grid gains an 'RF class' column only when labels are passed."""
    import dashboard

    records = [
        {"verdict_entropy": "BENIGN", "verdict_pca": "BENIGN", "verdict_rf": "BENIGN"},
        {"verdict_entropy": "ATTACK", "verdict_pca": "ATTACK", "verdict_rf": "ATTACK"},
    ]
    config: dict = {}

    # Backward compatibility: the two-argument call is unchanged.
    plain = dashboard.render_verdict_grid(records, config)
    assert list(plain.columns) == ["window", "entropy", "PCA", "RF"]

    labelled = dashboard.render_verdict_grid(records, config, classes=["BENIGN", "SLOWLORIS"])
    assert list(labelled.columns) == ["window", "entropy", "PCA", "RF", "RF class"]
    assert list(labelled["RF class"]) == ["BENIGN", "SLOWLORIS"]

    # Every class the RF can emit has a distinct style, so no label renders as
    # the unknown-value grey fallback.
    for cls in ("BENIGN", "UDP_FLOOD", "SYN_FLOOD", "SLOWLORIS", "NTP_AMP"):
        assert cls in dashboard.RF_CLASS_COLORS
        assert "#eeeeee" not in dashboard._style_rf_class(cls)


def test_rf_class_column_flags_verdict_classify_disagreement() -> None:
    """A verdict()/classify() contradiction is surfaced, not silently rendered.

    tests/test_rf_multiclass.py locks the invariant that these two agree, so
    this should be unreachable. The dashboard still refuses to paint a
    contradiction as an ordinary class cell.
    """
    import dashboard

    records = [{"verdict_entropy": "BENIGN", "verdict_pca": "BENIGN", "verdict_rf": "BENIGN"}]
    grid = dashboard.render_verdict_grid(records, {}, classes=["UDP_FLOOD"])
    cell = grid["RF class"].iloc[0]
    assert cell.startswith("! "), f"disagreement not flagged: {cell!r}"
    assert "border" in dashboard._style_rf_class(cell)


def test_replay_pcap_to_records_schema_unchanged_with_new_params() -> None:
    """The 13-field contract survives the Phase 4d.1 signature change.

    replay_pcap_to_records gained `use_pcap_clock`. Neither that parameter nor
    the new sibling replay_pcap_with_classes may widen what this function
    returns: the telemetry record is consumed by the coordinator wire protocol
    and by downstream jq pipelines.
    """
    if not NORMAL_PCAP.is_file():
        pytest.skip("samples/normal.pcap not present; run `make samples`")

    import dashboard

    expected = set(TelemetryEmitter.FIELDS)
    for use_clock in (False, True):
        records = dashboard.replay_pcap_to_records(NORMAL_PCAP, use_pcap_clock=use_clock)
        assert records, f"no records emitted (use_pcap_clock={use_clock})"
        for r in records:
            assert set(r.keys()) == expected, (
                f"schema drift at use_pcap_clock={use_clock}: "
                f"extra={set(r.keys()) - expected}, missing={expected - set(r.keys())}"
            )


def test_use_pcap_clock_defaults_to_false() -> None:
    """The default must stay frozen-clock: demo.py's locked [PASS] depends on it.

    demo.py reports "first detection at packet #500", which is a function of
    where windows close. Flipping this default would move window boundaries for
    every existing caller.
    """
    import inspect

    import dashboard

    for fn in (dashboard.replay_pcap_to_records, dashboard.replay_pcap_with_classes):
        default = inspect.signature(fn).parameters["use_pcap_clock"].default
        assert default is False, f"{fn.__name__} must default use_pcap_clock=False, got {default!r}"


def test_pcap_clock_produces_real_pps_and_slowloris_class() -> None:
    """HEADLINE (Phase 4d.1 §4d.1.B): the clock fix makes slow-loris reachable.

    Slow-loris is defined by pps ~ 5-20. With the frozen clock every window
    reports a synthetic pps=250000 and the RF names the window NTP_AMP. This
    test locks both halves: real pps under the pcap clock, and the correct
    class label falling out of it.
    """
    if not SLOWLORIS_PCAP.is_file():
        pytest.skip("samples/attack_slowloris.pcap not present; run `make samples`")

    import dashboard

    pca_det, ml_det = dashboard._load_pca_ml()
    if ml_det is None:
        pytest.skip("models/rf.joblib not present; run notebooks/train_pca_and_rf.py")

    records, classes = dashboard.replay_pcap_with_classes(
        SLOWLORIS_PCAP, pca_det, ml_det, use_pcap_clock=True
    )
    assert len(records) == len(classes), "labels must align 1:1 with records"

    # strict=True is meaningful here: the assertion above already established
    # equal lengths, so a mismatch would be a real alignment bug, not noise.
    attack_pps = [r["pps"] for r, c in zip(records, classes, strict=True) if c == "SLOWLORIS"]
    assert attack_pps, f"no SLOWLORIS windows classified; got {classes}"
    assert all(p < 100 for p in attack_pps), (
        f"SLOWLORIS windows should report a low rate, got pps={attack_pps}. "
        f"A value near 250000 means the frozen clock leaked back in."
    )

    frozen_records, frozen_classes = dashboard.replay_pcap_with_classes(
        SLOWLORIS_PCAP, pca_det, ml_det, use_pcap_clock=False
    )
    assert all(r["pps"] == 250000 for r in frozen_records), "frozen clock path changed"
    assert "SLOWLORIS" not in frozen_classes, (
        "the frozen-clock path is expected to MISclassify slow-loris; if this "
        "starts passing, the pcap-clock parameter is no longer load-bearing and "
        "this whole mechanism should be re-examined"
    )


def test_coordinator_panel_reads_fixture_without_error() -> None:
    """Panel 5's renderers are pure functions over the committed fixture."""
    if not COORDINATOR_FIXTURE.is_file():
        pytest.skip("samples/coordinator_replay.jsonl not present")

    import dashboard

    messages = dashboard.load_coordinator_replay()
    assert len(messages) == 20, f"expected the 20-record scenario, got {len(messages)}"

    for worker in ("worker-1", "worker-2"):
        table = dashboard.render_worker_telemetry(messages, worker)
        assert not table.empty, f"{worker} produced no telemetry rows"
        assert list(table.columns) == ["t", "dpid", "top_src", "verdict"]

    buckets = dashboard.render_coordinator_buckets(messages)
    assert not buckets.empty
    assert "ISSUED" in list(buckets["drop rule"]), "no drop rule ever fires in the fixture"

    dispatched = dashboard.render_dispatched_rules(messages)
    assert not dispatched.empty
    assert set(dispatched["dispatched_to"]) == {"worker-1", "worker-2"}, (
        "the coordinator dispatches one command per corroborating worker, " "not a single broadcast"
    )

    # Missing fixture degrades to an empty list rather than raising.
    assert dashboard.load_coordinator_replay(REPO_ROOT / "samples" / "does_not_exist.jsonl") == []


def test_coordinator_fixture_matches_real_correlation() -> None:
    """The fixture must describe what the REAL coordinator would actually do.

    Panel 5 is illustrative, which makes it free to drift into fiction unless
    something pins it down. This feeds the committed fixture through the actual
    CoordinatorServer.correlate() and asserts the drop rules it yields are the
    ones the panel claims:

      - records 5-6 are two simultaneous ATTACK reports on DIFFERENT sources
        and must produce nothing (correlation keys on top_src, not on alarm
        count). This is the load-bearing negative case.
      - record 8 is the first corroborated match and must dispatch one command
        per worker, each scoped to that worker's own dpid.
    """
    if not COORDINATOR_FIXTURE.is_file():
        pytest.skip("samples/coordinator_replay.jsonl not present")

    from ddos_sdn.coordinator.server import CoordinatorServer

    now = [0.0]
    server = CoordinatorServer(
        host="127.0.0.1",
        port=0,
        tolerance_window_seconds=1.0,
        min_corroborating_workers=2,
        workers=[
            {"worker_id": "worker-1", "partition_dpids": [1, 2]},
            {"worker_id": "worker-2", "partition_dpids": [3, 4]},
        ],
        clock=lambda: now[0],
    )

    fired: dict[int, list[dict]] = {}
    for i, line in enumerate(COORDINATOR_FIXTURE.read_text(encoding="utf-8").splitlines(), 1):
        msg = json.loads(line)
        record = msg["record"]
        now[0] = record["t"]
        commands = server.correlate(record, msg["worker_id"], sender=lambda w, c: None)
        if commands:
            fired[i] = commands

    assert 6 not in fired, (
        "records 5-6 are ATTACK reports on different top_src values and must NOT "
        "produce a drop rule; if they do, the panel's central claim is wrong"
    )
    assert 8 in fired, "record 8 is the first corroborated match and must fire"

    first = fired[8]
    assert len(first) == 2, f"expected one command per corroborating worker, got {len(first)}"
    assert {c["nw_src"] for c in first} == {"10.0.0.5"}
    assert {c["dpid"] for c in first} == {
        1,
        3,
    }, "each command must carry the target worker's own dpid, not a shared one"
    assert all(c["hard_timeout"] == 30 for c in first)
