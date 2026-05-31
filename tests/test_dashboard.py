"""Phase 4a §4a.E — module-smoke tests for dashboard.py.

These do NOT spin up a Streamlit server. The Streamlit reactive runtime is
heavy and CI doesn't need it. Instead the contract between the dashboard
and the rest of the project is what we lock:

  1. dashboard.py imports cleanly with no top-level side effects (no auto-run
     of main() under pytest).
  2. The four named panel render functions exist and are callable.
  3. replay_pcap_to_records produces 13-field telemetry records matching
     TelemetryEmitter.FIELDS — the cross-phase schema contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ddos_sdn.detector.telemetry import TelemetryEmitter

REPO_ROOT = Path(__file__).resolve().parent.parent
NORMAL_PCAP = REPO_ROOT / "samples" / "normal.pcap"
ATTACK_PCAP = REPO_ROOT / "samples" / "attack.pcap"


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
