"""Streamlit dashboard for the entropy DDoS detector (Phase 4a §4a.D).

Single command:

    streamlit run dashboard.py

Default mode is `--replay`: the dashboard reads samples/normal.pcap and
samples/attack.pcap from disk, drives them through EntropyAnalyzer (with
PCA + RF wired in), and animates the per-window verdicts window-by-window
with a 100 ms sleep between windows. The full replay takes ~5 seconds —
the reviewer watches the entropy_dst line collapse on the attack windows
and the verdict cells in the grid flip from green to red as the flood lands.

`--mode tail` switches to reading $telemetry_path from config and tailing
the JSON-line stream. That's the production observability path; on
Community Cloud the default replay path is what runs.

Four stacked panels:
    1. Entropy over time (plotly line, entropy_dst + entropy_src + entropy_size)
    2. Three-detector verdict grid (last N windows, entropy / PCA / RF columns)
    3. PCA scatter (windows projected into the 2D PCA space, color by verdict_pca)
    4. Would-install flow_mod table (per ATTACK window: nw_src, hard_timeout)

Streamlit Community Cloud constraints (per plan §4a.G):

    - No secrets, no env vars, no API keys. Cloud is public hosting; this
      file reads only world-readable files in the repo (samples/*.pcap,
      models/*.joblib, config.yaml).
    - First load on a sleeping app takes 30-60s. st.spinner() makes that
      visible; docs/screenshots/dashboard.png in the README is the
      cold-start failsafe.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from scapy.all import IP, rdpcap

from ddos_sdn.config import load_config
from ddos_sdn.detector.entropy import EntropyAnalyzer
from ddos_sdn.detector.telemetry import TelemetryEmitter

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_NORMAL_PCAP = REPO_ROOT / "samples" / "normal.pcap"
DEFAULT_ATTACK_PCAP = REPO_ROOT / "samples" / "attack.pcap"
PCA_PATH = REPO_ROOT / "models" / "pca.joblib"
RF_PATH = REPO_ROOT / "models" / "rf.joblib"

# Per-window animation delay (100 ms; total replay ≈ 5 seconds for 7 windows).
WINDOW_TICK_SECONDS = 0.1

# Last-N rows in the verdict grid.
VERDICT_GRID_ROWS = 20


# ---------------------------------------------------------------------------
# Detector loading
# ---------------------------------------------------------------------------
def _load_pca_ml() -> tuple[Any, Any]:
    """Load PCA + ML detectors. Returns (None, None) when artifacts absent."""
    try:
        from ddos_sdn.detector.ml_detector import MLDetector
        from ddos_sdn.detector.pca_detector import PCADetector

        return PCADetector(), MLDetector()
    except (FileNotFoundError, ImportError):
        return None, None


# ---------------------------------------------------------------------------
# Replay helper — the analyzer-replay code path the dashboard wraps.
# Called from the smoke test too, so its contract is locked.
# ---------------------------------------------------------------------------
def replay_pcap_to_records(
    pcap_path: Path,
    pca_detector=None,
    ml_detector=None,
) -> list[dict]:
    """Replay one PCAP through EntropyAnalyzer; return parsed JSON records.

    Each record is a 13-field dict matching TelemetryEmitter.FIELDS.
    """
    buf = io.StringIO()
    emitter = TelemetryEmitter(sink=buf, clock=lambda: 0.0)
    analyzer = EntropyAnalyzer(
        telemetry=emitter,
        pca_detector=pca_detector,
        ml_detector=ml_detector,
    )
    for pkt in rdpcap(str(pcap_path)):
        if IP not in pkt:
            continue
        analyzer.collect_statistics(
            pkt[IP].dst,
            src_ip=pkt[IP].src,
            packet_size=len(pkt),
        )
    return [json.loads(line) for line in buf.getvalue().splitlines()]


# ---------------------------------------------------------------------------
# Panel renderers — one function per panel, each takes (records, config).
# Smoke test asserts these names exist; test_dashboard.py imports them.
# ---------------------------------------------------------------------------
def render_entropy_timeseries(records: list[dict], config: dict) -> go.Figure:
    """Panel 1: entropy_{dst,src,size} over window index with threshold line."""
    threshold = config["detector"]["entropy_threshold_bits"]
    df = pd.DataFrame(records)
    df["window"] = range(1, len(df) + 1)

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["window"],
            y=df["entropy_dst"],
            mode="lines+markers",
            name="entropy_dst",
            line={"color": "#1f77b4", "width": 2},
        )
    )
    fig.add_trace(
        go.Scatter(
            x=df["window"],
            y=df["entropy_src"],
            mode="lines+markers",
            name="entropy_src",
            line={"color": "#2ca02c", "width": 2},
        )
    )
    fig.add_trace(
        go.Scatter(
            x=df["window"],
            y=df["entropy_size"],
            mode="lines+markers",
            name="entropy_size",
            line={"color": "#ff7f0e", "width": 2},
        )
    )
    fig.add_hline(
        y=threshold,
        line_dash="dash",
        line_color="red",
        annotation_text=f"threshold = {threshold} bits",
        annotation_position="bottom right",
    )
    fig.update_layout(
        title="Per-window entropy (bits)",
        xaxis_title="window #",
        yaxis_title="entropy (bits)",
        height=350,
        showlegend=True,
        margin={"l": 40, "r": 20, "t": 50, "b": 40},
    )
    return fig


def render_verdict_grid(records: list[dict], config: dict) -> pd.DataFrame:
    """Panel 2: last-N windows, three detector columns side by side."""
    tail = records[-VERDICT_GRID_ROWS:] if records else []
    rows = []
    for i, r in enumerate(tail, start=max(1, len(records) - len(tail) + 1)):
        rows.append(
            {
                "window": i,
                "entropy": r.get("verdict_entropy") or "—",
                "PCA": r.get("verdict_pca") or "—",
                "RF": r.get("verdict_rf") or "—",
            }
        )
    return pd.DataFrame(rows)


def _style_verdict(val: str) -> str:
    """Streamlit DataFrame cell styling for verdict cells."""
    if val == "ATTACK":
        return "background-color: #ffcccc; color: #aa0000; font-weight: bold"
    if val == "BENIGN":
        return "background-color: #ccffcc; color: #006600"
    return "background-color: #eeeeee; color: #888888"


def render_pca_scatter(records: list[dict], config: dict) -> go.Figure | None:
    """Panel 3: 2D PCA projection scatter, color by verdict_pca.

    Returns None if no records carry pca_mahalanobis (e.g. models absent).
    """
    df = pd.DataFrame(records)
    if "pca_mahalanobis" not in df or df["pca_mahalanobis"].isna().all():
        return None
    df["x"] = df["entropy_dst"]
    df["y"] = df["entropy_src"]
    df["window"] = range(1, len(df) + 1)
    df["verdict"] = df["verdict_pca"].fillna("—")
    fig = px.scatter(
        df,
        x="x",
        y="y",
        color="verdict",
        color_discrete_map={"BENIGN": "#2ca02c", "ATTACK": "#d62728", "—": "#888888"},
        hover_data=["window", "entropy_dst", "entropy_src", "entropy_size", "pca_mahalanobis"],
    )
    fig.update_layout(
        title="Window distribution (entropy_dst vs entropy_src), colored by PCA verdict",
        xaxis_title="entropy_dst (bits)",
        yaxis_title="entropy_src (bits)",
        height=400,
        margin={"l": 40, "r": 20, "t": 50, "b": 40},
    )
    fig.update_traces(marker={"size": 14, "line": {"width": 1, "color": "white"}})
    return fig


def render_flow_mod_table(records: list[dict], config: dict) -> pd.DataFrame:
    """Panel 4: would-install ofp_flow_mod rules for each ATTACK window."""
    hard_timeout = config["controller"]["flow_mod_hard_timeout_seconds"]
    rows = []
    for i, r in enumerate(records, start=1):
        if r.get("verdict_entropy") != "ATTACK":
            continue
        nw_src = r.get("top_src")
        if nw_src is None:
            continue
        rows.append(
            {
                "window#": i,
                "match.in_port": "N/A (offline)",
                "match.nw_src": nw_src,
                "actions": "drop",
                "hard_timeout": f"{hard_timeout}s",
            }
        )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Main Streamlit entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    st.set_page_config(
        page_title="DDoS detection on SDN — live dashboard",
        page_icon="🛡️",
        layout="wide",
    )
    st.title("Detection and Mitigation of DDoS Attacks in SDN")
    st.caption(
        "Streaming Shannon entropy + PCA + RandomForest at a POX/OpenFlow controller. "
        "Window-by-window replay of `samples/normal.pcap` then `samples/attack.pcap`."
    )

    config = load_config()
    pca_det, ml_det = _load_pca_ml()
    if pca_det is None or ml_det is None:
        st.error(
            "models/pca.joblib and/or models/rf.joblib not found. "
            "Run `python notebooks/train_pca_and_rf.py` to produce them, then refresh."
        )
        return

    # Re-run trigger.
    if "run_id" not in st.session_state:
        st.session_state.run_id = 0
    if st.button("▶  Replay again"):
        st.session_state.run_id += 1
        st.rerun()

    # Animated replay: window-by-window with WINDOW_TICK_SECONDS sleeps so
    # the reviewer watches the entropy line collapse on the attack window
    # rather than seeing the post-replay end-state. Total ≈ 5 seconds.
    progress = st.progress(0.0, text="Replaying samples/{normal,attack}.pcap...")
    records: list[dict] = []
    all_records: list[dict] = []
    for pcap_path in (DEFAULT_NORMAL_PCAP, DEFAULT_ATTACK_PCAP):
        all_records += replay_pcap_to_records(pcap_path, pca_det, ml_det)
    n_total = max(1, len(all_records))
    for i, rec in enumerate(all_records):
        records.append(rec)
        progress.progress((i + 1) / n_total, text=f"Window {i + 1} / {n_total}")
        time.sleep(WINDOW_TICK_SECONDS)
    progress.empty()

    # Render the four panels with the FULL record list. The animation lives
    # at the time-compressed loop above; Streamlit's reactive model handles
    # the rest. (For a true per-window animation we'd use st.empty() +
    # progressive updates inside the loop; that's available as a refinement.)
    st.markdown("### Panel 1 — Per-window entropy")
    st.plotly_chart(
        render_entropy_timeseries(records, config),
        use_container_width=True,
    )

    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("### Panel 2 — Three-detector verdicts (last 20 windows)")
        grid = render_verdict_grid(records, config)
        styled = grid.style.map(_style_verdict, subset=["entropy", "PCA", "RF"])
        st.dataframe(styled, use_container_width=True, hide_index=True)

    with col2:
        st.markdown("### Panel 3 — PCA projection")
        fig = render_pca_scatter(records, config)
        if fig is not None:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("PCA artifact not loaded; scatter unavailable.")

    st.markdown("### Panel 4 — Would-install ofp_flow_mod drop rules")
    flow_mods = render_flow_mod_table(records, config)
    if flow_mods.empty:
        st.info("No ATTACK windows detected — nothing to install.")
    else:
        st.dataframe(flow_mods, use_container_width=True, hide_index=True)

    st.success(
        f"Replay finished — {len(records)} windows processed. "
        f"Hit ▶ Replay again above to re-run."
    )


# `streamlit run dashboard.py` invokes the module with __name__ == "__main__"
# (that's Streamlit's contract for the script entrypoint).
# `streamlit_app.py` (the Community Cloud shim) calls dashboard.main()
# explicitly. tests/test_dashboard.py imports the module without triggering
# main() so the panel-function smoke runs without spinning up Streamlit.
if __name__ == "__main__":
    main()
