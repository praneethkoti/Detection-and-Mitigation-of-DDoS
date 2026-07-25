"""Streamlit dashboard for the entropy DDoS detector (Phase 4a §4a.D).

Single command:

    streamlit run dashboard.py

The dashboard reads samples/normal.pcap and one attack PCAP from disk, drives
them through EntropyAnalyzer (with PCA + RF wired in), and animates the
per-window verdicts with a 100 ms sleep between windows. The full replay takes
~5 seconds; the reviewer watches the entropy_dst line collapse on the attack
windows and the verdict cells flip from green to red as the flood lands.

There is no CLI: Streamlit Community Cloud invokes streamlit_app.py with no
arguments, so every option is a widget. (An earlier version of this docstring
described `--mode replay` / `--mode tail` flags. They were never implemented;
Phase 4d.1 removed the claim rather than leaving it as aspirational
documentation. A tail-the-telemetry-stream mode would be a widget too.)

Attack class is chosen from a selectbox (Phase 4d.1 §4d.1.C). The default is
the UDP flood against samples/attack.pcap, which reproduces the Phase 3/4a view
exactly; the other three classes replay the PCAPs added in §4d.1.A.

Five stacked panels:
    1. Entropy over time (plotly line, entropy_dst + entropy_src + entropy_size)
    2. Verdict grid (last N windows: entropy / PCA / RF + the RF class label)
    3. PCA scatter (windows projected into the 2D PCA space, color by verdict_pca)
    4. Would-install flow_mod table (per ATTACK window: nw_src, hard_timeout)
    5. East-West coordinator view (Phase 4b correlation, fixture-driven)

Streamlit Community Cloud constraints (per plan §4a.G):

    - No secrets, no env vars, no API keys. Cloud is public hosting; this
      file reads only world-readable files in the repo (samples/*.pcap,
      models/*.joblib, config.yaml).
    - First load on a sleeping app takes 30-60s. st.spinner() makes that
      visible.
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
# Phase 4d.1 §4d.1.E: pre-recorded Phase 4b coordinator scenario for Panel 5.
COORDINATOR_REPLAY_JSONL = REPO_ROOT / "samples" / "coordinator_replay.jsonl"

# Per-window animation delay (100 ms; total replay ≈ 5 seconds for 7 windows).
WINDOW_TICK_SECONDS = 0.1

# Last-N rows in the verdict grid.
VERDICT_GRID_ROWS = 20

# Placeholder shown wherever a detector reported no verdict (JSON null), i.e.
# the corresponding .joblib was not loaded. This is rendered UI data, not
# prose: it fills verdict-grid cells and doubles as the plotly legend key in
# render_pca_scatter, so the two must stay in sync. ASCII per Phase 4c §4c.X.
NO_VERDICT = "n/a"

# Phase 4d.1 §4d.1.C: the attack-class selector's option registry.
#
# Order matters: index 0 is the Streamlit selectbox default, and it maps to
# samples/attack.pcap so the no-interaction view stays exactly the Phase 3/4a
# experience. The working agreement makes any regression to that default a
# blocker, so UDP flood stays first and keeps the original file name.
#
# `blurb` is the one-line description rendered under the dropdown: what the
# class does at the packet level and which detector earns its keep on it.
ATTACK_CLASSES: dict[str, dict[str, str]] = {
    "UDP flood (single target)": {
        "pcap": "attack.pcap",
        "blurb": (
            "High volume, few sources, one destination. Destination entropy "
            "collapses, so entropy-only catches it; PCA and RF confirm."
        ),
    },
    "SYN flood (spoofed sources)": {
        "pcap": "attack_syn_flood.pcap",
        "blurb": (
            "TCP SYN half-open exhaustion from spoofed sources. Source entropy "
            "goes high while destination entropy collapses; RF names the class "
            "from the fixed 60-byte frame size."
        ),
    },
    "Slow-loris (low and slow)": {
        "pcap": "attack_slowloris.pcap",
        "blurb": (
            "Rate-limited by design: a handful of long-lived sources dribbling "
            "keep-alives. Volume-based signals miss it; the rate collapse "
            "(pps ~ 13 against a flood's ~1000) is what identifies it."
        ),
    },
    "NTP amplification (reflected)": {
        "pcap": "attack_ntp_amp.pcap",
        "blurb": (
            "Reflected off a pool of NTP servers, so the victim sees many "
            "mid-cardinality sources sending large varied responses. Payload "
            "size variance is what separates it from a plain flood."
        ),
    },
}

# Cell background colors for the RF class column (Phase 4d.1 §4d.1.D).
# Hardcoded rather than theme-derived: five entries is more reviewable than a
# dynamic lookup, and these must stay legible against both the light theme in
# .streamlit/config.toml and Streamlit's dark mode.
RF_CLASS_COLORS: dict[str, str] = {
    "BENIGN": "#ccffcc",
    "UDP_FLOOD": "#ffcccc",
    "SYN_FLOOD": "#ffe0b3",
    "SLOWLORIS": "#fff5b3",
    "NTP_AMP": "#e6ccff",
}


# ---------------------------------------------------------------------------
# Detector loading
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def _load_pca_ml() -> tuple[Any, Any]:
    """Load PCA + ML detectors. Returns (None, None) when artifacts absent.

    @st.cache_resource (Phase 4d.1 §4d.1.G): the joblib artifacts are immutable
    for the life of the process, but Streamlit re-runs this whole script on
    every widget interaction. Uncached, adding the attack-class selector would
    reload both models on each selection change. cache_resource is the right
    decorator rather than cache_data because these are unserializable model
    objects shared across sessions, not copyable values.
    """
    try:
        from ddos_sdn.detector.ml_detector import MLDetector
        from ddos_sdn.detector.pca_detector import PCADetector

        return PCADetector(), MLDetector()
    except (FileNotFoundError, ImportError):
        return None, None


# ---------------------------------------------------------------------------
# Replay helper: the analyzer-replay code path the dashboard wraps.
# Called from the smoke test too, so its contract is locked.
# ---------------------------------------------------------------------------
def replay_pcap_to_records(
    pcap_path: Path,
    pca_detector=None,
    ml_detector=None,
    use_pcap_clock: bool = False,
) -> list[dict]:
    """Replay one PCAP through EntropyAnalyzer; return parsed JSON records.

    Each record is a 13-field dict matching TelemetryEmitter.FIELDS.

    THE 13-FIELD RECORD SHAPE IS LOCKED. Do not add keys here, and do not add
    an optional `labels`/`classes` parameter that widens what this function
    returns. tests/test_dashboard.py asserts set-equality against
    TelemetryEmitter.FIELDS, and the telemetry contract is consumed by
    downstream jq pipelines and the coordinator wire protocol. Attack-class
    labels and any other per-window metadata belong in the sibling
    replay_pcap_with_classes(), which returns them in a PARALLEL structure
    rather than inside these dicts. Consolidating the two functions back into
    one would put scope-creep pressure directly on the telemetry contract,
    which is the thing both Phase 4b and 4c were careful not to widen.

    `use_pcap_clock` (Phase 4d.1 §4d.1.B) selects where `pps` comes from:

        False (default)  the emitter clock is frozen at 0.0, so
                         EntropyAnalyzer's `window_seconds` floors at 1e-3 and
                         every window reports the synthetic pps=250000. This is
                         the historical behavior and it is the DEFAULT ON
                         PURPOSE: demo.py, tests/test_pcap_replay.py and the
                         existing dashboard path all depend on it, and demo.py's
                         locked "[PASS] attack detected within first 500 packets"
                         line depends on window boundaries that a clock change
                         would move.

        True             the clock advances to each packet's own timestamp, so
                         `pps` reflects the capture's real inter-packet spacing.
                         Required for the multi-class selector: SLOWLORIS is
                         defined by pps ~ 5-20, which is unreachable when the
                         clock is frozen (the window would report 250000 and the
                         RF would name it NTP_AMP).

    Callers that opt in must pass it explicitly. The default never changes.
    """
    buf = io.StringIO()
    # Mutable cell so the clock closure can be advanced per packet without
    # rebuilding the emitter. Read by TelemetryEmitter.now() at window close.
    clock_t = [0.0]
    clock = (lambda: clock_t[0]) if use_pcap_clock else (lambda: 0.0)
    emitter = TelemetryEmitter(sink=buf, clock=clock)
    analyzer = EntropyAnalyzer(
        telemetry=emitter,
        pca_detector=pca_detector,
        ml_detector=ml_detector,
    )
    for pkt in rdpcap(str(pcap_path)):
        if IP not in pkt:
            continue
        if use_pcap_clock:
            # Advance BEFORE collect_statistics: the window-close path reads
            # telemetry.now() inside this same call, so the timestamp has to be
            # current when the 250th packet of a window arrives.
            clock_t[0] = float(pkt.time)
        analyzer.collect_statistics(
            pkt[IP].dst,
            src_ip=pkt[IP].src,
            packet_size=len(pkt),
        )
    return [json.loads(line) for line in buf.getvalue().splitlines()]


def replay_pcap_with_classes(
    pcap_path: Path,
    pca_detector=None,
    ml_detector=None,
    use_pcap_clock: bool = False,
) -> tuple[list[dict], list[str]]:
    """Replay a PCAP and return (13-field records, parallel attack-class labels).

    Phase 4d.1 §4d.1.C. The class labels ride in a SEPARATE list, deliberately.
    MLDetector.classify() names the specific attack class, but the 13-field
    telemetry record carries only the binary verdict_rf, and widening it would
    break the contract that Phase 4b's coordinator wire protocol and every
    downstream jq consumer read. See the note in replay_pcap_to_records.

    The label is computed from EntropyAnalyzer.last_feature_vector, the Phase 4c
    hook added for exactly this purpose: five of the ten features
    (unique_src_count, unique_dst_count, top_dst_frequency, top_src_frequency,
    packet_size_std_dev) never appear in the telemetry record, so the class
    cannot be recovered from a record after the fact. It has to be captured at
    window-close time, which is what this function does.

    Returns labels aligned 1:1 with records. When no ml_detector is supplied,
    every label is NO_VERDICT.
    """
    buf = io.StringIO()
    clock_t = [0.0]
    clock = (lambda: clock_t[0]) if use_pcap_clock else (lambda: 0.0)
    emitter = TelemetryEmitter(sink=buf, clock=clock)
    analyzer = EntropyAnalyzer(
        telemetry=emitter,
        pca_detector=pca_detector,
        ml_detector=ml_detector,
    )
    labels: list[str] = []
    emitted = 0
    for pkt in rdpcap(str(pcap_path)):
        if IP not in pkt:
            continue
        if use_pcap_clock:
            clock_t[0] = float(pkt.time)
        analyzer.collect_statistics(
            pkt[IP].dst,
            src_ip=pkt[IP].src,
            packet_size=len(pkt),
        )
        # A window closed iff the emitter produced another line on this call.
        n_lines = buf.getvalue().count("\n")
        if n_lines > emitted:
            emitted = n_lines
            fv = analyzer.last_feature_vector
            if ml_detector is not None and fv is not None:
                labels.append(ml_detector.classify(fv))
            else:
                labels.append(NO_VERDICT)
    records = [json.loads(line) for line in buf.getvalue().splitlines()]
    return records, labels


@st.cache_data(show_spinner=False)
def _replay_cached(
    pcap_path_str: str,
    mtime: float,
    use_pcap_clock: bool,
) -> tuple[list[dict], list[str]]:
    """Cached wrapper around replay_pcap_with_classes (Phase 4d.1 §4d.1.G).

    Keyed on (path, mtime, clock mode) so regenerating the PCAP corpus
    invalidates the entry. Without this, every selector change re-parses ~1.8 MB
    of PCAP through scapy, which is several seconds of dead UI per interaction.

    Detectors are fetched inside rather than passed in: cache_data hashes its
    arguments, and the detector objects are neither hashable nor meaningfully
    comparable. They come from _load_pca_ml(), which is cache_resource'd.
    """
    pca_det, ml_det = _load_pca_ml()
    return replay_pcap_with_classes(
        Path(pcap_path_str),
        pca_det,
        ml_det,
        use_pcap_clock=use_pcap_clock,
    )


# ---------------------------------------------------------------------------
# Panel renderers: one function per panel, each takes (records, config).
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


def render_verdict_grid(
    records: list[dict],
    config: dict,
    classes: list[str] | None = None,
) -> pd.DataFrame:
    """Panel 2: last-N windows, detector columns side by side.

    `classes` (Phase 4d.1 §4d.1.D) is the optional parallel label list from
    replay_pcap_with_classes. When supplied, an "RF class" column is appended
    naming the specific attack class. Omitting it reproduces the original
    three-column grid exactly, which is what keeps the locked signature test
    and every existing two-argument caller working.
    """
    tail = records[-VERDICT_GRID_ROWS:] if records else []
    class_tail = list(classes[-VERDICT_GRID_ROWS:]) if classes else []
    rows = []
    for i, r in enumerate(tail, start=max(1, len(records) - len(tail) + 1)):
        row = {
            "window": i,
            "entropy": r.get("verdict_entropy") or NO_VERDICT,
            "PCA": r.get("verdict_pca") or NO_VERDICT,
            "RF": r.get("verdict_rf") or NO_VERDICT,
        }
        if classes:
            idx = i - max(1, len(records) - len(tail) + 1)
            label = class_tail[idx] if idx < len(class_tail) else NO_VERDICT
            # Defensive UX: verdict() and classify() must never disagree about
            # whether a window is an attack. tests/test_rf_multiclass.py locks
            # that invariant, so this branch should be unreachable, but the
            # dashboard renders whatever it is handed rather than hiding a
            # contradiction behind a plausible-looking label.
            verdict_attack = row["RF"] == "ATTACK"
            class_attack = label not in ("BENIGN", NO_VERDICT)
            if row["RF"] != NO_VERDICT and label != NO_VERDICT and verdict_attack != class_attack:
                label = f"! {label}"
            row["RF class"] = label
        rows.append(row)
    return pd.DataFrame(rows)


def _style_verdict(val: str) -> str:
    """Streamlit DataFrame cell styling for verdict cells."""
    if val == "ATTACK":
        return "background-color: #ffcccc; color: #aa0000; font-weight: bold"
    if val == "BENIGN":
        return "background-color: #ccffcc; color: #006600"
    return "background-color: #eeeeee; color: #888888"


def _style_rf_class(val: str) -> str:
    """Cell styling for the RF class column (Phase 4d.1 §4d.1.D)."""
    if isinstance(val, str) and val.startswith("! "):
        # verdict()/classify() disagreement: flag it loudly rather than
        # rendering it as an ordinary class cell.
        return "background-color: #ff9999; color: #660000; font-weight: bold; border: 2px solid #cc0000"
    color = RF_CLASS_COLORS.get(val)
    if color is None:
        return "background-color: #eeeeee; color: #888888"
    weight = "" if val == "BENIGN" else "; font-weight: bold"
    return f"background-color: {color}; color: #222222{weight}"


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
    df["verdict"] = df["verdict_pca"].fillna(NO_VERDICT)
    fig = px.scatter(
        df,
        x="x",
        y="y",
        color="verdict",
        color_discrete_map={"BENIGN": "#2ca02c", "ATTACK": "#d62728", NO_VERDICT: "#888888"},
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


def load_coordinator_replay(path: Path | None = None) -> list[dict]:
    """Load the Phase 4b coordinator replay fixture (Phase 4d.1 §4d.1.E).

    Returns [] when the fixture is absent so Panel 5 degrades to a hint rather
    than crashing the whole page. Regenerate with
    `python scripts/build_coordinator_replay.py`.
    """
    fixture = path or COORDINATOR_REPLAY_JSONL
    if not Path(fixture).is_file():
        return []
    out = []
    for line in Path(fixture).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def render_worker_telemetry(messages: list[dict], worker_id: str, limit: int = 5) -> pd.DataFrame:
    """Panel 5 left/right columns: the last `limit` telemetry rows for one worker."""
    rows = []
    for msg in messages:
        if msg.get("worker_id") != worker_id:
            continue
        rec = msg.get("record", {})
        rows.append(
            {
                "t": rec.get("t"),
                "dpid": rec.get("dpid"),
                "top_src": rec.get("top_src"),
                "verdict": rec.get("verdict_entropy") or NO_VERDICT,
            }
        )
    return pd.DataFrame(rows[-limit:])


def render_coordinator_buckets(
    messages: list[dict],
    tolerance_seconds: float = 1.0,
    min_workers: int = 2,
) -> pd.DataFrame:
    """Panel 5 middle column: the (top_src, bucket) corroboration map.

    Mirrors CoordinatorServer's bucketing (floor(t / tolerance_seconds), keyed
    on str(top_src), counting DISTINCT workers reporting ATTACK) so the panel
    shows the same state the real server would hold. This is a read-only
    reimplementation for display: the dashboard deliberately does not import
    ddos_sdn.coordinator, which would drag a socket server into a page render.
    tests/test_dashboard.py cross-checks the fixture against the REAL
    correlate() so this view cannot drift into fiction.
    """
    buckets: dict[tuple[int, str], set[str]] = {}
    for msg in messages:
        rec = msg.get("record", {})
        if rec.get("verdict_entropy") != "ATTACK":
            continue
        top_src = rec.get("top_src")
        if top_src is None:
            continue
        idx = int(rec.get("t", 0.0) // tolerance_seconds)
        buckets.setdefault((idx, str(top_src)), set()).add(msg.get("worker_id"))
    rows = []
    for (idx, top_src), workers in sorted(buckets.items()):
        rows.append(
            {
                "bucket": idx,
                "top_src": top_src,
                "workers": ", ".join(sorted(workers)),
                "count": len(workers),
                "drop rule": "ISSUED" if len(workers) >= min_workers else "waiting",
            }
        )
    return pd.DataFrame(rows)


def render_dispatched_rules(
    messages: list[dict],
    tolerance_seconds: float = 1.0,
    min_workers: int = 2,
    hard_timeout: int = 30,
) -> pd.DataFrame:
    """Panel 5 footer: the DROP_RULE_COMMANDs the coordinator would dispatch.

    One row per corroborating worker, matching CoordinatorServer's per-worker
    dispatch (each command carries that worker's own dpid), not one broadcast.
    """
    seen: dict[tuple[int, str], set[str]] = {}
    dpid_of: dict[str, int] = {}
    rows = []
    for msg in messages:
        rec = msg.get("record", {})
        worker_id = msg.get("worker_id")
        if rec.get("dpid") is not None:
            dpid_of[worker_id] = rec["dpid"]
        if rec.get("verdict_entropy") != "ATTACK":
            continue
        top_src = rec.get("top_src")
        if top_src is None:
            continue
        key = (int(rec.get("t", 0.0) // tolerance_seconds), str(top_src))
        workers = seen.setdefault(key, set())
        was_below = len(workers) < min_workers
        workers.add(worker_id)
        if was_below and len(workers) >= min_workers:
            for w in sorted(workers):
                rows.append(
                    {
                        "nw_src": top_src,
                        "dispatched_to": w,
                        "dpid": dpid_of.get(w),
                        "hard_timeout": rec.get("hard_timeout", hard_timeout),
                        "at_t": rec.get("t"),
                    }
                )
    return pd.DataFrame(rows)


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
        page_title="DDoS detection on SDN: live dashboard",
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

    # Attack-class selector (Phase 4d.1 §4d.1.C). Index 0 is the UDP flood, so
    # the no-interaction view is byte-for-byte the Phase 3/4a experience.
    labels = list(ATTACK_CLASSES)
    available = [
        name for name in labels if (REPO_ROOT / "samples" / ATTACK_CLASSES[name]["pcap"]).is_file()
    ]
    if not available:
        st.error(
            "No attack PCAPs found under samples/. "
            "Run `python scripts/build_sample_pcaps.py --seed 42` to generate them."
        )
        return
    missing = [name for name in labels if name not in available]

    choice = st.selectbox("Attack class to replay", available, index=0)
    st.caption(ATTACK_CLASSES[choice]["blurb"])
    if missing:
        st.caption(
            f"Not available locally: {', '.join(missing)}. "
            f"Run `python scripts/build_sample_pcaps.py --seed 42` to generate them."
        )

    if st.button("▶  Replay again"):
        # Drop the cached replay for the selected pcap so the button actually
        # re-runs the work rather than re-rendering a cached result.
        _replay_cached.clear()
        st.rerun()

    attack_pcap = REPO_ROOT / "samples" / ATTACK_CLASSES[choice]["pcap"]

    # Animated replay: window-by-window with WINDOW_TICK_SECONDS sleeps so
    # the reviewer watches the entropy line collapse on the attack window
    # rather than seeing the post-replay end-state. Total ≈ 5 seconds.
    progress = st.progress(0.0, text=f"Replaying samples/normal.pcap then {attack_pcap.name}...")
    records: list[dict] = []
    all_records: list[dict] = []
    all_classes: list[str] = []
    # use_pcap_clock=True is REQUIRED here, not cosmetic: slow-loris is defined
    # by pps ~ 13, and the frozen-clock path reports a synthetic pps=250000 for
    # every window, which makes the RF name it NTP_AMP. See §4d.1.B.
    for pcap_path in (DEFAULT_NORMAL_PCAP, attack_pcap):
        recs, cls = _replay_cached(str(pcap_path), pcap_path.stat().st_mtime, True)
        all_records += recs
        all_classes += cls
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
    st.markdown("### Panel 1: Per-window entropy")
    st.plotly_chart(
        render_entropy_timeseries(records, config),
        width="stretch",
    )

    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("### Panel 2: Detector verdicts + RF class (last 20 windows)")
        grid = render_verdict_grid(records, config, classes=all_classes)
        styled = grid.style.map(_style_verdict, subset=["entropy", "PCA", "RF"])
        if "RF class" in grid.columns:
            styled = styled.map(_style_rf_class, subset=["RF class"])
        st.dataframe(styled, width="stretch", hide_index=True)

    with col2:
        st.markdown("### Panel 3: PCA projection")
        fig = render_pca_scatter(records, config)
        if fig is not None:
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("PCA artifact not loaded; scatter unavailable.")

    st.markdown("### Panel 4: Would-install ofp_flow_mod drop rules")
    flow_mods = render_flow_mod_table(records, config)
    if flow_mods.empty:
        st.info("No ATTACK windows detected; nothing to install.")
    else:
        st.dataframe(flow_mods, width="stretch", hide_index=True)

    # -----------------------------------------------------------------------
    # Panel 5: multi-controller coordinator view (Phase 4d.1 §4d.1.E)
    #
    # Illustrative and read-only. Streamlit Cloud cannot run POX or Mininet, so
    # this replays a committed fixture rather than a live coordinator; the
    # ddos_sdn.coordinator package is never imported here.
    # -----------------------------------------------------------------------
    st.markdown("### Panel 5: East-West coordinator (Phase 4b)")
    coord_msgs = load_coordinator_replay()
    if not coord_msgs:
        st.info(
            "samples/coordinator_replay.jsonl not found. "
            "Run `python scripts/build_coordinator_replay.py` to generate it."
        )
    else:
        tolerance = config.get("coordinator", {}).get("tolerance_window_seconds", 1.0)
        min_workers = config.get("coordinator", {}).get("min_corroborating_workers", 2)
        st.caption(
            "Recorded two-worker scenario, not a live capture. Two workers report "
            "per-window telemetry; the coordinator correlates on `top_src` within "
            f"a {tolerance}s tolerance window and dispatches a drop rule once "
            f"{min_workers} workers corroborate. Watch records 5-6: two "
            "simultaneous ATTACK reports on *different* sources correctly produce "
            "no rule, which is what distinguishes correlation from a simple alarm count."
        )

        coord_area = st.empty()
        # A real per-record animation, unlike Panel 1's loop (which sleeps
        # without re-rendering). Each tick redraws the three columns so the
        # reviewer sees the bucket fill and the rule fire.
        for i in range(1, len(coord_msgs) + 1):
            shown = coord_msgs[:i]
            with coord_area.container():
                c1, c2, c3 = st.columns([1, 1, 1])
                with c1:
                    st.markdown("**Worker 1 telemetry**")
                    st.dataframe(
                        render_worker_telemetry(shown, "worker-1"),
                        width="stretch",
                        hide_index=True,
                    )
                with c2:
                    st.markdown("**Coordinator state**")
                    buckets = render_coordinator_buckets(shown, tolerance, min_workers)
                    if buckets.empty:
                        st.caption("No ATTACK reports yet.")
                    else:
                        st.dataframe(
                            buckets.style.map(
                                lambda v: (
                                    "background-color: #ffcccc; font-weight: bold"
                                    if v == "ISSUED"
                                    else ""
                                ),
                                subset=["drop rule"],
                            ),
                            width="stretch",
                            hide_index=True,
                        )
                with c3:
                    st.markdown("**Worker 2 telemetry**")
                    st.dataframe(
                        render_worker_telemetry(shown, "worker-2"),
                        width="stretch",
                        hide_index=True,
                    )
                st.markdown("**Drop rules dispatched**")
                dispatched = render_dispatched_rules(shown, tolerance, min_workers)
                if dispatched.empty:
                    st.caption("None yet: no source has been corroborated by enough workers.")
                else:
                    st.dataframe(dispatched, width="stretch", hide_index=True)
            time.sleep(WINDOW_TICK_SECONDS)

    st.success(
        f"Replay finished: {len(records)} windows processed. "
        f"Hit ▶ Replay again above to re-run."
    )


# `streamlit run dashboard.py` invokes the module with __name__ == "__main__"
# (that's Streamlit's contract for the script entrypoint).
# `streamlit_app.py` (the Community Cloud shim) calls dashboard.main()
# explicitly. tests/test_dashboard.py imports the module without triggering
# main() so the panel-function smoke runs without spinning up Streamlit.
if __name__ == "__main__":
    main()
