"""Single-command offline demo for the entropy DDoS detector.

Runs on macOS, Linux, and Windows. No sudo, no root, no POX, no Mininet, no
scapy.sendp(). Replays two committed PCAP files (samples/normal.pcap and
samples/attack.pcap) through EntropyAnalyzer and prints a coherent summary.

Default invocation (interview entry point):

    python demo.py

Expected last line on stderr:

    [PASS] attack detected within first 500 packets of attack.pcap

Exit code 0 if the entropy detector flags the attack within the first 500
packets of attack.pcap; exit 1 otherwise. Doubles as a CI smoke test.

I/O contract:
    stdout : one JSON line per closed entropy window (the project's external
             telemetry contract from TelemetryEmitter; locked at 13 fields in
             Phase 1). Pipe to `jq` or to a file for downstream tools.
    stderr : human-readable [SUMMARY]/[PASS]/[FAIL] lines. Routed away from
             stdout so the JSON stream stays consumable by automation.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from typing import Any

from scapy.all import IP, rdpcap

from ddos_sdn.config import load_config
from ddos_sdn.detector.entropy import EntropyAnalyzer
from ddos_sdn.detector.telemetry import TelemetryEmitter

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_NORMAL_PCAP = REPO_ROOT / "samples" / "normal.pcap"
DEFAULT_ATTACK_PCAP = REPO_ROOT / "samples" / "attack.pcap"

DETECTION_BUDGET_PACKETS = 500


def _load_pca_ml() -> tuple[Any, Any]:
    """Load the Phase 3 PCA + ML detectors if their .joblib files exist.

    Returns (None, None) when models are absent (e.g. fresh clone before
    notebooks/train_pca_and_rf.ipynb has been run). demo.py degrades
    gracefully: entropy verdict is unchanged, verdict_pca / verdict_rf
    stay as JSON null per the Phase 1 schema contract, and the summary
    line reports n/a for the PCA / RF F1 columns.
    """
    try:
        from ddos_sdn.detector.ml_detector import MLDetector
        from ddos_sdn.detector.pca_detector import PCADetector

        pca = PCADetector()
        rf = MLDetector()
        return pca, rf
    except (FileNotFoundError, ImportError):
        return None, None


def _replay_pcap(
    path: Path,
    window: int,
    threshold_bits: float,
    sink: io.TextIOBase,
    pca_detector: Any = None,
    ml_detector: Any = None,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Replay one PCAP through a fresh EntropyAnalyzer.

    Returns:
        (records, first_attack_packet_index_1based_or_neg1, rf_class_labels)
        - records: the parsed JSON dicts emitted for each closed window
        - first_attack_packet_index: the 1-based packet index that closed
          the first ATTACK window, or -1 if no attack window closed
        - rf_class_labels: MLDetector.classify() per closed window, empty when
          no RF artifact is loaded (Phase 4c §4c.B)
    """
    capture = io.StringIO()
    emitter = TelemetryEmitter(sink=capture, clock=lambda: 0.0)
    analyzer = EntropyAnalyzer(
        window=window,
        threshold_bits=threshold_bits,
        telemetry=emitter,
        pca_detector=pca_detector,
        ml_detector=ml_detector,
    )

    packet_index = 0
    first_attack_packet_index = -1
    windows_emitted = 0
    class_labels: list[str] = []

    packets = rdpcap(str(path))
    for pkt in packets:
        if IP not in pkt:
            continue
        packet_index += 1
        # Phase 4a §4a.A: pass packet size so entropy_size + packet_size_std_dev
        # are populated in the telemetry record and in the 10-feature vector
        # PCA/RF score. len(pkt) is the on-the-wire frame length (Ether + IP + UDP
        # + payload), the same metric the runtime POX controller would see.
        analyzer.collect_statistics(pkt[IP].dst, src_ip=pkt[IP].src, packet_size=len(pkt))

        # Did the analyzer just close a window? Each new window appends to dst_entropy.
        new_record_count = len(analyzer.dst_entropy)
        if new_record_count > windows_emitted:
            windows_emitted = new_record_count
            # Replay the just-captured JSON line to the real sink (stdout),
            # then check whether it was the first ATTACK window.
            last_line = capture.getvalue().splitlines()[-1]
            sink.write(last_line + "\n")
            sink.flush()
            record = json.loads(last_line)
            if record["verdict_entropy"] == "ATTACK" and first_attack_packet_index < 0:
                first_attack_packet_index = packet_index
            # Phase 4c §4c.B: capture the RF class while the analyzer still
            # holds the full 10-feature vector. Five of those features are not
            # telemetry fields, so this cannot be recovered from `record`.
            if ml_detector is not None and analyzer.last_feature_vector is not None:
                class_labels.append(ml_detector.classify(analyzer.last_feature_vector))

    records = [json.loads(line) for line in capture.getvalue().splitlines()]
    return records, first_attack_packet_index, class_labels


def _f1_from_records(
    attack_records: list[dict[str, Any]],
    normal_records: list[dict[str, Any]],
    verdict_field: str,
) -> str:
    """Compute F1 for one verdict column (entropy / pca / rf) across both pcaps.

    Returns the F1 as a 2-decimal string, or 'n/a' when the field is JSON null
    on every record (i.e. the corresponding detector was not loaded). This
    keeps the summary line honest per working agreement #4: no fabricated F1.
    """
    has_values = any(r.get(verdict_field) is not None for r in (*attack_records, *normal_records))
    if not has_values:
        return "n/a"
    tp = sum(1 for r in attack_records if r.get(verdict_field) == "ATTACK")
    fp = sum(1 for r in normal_records if r.get(verdict_field) == "ATTACK")
    fn = sum(1 for r in attack_records if r.get(verdict_field) == "BENIGN")
    denom = 2 * tp + fp + fn
    return f"{(2 * tp / denom):.2f}" if denom else "n/a"


def _format_rf_class_counts(class_labels: list[str], ml_detector: Any) -> str:
    """Format the RF class tally for the [SUMMARY] block (Phase 4c §4c.B).

    Labels are collected during replay (see _replay_pcap) because five of the
    ten features -- unique_src_count, unique_dst_count, top_dst_frequency,
    top_src_frequency, packet_size_std_dev -- are deliberately absent from the
    13-field telemetry schema. The vector cannot be reconstructed from the
    emitted JSON, and Phase 4c does not widen that contract to make it
    possible: the class label is additive metadata, not a schema field.
    """
    if ml_detector is None:
        return "n/a (no RF artifact loaded)"
    if len(getattr(ml_detector, "classes_", [])) < 3:
        return "binary model (re-run notebooks/train_pca_and_rf.py for class labels)"
    if not class_labels:
        return "n/a (no attack windows)"
    counts: dict[str, int] = {}
    for label in class_labels:
        counts[label] = counts.get(label, 0) + 1
    return "  ".join(f"{label}={n}" for label, n in sorted(counts.items()))


def _summarize(
    normal_records: list[dict[str, Any]],
    attack_records: list[dict[str, Any]],
    first_attack_packet_index: int,
    err: io.TextIOBase,
    ml_detector: Any = None,
    attack_class_labels: list[str] | None = None,
) -> bool:
    benign_windows = sum(1 for r in normal_records if r["verdict_entropy"] == "BENIGN")
    attack_windows_entropy = sum(1 for r in attack_records if r["verdict_entropy"] == "ATTACK")
    attack_windows_pca = sum(1 for r in attack_records if r.get("verdict_pca") == "ATTACK")
    attack_windows_rf = sum(1 for r in attack_records if r.get("verdict_rf") == "ATTACK")

    benign_min = min((r["entropy_dst"] for r in normal_records), default=float("nan"))
    attack_min = min((r["entropy_dst"] for r in attack_records), default=float("nan"))

    # Phase 3: real F1 for entropy + PCA + RF whenever the underlying verdict
    # fields are populated. Detectors that didn't load (no .joblib on disk)
    # leave their verdict fields as JSON null and _f1_from_records returns 'n/a'.
    entropy_f1 = _f1_from_records(attack_records, normal_records, "verdict_entropy")
    pca_f1 = _f1_from_records(attack_records, normal_records, "verdict_pca")
    rf_f1 = _f1_from_records(attack_records, normal_records, "verdict_rf")

    # would-install flow_mod: read top_src from the last ATTACK window. Phase 3's
    # real ofp_flow_mod drop rule consumes exactly this field via the telemetry.
    last_attack_rec = next(
        (r for r in reversed(attack_records) if r["verdict_entropy"] == "ATTACK"),
        None,
    )
    flow_mod_src = last_attack_rec["top_src"] if last_attack_rec else "n/a"

    first_str = f"#{first_attack_packet_index}" if first_attack_packet_index > 0 else "n/a"
    err.write(
        f"[SUMMARY] benign windows: {benign_windows}   "
        f"attack windows detected (entropy): {attack_windows_entropy}   "
        f"(pca): {attack_windows_pca}   "
        f"(rf): {attack_windows_rf}   "
        f"first detection at packet {first_str}\n"
    )
    err.write(
        f"[SUMMARY] entropy_dst min during benign: {benign_min:.2f}   "
        f"entropy_dst min during attack: {attack_min:.2f}\n"
    )
    err.write(
        f"[SUMMARY] entropy-only F1: {entropy_f1}   " f"PCA-gated F1: {pca_f1}   RF F1: {rf_f1}\n"
    )
    err.write(
        f"[SUMMARY] would-install flow_mod: nw_src={flow_mod_src}, in_port=N/A, hard_timeout=30\n"
    )
    # Phase 4c §4c.B: the specific attack class RF assigns to each attack
    # window. Additive metadata only; verdict_rf in the JSON stays binary.
    err.write(
        f"[SUMMARY] RF class labels: "
        f"{_format_rf_class_counts(attack_class_labels or [], ml_detector)}\n"
    )

    passed = (
        attack_windows_entropy >= 1 and 0 < first_attack_packet_index <= DETECTION_BUDGET_PACKETS
    )
    if passed:
        err.write(
            f"[PASS] attack detected within first {DETECTION_BUDGET_PACKETS} packets of attack.pcap\n"
        )
    else:
        err.write(
            f"[FAIL] attack NOT detected within first {DETECTION_BUDGET_PACKETS} packets of attack.pcap"
            f" (first_attack_packet={first_str}, attack_windows={attack_windows_entropy})\n"
        )
    err.flush()
    return passed


def main(argv: list[str] | None = None) -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Offline entropy-DDoS detection demo. Replays two PCAPs "
        "through EntropyAnalyzer; exit 0 on attack-detected, 1 otherwise.",
    )
    parser.add_argument(
        "--normal-pcap",
        type=Path,
        default=DEFAULT_NORMAL_PCAP,
        help=f"benign baseline PCAP (default: {DEFAULT_NORMAL_PCAP.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--attack-pcap",
        type=Path,
        default=DEFAULT_ATTACK_PCAP,
        help=f"attack PCAP (default: {DEFAULT_ATTACK_PCAP.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=cfg["detector"]["window_packets"],
        help=f"entropy window in packets (default: {cfg['detector']['window_packets']} from config)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=cfg["detector"]["entropy_threshold_bits"],
        help=f"attack threshold in bits (default: {cfg['detector']['entropy_threshold_bits']} from config)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress per-window JSON on stdout; only print summary lines on stderr",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    for label, path in [("--normal-pcap", args.normal_pcap), ("--attack-pcap", args.attack_pcap)]:
        if not path.is_file():
            print(f"demo: {label}={path} not found", file=sys.stderr)
            return 2

    stdout_sink: io.TextIOBase = io.StringIO() if args.quiet else sys.stdout

    # Phase 3: load PCA + RF detectors if their .joblib artifacts are on disk.
    # When absent (fresh clone before the training notebook runs), demo.py
    # degrades gracefully: pca/rf verdict fields stay null, summary reports n/a.
    pca_det, ml_det = _load_pca_ml()
    if pca_det is None or ml_det is None:
        print(
            "demo: PCA / ML detector artifacts not found; running entropy-only "
            "(run notebooks/train_pca_and_rf.py to produce them).",
            file=sys.stderr,
        )

    normal_records, _, _ = _replay_pcap(
        args.normal_pcap,
        args.window,
        args.threshold,
        stdout_sink,
        pca_detector=pca_det,
        ml_detector=ml_det,
    )
    attack_records, first_attack_index, attack_class_labels = _replay_pcap(
        args.attack_pcap,
        args.window,
        args.threshold,
        stdout_sink,
        pca_detector=pca_det,
        ml_detector=ml_det,
    )

    if not normal_records and not attack_records:
        print(
            f"demo: no IP packets found in either PCAP "
            f"(normal={args.normal_pcap}, attack={args.attack_pcap})",
            file=sys.stderr,
        )
        return 2

    passed = _summarize(
        normal_records,
        attack_records,
        first_attack_index,
        sys.stderr,
        ml_detector=ml_det,
        attack_class_labels=attack_class_labels,
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
