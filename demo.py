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


def _replay_pcap(
    path: Path,
    window: int,
    threshold_bits: float,
    sink: io.TextIOBase,
) -> tuple[list[dict[str, Any]], int]:
    """Replay one PCAP through a fresh EntropyAnalyzer.

    Returns:
        (records, first_attack_packet_index_1based_or_neg1)
        - records: the parsed JSON dicts emitted for each closed window
        - first_attack_packet_index: the 1-based packet index that closed
          the first ATTACK window, or -1 if no attack window closed
    """
    capture = io.StringIO()
    emitter = TelemetryEmitter(sink=capture, clock=lambda: 0.0)
    analyzer = EntropyAnalyzer(window=window, threshold_bits=threshold_bits, telemetry=emitter)

    packet_index = 0
    first_attack_packet_index = -1
    windows_emitted = 0

    packets = rdpcap(str(path))
    for pkt in packets:
        if IP not in pkt:
            continue
        packet_index += 1
        analyzer.collect_statistics(pkt[IP].dst, src_ip=pkt[IP].src)

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

    records = [json.loads(line) for line in capture.getvalue().splitlines()]
    return records, first_attack_packet_index


def _summarize(
    normal_records: list[dict[str, Any]],
    attack_records: list[dict[str, Any]],
    first_attack_packet_index: int,
    err: io.TextIOBase,
) -> bool:
    benign_windows = sum(1 for r in normal_records if r["verdict_entropy"] == "BENIGN")
    attack_windows_entropy = sum(1 for r in attack_records if r["verdict_entropy"] == "ATTACK")
    attack_windows_pca = sum(1 for r in attack_records if r.get("verdict_pca") == "ATTACK")
    attack_windows_rf = sum(1 for r in attack_records if r.get("verdict_rf") == "ATTACK")

    benign_min = min((r["entropy_dst"] for r in normal_records), default=float("nan"))
    attack_min = min((r["entropy_dst"] for r in attack_records), default=float("nan"))

    # Phase 1 entropy-only verdict labels are real; PCA/RF are JSON null
    # because no Phase 3 detector has shipped yet. F1 for those is n/a until
    # Phase 3 populates verdict_pca / verdict_rf.
    if attack_records:
        tp = sum(1 for r in attack_records if r["verdict_entropy"] == "ATTACK")
        fp = sum(1 for r in normal_records if r["verdict_entropy"] == "ATTACK")
        fn = sum(1 for r in attack_records if r["verdict_entropy"] == "BENIGN")
        denom = (2 * tp + fp + fn)
        entropy_f1: str = f"{(2 * tp / denom):.2f}" if denom else "n/a"
    else:
        entropy_f1 = "n/a"

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
        f"[SUMMARY] entropy-only F1: {entropy_f1}   "
        f"PCA-gated F1: n/a   RF F1: n/a\n"
    )
    err.write(
        f"[SUMMARY] would-install flow_mod: nw_src={flow_mod_src}, in_port=N/A, hard_timeout=30\n"
    )

    passed = (
        attack_windows_entropy >= 1
        and 0 < first_attack_packet_index <= DETECTION_BUDGET_PACKETS
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
        "--normal-pcap", type=Path, default=DEFAULT_NORMAL_PCAP,
        help=f"benign baseline PCAP (default: {DEFAULT_NORMAL_PCAP.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--attack-pcap", type=Path, default=DEFAULT_ATTACK_PCAP,
        help=f"attack PCAP (default: {DEFAULT_ATTACK_PCAP.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--window", type=int, default=cfg["detector"]["window_packets"],
        help=f"entropy window in packets (default: {cfg['detector']['window_packets']} from config)",
    )
    parser.add_argument(
        "--threshold", type=float, default=cfg["detector"]["entropy_threshold_bits"],
        help=f"attack threshold in bits (default: {cfg['detector']['entropy_threshold_bits']} from config)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="suppress per-window JSON on stdout; only print summary lines on stderr",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    for label, path in [("--normal-pcap", args.normal_pcap), ("--attack-pcap", args.attack_pcap)]:
        if not path.is_file():
            print(f"demo: {label}={path} not found", file=sys.stderr)
            return 2

    stdout_sink: io.TextIOBase = io.StringIO() if args.quiet else sys.stdout

    normal_records, _ = _replay_pcap(args.normal_pcap, args.window, args.threshold, stdout_sink)
    attack_records, first_attack_index = _replay_pcap(
        args.attack_pcap, args.window, args.threshold, stdout_sink,
    )

    if not normal_records and not attack_records:
        print(
            f"demo: no IP packets found in either PCAP "
            f"(normal={args.normal_pcap}, attack={args.attack_pcap})",
            file=sys.stderr,
        )
        return 2

    passed = _summarize(normal_records, attack_records, first_attack_index, sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
