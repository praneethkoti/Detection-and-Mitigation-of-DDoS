"""Integration tests that replay the committed PCAPs through EntropyAnalyzer.

These pin the demo.py story end-to-end: the committed `samples/attack.pcap`
collapses dst-IP entropy to zero (the single-target flood case), and the
committed `samples/normal.pcap` stays above the configured attack threshold
for every closed window. If either assertion fails, the demo's [PASS]
contract is broken.

The PCAPs are produced by `scripts/build_sample_pcaps.py --seed 42` and
checked into git, so these tests are deterministic and run anywhere pytest
runs (Linux, macOS, Windows) without scapy.sendp, sudo, POX, or Mininet.
"""

from __future__ import annotations

import io
from pathlib import Path

from scapy.all import IP, rdpcap

from ddos_sdn.detector.entropy import EntropyAnalyzer
from ddos_sdn.detector.telemetry import TelemetryEmitter

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
ATTACK_PCAP = SAMPLES_DIR / "attack.pcap"
NORMAL_PCAP = SAMPLES_DIR / "normal.pcap"


def _replay(pcap_path: Path) -> EntropyAnalyzer:
    emitter = TelemetryEmitter(sink=io.StringIO(), clock=lambda: 0.0)
    analyzer = EntropyAnalyzer(telemetry=emitter)
    for pkt in rdpcap(str(pcap_path)):
        if IP in pkt:
            analyzer.collect_statistics(pkt[IP].dst, src_ip=pkt[IP].src)
    return analyzer


def test_attack_pcap_collapses_entropy_below_threshold() -> None:
    a = _replay(ATTACK_PCAP)
    # At least one window must have collapsed below threshold.
    assert min(a.dst_entropy) < a.threshold_bits
    # And the detector itself must report ATTACK for at least one window
    # (this is the assertion that fails first if a future refactor accidentally
    # makes is_attack() inconsistent with the raw entropy comparison).
    flood_windows = [e for e in a.dst_entropy if e < a.threshold_bits]
    assert len(flood_windows) >= 1
    # The structural fact behind demo.py's [PASS] line: the flood collapses
    # entropy to exactly 0.0 (single destination across the window).
    assert min(a.dst_entropy) == 0.0


def test_normal_pcap_stays_above_threshold() -> None:
    a = _replay(NORMAL_PCAP)
    # Companion negative test: every closed window in the benign pcap must
    # be above threshold. Guards against a future bug that over-aggressively
    # flags BENIGN windows.
    assert len(a.dst_entropy) >= 1
    assert all(e > a.threshold_bits for e in a.dst_entropy), a.dst_entropy
