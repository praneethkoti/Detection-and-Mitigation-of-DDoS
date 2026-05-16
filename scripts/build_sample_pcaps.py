"""Deterministic PCAP corpus builder for the offline demo.

Generates two PCAP files under samples/:

    samples/normal.pcap   — 750-packet benign baseline (>= 3 closed windows of 250)
    samples/attack.pcap   — 1000 packets: 250 benign, then 750 single-target flood
                            (the flood starts at packet #251 so the second window
                             closes at packet #500 with verdict ATTACK — this is the
                             structural reason demo.py's [PASS] line claims detection
                             within the first 500 packets of attack.pcap)

The streams match tests/test_three_case_smoke.py exactly:
- benign destinations: uniform 10.0.0.[2..64]
- attack destination:  10.0.0.64 (the SINGLE_TARGET constant in the smoke)
- benign sources:      random TEST-NET-3 (203.0.113.x) for determinism
- attacker source:     10.0.0.1

The script writes packets with 1 ms monotonic synthetic timestamps starting at
epoch 0. Re-running with the same --seed produces byte-identical PCAPs across
machines and OSes.

Usage (one-shot at Phase 2 commit time; in normal use the committed PCAPs are
read by demo.py, not regenerated):

    python scripts/build_sample_pcaps.py --seed 42

The Makefile target `make samples` is the usual invocation.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from scapy.all import IP, UDP, Ether, wrpcap

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"

# Constants chosen to match tests/test_three_case_smoke.py exactly.
BENIGN_RANGE = range(2, 65)        # 10.0.0.[2..64]
SINGLE_TARGET = "10.0.0.64"        # flood destination
ATTACKER_SRC = "10.0.0.1"          # flood source — read by Phase 3's ofp_flow_mod(nw_src=...)

NORMAL_PCAP_PACKETS = 750
ATTACK_PCAP_PACKETS = 1000
ATTACK_PCAP_BENIGN_PREFIX = 250    # first 250 packets are benign; flood begins at index 251

DPORT = 80
SPORT = 2
PAYLOAD_BYTES = 982                # gives ~1024-byte frames (982 + 42 = Ether/IP/UDP overhead)

INTER_PACKET_MS = 1.0              # 1 ms monotonic spacing — see module docstring

# Deterministic placeholder MACs. Using real / resolved MACs makes scapy do live
# ARP lookups during Ether() construction, which is enormously slow on Windows.
# These MACs are stable across runs, so the PCAPs hash-match across machines.
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"


def _benign_src(rng: random.Random) -> str:
    """Random TEST-NET-3 (203.0.113.0/24) source — non-RFC-1918, deterministic via rng."""
    return f"203.0.113.{rng.randint(1, 254)}"


def _benign_dst(rng: random.Random) -> str:
    return f"10.0.0.{rng.choice(list(BENIGN_RANGE))}"


def _make_packet(src: str, dst: str, payload: bytes, timestamp: float):
    # Explicit src/dst MAC bypasses scapy's ARP resolution path.
    pkt = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src, dst=dst) / UDP(sport=SPORT, dport=DPORT) / payload
    pkt.time = timestamp
    return pkt


def build_normal_pcap(rng: random.Random, payload: bytes) -> list:
    pkts = []
    for i in range(NORMAL_PCAP_PACKETS):
        ts = i * (INTER_PACKET_MS / 1000.0)
        pkts.append(_make_packet(_benign_src(rng), _benign_dst(rng), payload, ts))
    return pkts


def build_attack_pcap(rng: random.Random, payload: bytes) -> list:
    pkts = []
    for i in range(ATTACK_PCAP_PACKETS):
        ts = i * (INTER_PACKET_MS / 1000.0)
        if i < ATTACK_PCAP_BENIGN_PREFIX:
            src = _benign_src(rng)
            dst = _benign_dst(rng)
        else:
            src = ATTACKER_SRC
            dst = SINGLE_TARGET
        pkts.append(_make_packet(src, dst, payload, ts))
    return pkts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the deterministic PCAP corpus consumed by demo.py and tests/test_pcap_replay.py.",
    )
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for deterministic IP draws (default: 42)")
    parser.add_argument(
        "--payload-bytes", type=int, default=PAYLOAD_BYTES,
        help=f"UDP payload size in bytes (default: {PAYLOAD_BYTES} — total frame ≈ 1024 B)",
    )
    parser.add_argument(
        "--out-dir", default=str(SAMPLES_DIR),
        help=f"output directory for normal.pcap and attack.pcap (default: {SAMPLES_DIR})",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = b"X" * args.payload_bytes

    rng_normal = random.Random(args.seed)
    rng_attack = random.Random(args.seed + 1)  # independent stream for attack pcap's benign prefix

    normal_pkts = build_normal_pcap(rng_normal, payload)
    attack_pkts = build_attack_pcap(rng_attack, payload)

    normal_path = out_dir / "normal.pcap"
    attack_path = out_dir / "attack.pcap"
    wrpcap(str(normal_path), normal_pkts)
    wrpcap(str(attack_path), attack_pkts)

    normal_size = normal_path.stat().st_size
    attack_size = attack_path.stat().st_size
    total = normal_size + attack_size

    print(f"build_sample_pcaps: wrote {normal_path}  packets={len(normal_pkts)}  bytes={normal_size}")
    print(f"build_sample_pcaps: wrote {attack_path}  packets={len(attack_pkts)}  bytes={attack_size}")
    print(f"build_sample_pcaps: total {total} bytes ({total / 1024 / 1024:.2f} MiB)")

    if total > 2 * 1024 * 1024:
        print(
            f"build_sample_pcaps: WARNING combined size {total} > 2 MiB budget; "
            f"reduce --payload-bytes or packet counts",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
