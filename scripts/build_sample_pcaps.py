"""Deterministic PCAP corpus builder for the offline demo.

Generates two PCAP files under samples/:

    samples/normal.pcap     750-packet benign baseline (>= 3 closed windows of 250)
    samples/attack.pcap     1000 packets: 250 benign, then 750 single-target flood
                            (the flood starts at packet #251 so the second window
                             closes at packet #500 with verdict ATTACK. This is the
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
BENIGN_RANGE = range(2, 65)  # 10.0.0.[2..64]
SINGLE_TARGET = "10.0.0.64"  # flood destination
ATTACKER_SRC = "10.0.0.1"  # flood source, read by Phase 3's ofp_flow_mod(nw_src=...)

NORMAL_PCAP_PACKETS = 750
ATTACK_PCAP_PACKETS = 1000
ATTACK_PCAP_BENIGN_PREFIX = 250  # first 250 packets are benign; flood begins at index 251

DPORT = 80
SPORT = 2
PAYLOAD_BYTES = 982  # gives ~1024-byte frames (982 + 42 = Ether/IP/UDP overhead)

INTER_PACKET_MS = 1.0  # 1 ms monotonic spacing, see module docstring

# ---------------------------------------------------------------------------
# Phase 4d.1 §4d.1.A: three additional attack classes for the dashboard's
# class selector. Packet-level parameters MIRROR the per-class draws in
# scripts/build_synth_dataset.py (_window_syn_flood / _window_slowloris /
# _window_ntp_amp) so a replayed PCAP lands in the same region of the feature
# space the RF was trained on. Deliberately NOT real L4 protocol traffic:
# EntropyAnalyzer consumes only (src IP, dst IP, packet size), so real TCP
# flags or NTP monlist exchanges would add bytes without moving any feature.
# Same honest-synth framing as Phase 4c.
#
# Timing note (Phase 4d.1 §4d.1.B): `pps` is derived from packet timestamps
# when the dashboard replays with use_pcap_clock=True. SLOWLORIS is DEFINED by
# its rate, so its spacing is the load-bearing parameter here, not decoration.
# A 250-packet window spans 249 * delta seconds, so delta = (250/pps)/249.
# At 77.23 ms that is a 19.2 s window => pps ~ 13, the midpoint of the trained
# SLOWLORIS band (5-20). The other classes keep 1 ms (~1004 pps per window).
SYN_PACKET_BYTES = 60  # bare SYN on the wire; payload padded to hit this frame size
SYN_SRC_POOL = 200  # spoofed sources, mirrors _window_syn_flood's 75-300 draw

SLOWLORIS_SRC_COUNT = 18  # mirrors _window_slowloris's 6-30 draw
SLOWLORIS_PACKET_SIZES = (110, 120, 130, 140, 150, 160)
SLOWLORIS_TARGET_PPS = 13.0
SLOWLORIS_INTER_PACKET_S = (250.0 / SLOWLORIS_TARGET_PPS) / 249.0

NTP_REFLECTOR_COUNT = 55  # mirrors _window_ntp_amp's 12-110 draw
NTP_RESPONSE_SIZES = (440, 468, 482, 1200, 1440)

# Deterministic placeholder MACs. Using real / resolved MACs makes scapy do live
# ARP lookups during Ether() construction, which is enormously slow on Windows.
# These MACs are stable across runs, so the PCAPs hash-match across machines.
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"


def _benign_src(rng: random.Random) -> str:
    """Random TEST-NET-3 (203.0.113.0/24) source, non-RFC-1918, deterministic via rng."""
    return f"203.0.113.{rng.randint(1, 254)}"


def _benign_dst(rng: random.Random) -> str:
    return f"10.0.0.{rng.choice(list(BENIGN_RANGE))}"


def _make_packet(src: str, dst: str, payload: bytes, timestamp: float):
    # Explicit src/dst MAC bypasses scapy's ARP resolution path.
    pkt = (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / IP(src=src, dst=dst)
        / UDP(sport=SPORT, dport=DPORT)
        / payload
    )
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


# ---------------------------------------------------------------------------
# Phase 4d.1 §4d.1.A: SYN flood / slow-loris / NTP amplification.
#
# All three share build_attack_pcap's shape: ATTACK_PCAP_BENIGN_PREFIX benign
# packets then the attack, 1000 packets total, so the "detected within the
# first 500 packets" structure that demo.py locks generalizes to each class.
# ---------------------------------------------------------------------------
FRAME_OVERHEAD_BYTES = 42  # Ether(14) + IP(20) + UDP(8)


def _sized_payload(frame_bytes: int) -> bytes:
    """Payload that yields a `frame_bytes`-byte frame, floored at the header size."""
    return b"\x00" * max(0, frame_bytes - FRAME_OVERHEAD_BYTES)


def _pool_ip(prefix: str, index: int) -> str:
    """Map a 1-based pool index onto an IP under `prefix` (a /16 given as "a.b").

    Mirrors _pool_ip in scripts/build_synth_dataset.py: pools exceed 254, so the
    third octet carries the overflow and the pool size is exactly the parameter
    drawn rather than a product of two independent draws.
    """
    return f"{prefix}.{(index - 1) // 254 + 1}.{(index - 1) % 254 + 1}"


def build_syn_flood_pcap(rng: random.Random, benign_payload: bytes) -> list:
    """Spoofed-source SYN flood: many sources, one victim, fixed 60-byte frames."""
    syn_payload = _sized_payload(SYN_PACKET_BYTES)
    pkts = []
    for i in range(ATTACK_PCAP_PACKETS):
        ts = i * (INTER_PACKET_MS / 1000.0)
        if i < ATTACK_PCAP_BENIGN_PREFIX:
            pkts.append(_make_packet(_benign_src(rng), _benign_dst(rng), benign_payload, ts))
        else:
            src = _pool_ip("203.0", rng.randint(1, SYN_SRC_POOL))
            pkts.append(_make_packet(src, SINGLE_TARGET, syn_payload, ts))
    return pkts


def build_slowloris_pcap(rng: random.Random, benign_payload: bytes) -> list:
    """Low-and-slow: few long-lived sources, one victim, rate-limited by design.

    The inter-packet spacing IS the signature. Benign prefix keeps the 1 ms
    spacing so the first window still looks like ordinary traffic; the attack
    portion stretches to SLOWLORIS_INTER_PACKET_S so its windows report
    pps ~ 13. Without that stretch the class is unreachable: a frozen or
    1 ms clock reports pps ~ 1004+ and the RF names it NTP_AMP.
    """
    pkts = []
    t = 0.0
    for i in range(ATTACK_PCAP_PACKETS):
        if i < ATTACK_PCAP_BENIGN_PREFIX:
            pkts.append(_make_packet(_benign_src(rng), _benign_dst(rng), benign_payload, t))
            t += INTER_PACKET_MS / 1000.0
        else:
            src = f"198.51.100.{rng.randint(1, SLOWLORIS_SRC_COUNT)}"
            payload = _sized_payload(rng.choice(SLOWLORIS_PACKET_SIZES))
            pkts.append(_make_packet(src, SINGLE_TARGET, payload, t))
            t += SLOWLORIS_INTER_PACKET_S
    return pkts


def build_ntp_amp_pcap(rng: random.Random, benign_payload: bytes) -> list:
    """Reflected amplification: mid-size reflector pool, large varied responses."""
    pkts = []
    for i in range(ATTACK_PCAP_PACKETS):
        ts = i * (INTER_PACKET_MS / 1000.0)
        if i < ATTACK_PCAP_BENIGN_PREFIX:
            pkts.append(_make_packet(_benign_src(rng), _benign_dst(rng), benign_payload, ts))
        else:
            src = _pool_ip("192.0", rng.randint(1, NTP_REFLECTOR_COUNT))
            payload = _sized_payload(rng.choice(NTP_RESPONSE_SIZES))
            pkts.append(_make_packet(src, SINGLE_TARGET, payload, ts))
    return pkts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the deterministic PCAP corpus consumed by demo.py and tests/test_pcap_replay.py.",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="RNG seed for deterministic IP draws (default: 42)"
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=PAYLOAD_BYTES,
        help=f"UDP payload size in bytes (default: {PAYLOAD_BYTES}, total frame ≈ 1024 B)",
    )
    parser.add_argument(
        "--out-dir",
        default=str(SAMPLES_DIR),
        help=f"output directory for the PCAP corpus (default: {SAMPLES_DIR})",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = b"X" * args.payload_bytes

    # Seed offsets 0 and 1 are FROZEN: they reproduce normal.pcap and
    # attack.pcap byte-for-byte, which demo.py's locked [PASS] line and
    # tests/test_pcap_replay.py both depend on. Phase 4d.1's three new classes
    # take offsets 2-4 so they cannot perturb the two original streams.
    rng_normal = random.Random(args.seed)
    rng_attack = random.Random(args.seed + 1)  # independent stream for attack pcap's benign prefix
    rng_syn = random.Random(args.seed + 2)
    rng_slow = random.Random(args.seed + 3)
    rng_ntp = random.Random(args.seed + 4)

    builds = [
        ("normal.pcap", build_normal_pcap(rng_normal, payload)),
        ("attack.pcap", build_attack_pcap(rng_attack, payload)),
        ("attack_syn_flood.pcap", build_syn_flood_pcap(rng_syn, payload)),
        ("attack_slowloris.pcap", build_slowloris_pcap(rng_slow, payload)),
        ("attack_ntp_amp.pcap", build_ntp_amp_pcap(rng_ntp, payload)),
    ]

    total = 0
    for name, pkts in builds:
        path = out_dir / name
        wrpcap(str(path), pkts)
        size = path.stat().st_size
        total += size
        print(f"build_sample_pcaps: wrote {path}  packets={len(pkts)}  bytes={size}")

    print(f"build_sample_pcaps: total {total} bytes ({total / 1024 / 1024:.2f} MiB)")

    # Budget raised from 2 MiB to 5 MiB in Phase 4d.1: the corpus went from two
    # PCAPs to five. The three new attack classes are all smaller than the UDP
    # flood (60-byte SYN frames, 110-160-byte slow-loris writes, ~800-byte mean
    # NTP responses vs a flat 1024), so the real total lands well under this.
    if total > 5 * 1024 * 1024:
        print(
            f"build_sample_pcaps: WARNING combined size {total} > 5 MiB budget; "
            f"reduce --payload-bytes or packet counts",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
