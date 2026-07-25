"""Synth dataset builder (Phase 3 §3.E fallback path; extended in Phase 4a and 4c).

When the UNB CICDDoS2019 download isn't available, this script produces
samples/cicddos2019_sample.csv with the same column shape the real-data
extract_sample.py path would produce: 10 feature columns plus a Label
column, with the rows derived from the project's own smoke generators
scaled up.

Phase 4c §4c.A widens this from three regimes to five, and the Label column
from binary (BENIGN/ATTACK) to five-way. Six traffic regimes, 50,000
packets each (200 windows per case at window=250).

DIFFICULTY DISCIPLINE (§4c.A redo). The first cut of this builder pinned each
class to fixed parameter values: UDP_FLOOD always had exactly one source,
NTP_AMP always exactly 40 reflectors, SLOWLORIS always pps=500. That produced
five point-clouds with no overlap anywhere in the 10-feature space, and a
multi-class RF scored macro F1 = 1.0000 on it. That number measured the
generator, not the detector, so it was worthless as evidence.

Every class now draws its per-window parameters from a *distribution*, the
distributions of structurally similar classes deliberately overlap, and a
small fraction of windows per class are drawn as "hard cases" whose parameters
push into a neighbouring class's territory. The target is macro F1 in the
0.85-0.95 band, with the residual confusion concentrated on the pairs that
were designed to overlap. See the case list below for the per-class parameter ranges
and OVERLAP NOTES for which pairs collide on which features. The committed
result is macro F1 = 0.9270; scripts/probe_separability.py reports the
supporting separability probes.

    Case 1  benign baseline           Label = "BENIGN"
            uniform 10.0.0.[2..64] dst, random 203.0.113.x src
            mixed packet sizes drawn from common UDP payloads (Phase 4a §4a.C)
            Widest per-window variance of any class: source-pool size, dst
            spread, packet-size mix and rate all vary window to window, so
            BENIGN genuinely spans a range of legitimate traffic shapes
            rather than sitting on one point.

    Case 2  single-target flood       Label = "UDP_FLOOD"
            10.0.0.64 dst (with a ~20% spill onto neighbours), 1-5 attacker
            sources skewed toward 1, packet size near-fixed with jitter.

    Case 3  random-destination flood  Label = "UDP_FLOOD"  <-- the Phase 3 headline
            uniform 10.0.0.[2..64] dst, 1-5 sources, near-fixed packet size
            (entropy reports BENIGN on dst-IP; PCA must learn ATTACK from
             low entropy_src AND low entropy_size AND low packet_size_std_dev)
            Retained as a UDP_FLOOD variant so the Phase 3 narrative and
            test_pca_flips_random_dst_to_attack both survive Phase 4c.

    Case 4  SYN flood                 Label = "SYN_FLOOD"
            single target, spoofed sources drawn from a per-window pool of
            75-300 so most packets in a window carry a distinct source.
            60-byte SYN; a quarter of windows carry TCP option jitter.
            -> entropy_src high, unique_src_count ~ 38-178 (capped by the
               250-packet window), packet_size_std_dev near 0

    Case 5  slow-loris                Label = "SLOWLORIS"
            single target, a handful of long-lived sources, rate-limited by
            design. Small keep-alive writes of slightly varying size.
            -> pps ~ 5-20 per source-set (the per-case pps parameter below),
               unique_src_count ~ 6-30, packet_size_std_dev ~ 15-30
            Rate is the discriminator, but see OVERLAP NOTES: a slow BENIGN
            window reaches down into the same pps band, so rate alone does
            not settle it.

    Case 6  NTP amplification         Label = "NTP_AMP"
            single victim, responses reflected off a pool of 12-110 NTP
            servers, response sizes drawn from monlist reply sizes.
            -> unique_src_count ~ 12-110, packet_size_std_dev ~ 180-400
            Separated from SYN_FLOOD by size variance, and from UDP_FLOOD by
            source cardinality; overlaps both elsewhere.

OVERLAP NOTES (§4c.A redo item 2). The pairs below are engineered to collide,
and they are where the confusion-matrix off-diagonal mass lives:

    UDP_FLOOD / NTP_AMP   overlap on entropy_dst, pps, window_packets (both
                          are high-rate single-victim floods). Separated
                          primarily by packet_size_std_dev (plain vs
                          amplified) and unique_src_count (1-5 vs
                          12-110). A UDP_FLOOD hard case borrows NTP's
                          multi-size payload mix; an NTP_AMP hard case
                          collapses onto a small reflector pool.

    SYN_FLOOD / NTP_AMP   overlap on unique_src_count (both many-source; the
                          SYN low tail and the NTP high tail interleave).
                          Separated by packet_size_std_dev (near 0 vs
                          ~180-400) and entropy_size. A SYN hard case gets
                          MSS/option jitter that lifts its size variance off
                          zero; an NTP hard case draws a near-uniform
                          response size that flattens its size variance.

    SLOWLORIS / BENIGN    overlap on pps, and on unique_dst_count /
                          entropy_dst via the benign hard case. SLOWLORIS is
                          the structural outlier (rate + cadence), but
                          BENIGN's rate range extends down into single digits
                          and SLOWLORIS's bursts up into the thousands, so a
                          quiet benign window and a busy slow-loris window are
                          not separable on rate alone. The packet-size mix is
                          the only feature that reliably splits this pair.

Per-case pps (Phase 4c §4c.A): before Phase 4c, PPS was a module constant, so
the `pps` feature was identical on every row and carried no discriminative
signal. Slow-loris is *defined* by its rate, so _emit_case takes a pps
argument; the redo makes it a per-window draw rather than a per-case constant
so every class carries rate variance.

Feature noise (§4c.A redo item 1): after the per-window features are computed
from the packet stream, small Gaussian noise is added to entropy_dst,
entropy_src, entropy_size and packet_size_std_dev. This models measurement
jitter and, more importantly, stops the entropy features from being exact
functions of the generator's parameters (which is what made the classes
analytically separable before).

The 10-feature vector matches FEATURE_COLS in ddos_sdn.detector.features:

    [entropy_dst, entropy_src, entropy_size, pps, window_packets,
     unique_src_count, unique_dst_count,
     top_dst_frequency, top_src_frequency, packet_size_std_dev]

ddof discipline (Phase 4a): packet_size_std_dev = numpy.std(sizes, ddof=0)
explicitly. Train/inference symmetry guard: runtime entropy.py uses the
same ddof=0 path. If this script drifts to ddof=1 or to pandas default,
the headline PCA test will fail.

Determinism: same --seed produces a byte-identical CSV across machines and
OSes. RNGs are scoped per-case so case ordering can't bleed.

Usage:

    python scripts/build_synth_dataset.py --seed 42

Writes samples/cicddos2019_sample.csv and prints its sha256 so the value
can be pasted into data/README.md's ## Fallback (synth) section.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import math
import random
import sys
from collections import Counter
from pathlib import Path

import numpy as np

# Import the canonical FEATURE_COLS (Phase 4a §4a.B refactor).
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
from ddos_sdn.detector.features import FEATURE_COLS  # noqa: E402

SAMPLES_DIR = REPO_ROOT / "samples"
OUTPUT_CSV = SAMPLES_DIR / "cicddos2019_sample.csv"

WINDOW = 250
# §4c.A redo: raised from 10,000 (40 windows/case) to 50,000 (200 windows/case).
# With overlapping classes the held-out split is where the score is read, and at
# 40 windows/case the test half held 8 rows per class, so a single flipped row
# moved macro F1 by ~0.02 and the "2-3 confusions per 100 windows" target was
# not measurable at all. 200 windows/case puts 40 rows per class in the test
# half. The CSV stays small (1200 rows, well under the CI budget).
PACKETS_PER_CASE = 50000
BENIGN_RANGE = range(2, 65)  # 10.0.0.[2..64]
SINGLE_TARGET = "10.0.0.64"
ATTACKER_SRC = "10.0.0.1"

# Phase 4a: packet-size discipline per case regime.
# Benign baseline mimics a mix of common UDP payload sizes; floods use a
# near-fixed size (matches the runtime udp_flood / random_dst generators,
# which emit fixed-size packets; see src/ddos_sdn/generators/udp_flood.py).
BENIGN_PACKET_SIZES = (64, 128, 256, 512, 1024, 1500)
FLOOD_PACKET_SIZE = 1024

# Phase 4c §4c.A: per-class packet-level parameters.
#
# SYN flood: spoofed sources drawn from a per-window pool. A bare SYN with no
# options is 60 bytes on the wire; hard-case windows add option jitter.
SYN_PACKET_SIZE = 60
SYN_OPTION_SIZES = (52, 56, 60, 64, 72)  # SYN with varying option blocks

# Slow-loris: a small pool of long-lived connections dribbling keep-alive
# headers. Sizes vary slightly because partial headers differ in length.
SLOWLORIS_PACKET_SIZES = (110, 120, 130, 140, 150, 160)

# NTP amplification: the victim sees reflected responses from a pool of real
# NTP servers. monlist replies come back in a handful of discrete sizes.
NTP_RESPONSE_SIZES = (440, 468, 482, 1200, 1440)

# ----------------------------------------------------------------------
# §4c.A redo: per-window draw ranges and overlap controls.
# ----------------------------------------------------------------------
# Fraction of windows per class drawn as "hard cases": atypical parameter
# values pushed toward a structurally similar class. These are what populate
# the confusion matrix's off-diagonal cells. ~5% per the redo brief; at 40
# windows per case that is a small handful of rows per class, which is the
# intended 2-3 confusion errors per 100 windows.
HARD_CASE_RATE = 0.12

# Gaussian noise (standard deviations) applied to the computed features. The
# entropy features are in bits and live on ~[0, 8]; packet_size_std_dev is in
# bytes and spans ~[0, 500], so it gets a proportionally larger sigma.
NOISE_SIGMA = {
    "entropy_dst": 0.30,
    "entropy_src": 0.45,
    "entropy_size": 0.28,
    "packet_size_std_dev": 45.0,
}

# Per-window rate draws. Every class now carries rate variance; the ranges for
# BENIGN and SLOWLORIS deliberately touch (see OVERLAP NOTES in the module
# docstring) so pps alone cannot settle that pair.
#
# The high-rate classes are expressed as a multiplier on PPS so the historical
# 250000 stays the centre of the distribution and the runtime feature scale is
# unchanged.
FLOOD_PPS_RANGE = (0.06, 1.45)  # x PPS: a throttled flood is still a flood
BENIGN_PPS_RANGE = (0.02, 1.20)  # x PPS, wide: benign load genuinely varies
BENIGN_QUIET_RATE = 0.22  # fraction of benign windows that are near-idle
BENIGN_QUIET_PPS = (8.0, 2500.0)  # absolute pps: reaches down into SLOWLORIS
SLOWLORIS_PPS_RANGE = (5.0, 20.0)  # absolute pps: rate-limited by design
SLOWLORIS_BURST_PPS = (400.0, 4000.0)  # hard case: a busier slow-loris window

# Fraction of flood windows drawn at a deliberately throttled rate (a
# low-and-slow flood, or a flood measured mid-ramp). Without this, `pps` is a
# near-perfect gate separating the three high-rate classes from BENIGN and
# SLOWLORIS, and the classifier leans on a feature whose class margin spans
# four orders of magnitude, which is exactly the kind of artefact that made
# the first cut of this dataset score 1.0.
FLOOD_THROTTLED_RATE = 0.18
FLOOD_THROTTLED_PPS = (600.0, 20000.0)

LABEL_COL = "Label"
HEADER = list(FEATURE_COLS) + [LABEL_COL]

# Default synthetic pps; same value the runtime EntropyAnalyzer reports
# at 1ms/packet (250 packets / 0.001s = 250000), so the feature distribution
# at training matches what the runtime emits at inference. Phase 4c makes this
# a per-case argument (see _emit_case) because slow-loris is defined by rate.
PPS = 250000

# Five-way label set (Phase 4c). BENIGN plus four attack classes.
BENIGN_LABEL = "BENIGN"
ATTACK_LABELS = ("UDP_FLOOD", "SYN_FLOOD", "SLOWLORIS", "NTP_AMP")
ALL_LABELS = (BENIGN_LABEL,) + ATTACK_LABELS


def _shannon_bits(counter: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for c in counter.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _window_features(
    dsts: list[str],
    srcs: list[str],
    sizes: list[int],
    pps: float = PPS,
) -> list[float]:
    """Compute the 10-feature vector for one closed window.

    Order MUST match FEATURE_COLS in ddos_sdn.detector.features.

    `pps` is a parameter as of Phase 4c so slow-loris can report its true
    low rate; every other case passes the historical 250000 default.
    """
    n = len(dsts)
    dst_counts = Counter(dsts)
    src_counts = Counter(srcs)
    size_counts = Counter(sizes)
    top_dst_count = dst_counts.most_common(1)[0][1]
    top_src_count = src_counts.most_common(1)[0][1]
    # ddof=0 explicit: train/inference symmetry guard (see module docstring).
    packet_size_std_dev = float(np.std(sizes, ddof=0)) if sizes else 0.0
    return [
        _shannon_bits(dst_counts, n),  # entropy_dst
        _shannon_bits(src_counts, n),  # entropy_src
        _shannon_bits(size_counts, len(sizes)),  # entropy_size
        float(pps),  # pps
        float(n),  # window_packets
        float(len(src_counts)),  # unique_src_count
        float(len(dst_counts)),  # unique_dst_count
        top_dst_count / n,  # top_dst_frequency
        top_src_count / n,  # top_src_frequency
        packet_size_std_dev,  # packet_size_std_dev
    ]


def _apply_noise(features: list[float], rng: random.Random) -> list[float]:
    """Add Gaussian measurement noise to the entropy and size-variance features.

    §4c.A redo item 1. Without this the entropy features are exact functions of
    the generator's parameters, which makes classes analytically separable in a
    way real per-window measurements never are. Clamped at zero because none of
    the four noised features can be negative.
    """
    out = list(features)
    for name, sigma in NOISE_SIGMA.items():
        idx = FEATURE_COLS.index(name)
        out[idx] = max(0.0, out[idx] + rng.gauss(0.0, sigma))
    return out


def _emit_case(
    rng: random.Random,
    n_packets: int,
    window_fn,
    label: str,
) -> list[tuple[list[float], str]]:
    """Walk a synthetic packet stream and emit one feature row per closed window.

    §4c.A redo: `window_fn(rng, hard)` is called once per window and returns
    `(dst_fn, src_fn, size_fn, pps)` for that window. Drawing the regime
    parameters per window rather than per case is what gives each class its
    within-class variance; `hard` marks the ~5% of windows drawn toward a
    neighbouring class (see OVERLAP NOTES in the module docstring).
    """
    n_windows = n_packets // WINDOW
    rows: list[tuple[list[float], str]] = []
    for _ in range(n_windows):
        hard = rng.random() < HARD_CASE_RATE
        dst_fn, src_fn, size_fn, pps = window_fn(rng, hard)
        dsts = [dst_fn(rng) for _ in range(WINDOW)]
        srcs = [src_fn(rng) for _ in range(WINDOW)]
        sizes = [size_fn(rng) for _ in range(WINDOW)]
        features = _window_features(dsts, srcs, sizes, pps=pps)
        rows.append((_apply_noise(features, rng), label))
    return rows


# ----------------------------------------------------------------------
# Per-window regime draws (§4c.A redo items 1-3)
#
# Each _window_* function returns (dst_fn, src_fn, size_fn, pps) for a single
# window. `hard` selects the atypical branch that pushes this window toward a
# structurally similar class.
# ----------------------------------------------------------------------
def _skewed_int(rng: random.Random, low: int, high: int, skew: float = 2.5) -> int:
    """Draw an int in [low, high], skewed toward `low` (skew > 1)."""
    return low + int(round((high - low) * (rng.random() ** skew)))


def _victim_dst_fn(rng: random.Random):
    """Destination draw for the three single-victim attack classes.

    Usually the one victim, but a minority of windows spill onto one or two
    neighbouring hosts: a real campaign against a /24 rarely lands every packet
    on exactly one address, and holding unique_dst_count at a constant 1.0 for
    a whole class hands the classifier a free separator for it (which is what
    tests/test_synth_dataset.py::test_every_class_carries_within_class_variance
    catches).
    """
    if rng.random() < 0.20:
        neighbours = [SINGLE_TARGET] * 8 + [
            f"10.0.0.{rng.choice(list(BENIGN_RANGE))}" for _ in range(rng.randint(1, 2))
        ]
        return lambda r: r.choice(neighbours)
    return lambda r: SINGLE_TARGET


def _pool_ip(prefix: str, index: int) -> str:
    """Map a 1-based pool index onto an IP under `prefix` (a /16 as "a.b").

    Source pools now exceed 254 (SYN's spoof range reaches 300), so the third
    octet has to carry the overflow. Keeping this a pure function of the index
    means the pool size is exactly the parameter drawn for the window; building
    the address from two independent randint calls would silently multiply it.
    """
    return f"{prefix}.{(index - 1) // 254 + 1}.{(index - 1) % 254 + 1}"


def _flood_pps(rng: random.Random) -> float:
    """Draw a per-window rate for one of the three high-rate attack classes.

    Mostly a spread around the historical 250000, but FLOOD_THROTTLED_RATE of
    windows are throttled into the hundreds-to-low-thousands band where BENIGN
    and SLOWLORIS also live. See FLOOD_THROTTLED_RATE for why.
    """
    if rng.random() < FLOOD_THROTTLED_RATE:
        return rng.uniform(*FLOOD_THROTTLED_PPS)
    return PPS * rng.uniform(*FLOOD_PPS_RANGE)


def _window_benign(rng: random.Random, hard: bool):
    """Benign traffic, widest variance of any class.

    Source-pool size, destination spread, packet-size mix and rate all vary
    window to window so the class spans a range of legitimate shapes rather
    than one point. The hard branch is a narrow-destination burst (a backup
    job or a busy single server), which reaches toward the flood classes on
    entropy_dst.
    """
    src_pool = rng.randint(8, 254)
    quiet = rng.random() < BENIGN_QUIET_RATE
    if hard:
        # Concentrated benign: a handful of clients talking to one or two
        # servers at a low rate. On entropy_dst, unique_src_count and pps this
        # is the same shape as a slow-loris window; the packet-size mix is the
        # only thing left to tell them apart.
        # Single destination, small client pool, low rate: on entropy_dst,
        # unique_dst_count, top_dst_frequency, unique_src_count and pps this is
        # indistinguishable from slow-loris, and the packet-size mix is the
        # only remaining separator. Without this branch, unique_dst_count > 1
        # is a perfect BENIGN gate and the class scores 1.0 by construction.
        dst_hosts = [rng.choice(list(BENIGN_RANGE))]
        src_pool = rng.randint(4, 25)
        quiet = True
        # Small, uniform payloads: a keep-alive-heavy application session.
        # Drawing from BENIGN_PACKET_SIZES here would leave packet_size_std_dev
        # as a perfect BENIGN/SLOWLORIS separator even after every other
        # feature has been made to overlap.
        sizes = list(rng.sample((96, 110, 128, 140, 160, 180), rng.randint(2, 4)))
    else:
        # Sample WITHOUT replacement up to the full host range: a busy benign
        # window should still be able to touch every host on the subnet, which
        # is what the pre-redo generator did every window. Drawing with
        # replacement capped unique_dst_count around 40 and made the widest
        # benign windows unreachable.
        n_hosts = rng.randint(12, len(BENIGN_RANGE))
        dst_hosts = rng.sample(list(BENIGN_RANGE), n_hosts)
        sizes = rng.sample(BENIGN_PACKET_SIZES, rng.randint(2, len(BENIGN_PACKET_SIZES)))
    pps = rng.uniform(*BENIGN_QUIET_PPS) if quiet else PPS * rng.uniform(*BENIGN_PPS_RANGE)
    return (
        lambda r: f"10.0.0.{r.choice(dst_hosts)}",
        lambda r: f"203.0.113.{r.randint(1, max(2, src_pool))}",
        lambda r: r.choice(sizes),
        pps,
    )


def _window_udp_flood(rng: random.Random, hard: bool, random_dst: bool):
    """Volumetric UDP flood: 1-5 attacker sources, skewed hard toward 1.

    The hard branch borrows NTP_AMP's multi-size payload mix, which lifts
    packet_size_std_dev off ~0 and is the main thing separating the two
    classes (see OVERLAP NOTES).
    """
    if hard:
        # Botnet-shaped flood: dozens of bots, and amplification-shaped payloads.
        # Lands squarely inside NTP_AMP's territory on both separating features.
        src_count = rng.randint(18, 70)
    else:
        # 1-5 typical, but the skewed draw is stretched so a minority of
        # windows reach into the low teens, where NTP_AMP's lower tail sits.
        src_count = _skewed_int(rng, 1, 14, skew=2.5)
    srcs = [f"10.0.0.{i}" for i in rng.sample(range(1, 200), src_count)]
    if hard:
        pool = list(NTP_RESPONSE_SIZES)
        size_fn = lambda r: r.choice(pool)  # noqa: E731
    else:
        # Near-fixed size with occasional MTU-driven jitter.
        size_fn = lambda r: (  # noqa: E731
            FLOOD_PACKET_SIZE if r.random() < 0.92 else r.choice((512, 1024, 1470))
        )
    if random_dst:
        dst_fn = lambda r: f"10.0.0.{r.choice(list(BENIGN_RANGE))}"  # noqa: E731
    else:
        dst_fn = _victim_dst_fn(rng)
    return dst_fn, lambda r: r.choice(srcs), size_fn, _flood_pps(rng)


def _window_syn_flood(rng: random.Random, hard: bool):
    """SYN flood: spoofed sources drawn from a per-window pool of 100-300.

    unique_src_count saturates near the 250-packet window ceiling for the large
    pools and drops toward ~90 for the small ones, which is where the class
    starts touching NTP_AMP's upper tail. The hard branch adds TCP option
    jitter so packet_size_std_dev is no longer exactly zero, removing the
    other separator from that pair.
    """
    if hard:
        # Small spoof pool plus option jitter: source cardinality drops into
        # NTP_AMP's band and packet_size_std_dev lifts off zero, removing both
        # separators from that pair at once.
        pool = rng.randint(35, 90)
        sizes = list(SYN_OPTION_SIZES)
        size_fn = lambda r: r.choice(sizes)  # noqa: E731
    else:
        pool = rng.randint(75, 300)
        # A minority of ordinary SYN windows already carry some option jitter;
        # packet_size_std_dev being *exactly* zero was one of the artefacts
        # that made this class trivially separable.
        if rng.random() < 0.25:
            size_fn = lambda r: r.choice((56, 60, 64))  # noqa: E731
        else:
            size_fn = lambda r: (  # noqa: E731
                SYN_PACKET_SIZE if r.random() < 0.97 else r.choice((56, 64))
            )
    return (
        _victim_dst_fn(rng),
        lambda r: _pool_ip("203.0", r.randint(1, pool)),
        size_fn,
        _flood_pps(rng),
    )


def _window_slowloris(rng: random.Random, hard: bool):
    """Slow-loris: rate-limited by design, 6-30 long-lived sources.

    pps is the primary signal, but the hard branch bursts into the low
    thousands, which lands inside BENIGN's quiet band, so rate alone does not
    settle the pair.
    """
    src_count = rng.randint(6, 30)
    if hard:
        # A wider bot pool as well, so unique_src_count lands in the range a
        # small benign application session occupies.
        src_count = rng.randint(10, 40)
        # A busier slow-loris that also spreads across a couple of vhosts on
        # the target and writes larger bodies: rate, destination entropy and
        # size variance all move toward a quiet BENIGN window.
        pps = rng.uniform(*SLOWLORIS_BURST_PPS)
        # Larger request bodies alongside the keep-alives: the size mix starts
        # to look like ordinary web traffic rather than header dribble.
        sizes = list(SLOWLORIS_PACKET_SIZES) + [256, 512, 1024]
        dst_hosts = [SINGLE_TARGET] + [f"10.0.0.{rng.choice(list(BENIGN_RANGE))}" for _ in range(2)]
        dst_fn = lambda r: r.choice(dst_hosts)  # noqa: E731
    else:
        pps = rng.uniform(*SLOWLORIS_PPS_RANGE)
        sizes = rng.sample(SLOWLORIS_PACKET_SIZES, rng.randint(3, len(SLOWLORIS_PACKET_SIZES)))
        dst_fn = _victim_dst_fn(rng)
    return (
        dst_fn,
        lambda r: f"198.51.100.{r.randint(1, src_count)}",
        lambda r: r.choice(sizes),
        pps,
    )


def _window_ntp_amp(rng: random.Random, hard: bool):
    """NTP amplification: reflector pool of 20-80, amplified response sizes.

    Overlaps UDP_FLOOD on rate and destination and SYN_FLOOD on source
    cardinality; packet_size_std_dev is what carries it. The hard branch draws
    a near-uniform response size, flattening that variance and leaving the
    window looking like a plain flood or a SYN flood.
    """
    if hard:
        # Either a large open-resolver pool (reaching up into SYN_FLOOD's
        # cardinality band) or a single dominant reply size that collapses the
        # size variance toward a plain flood. Both remove a separator.
        if rng.random() < 0.5:
            reflectors = rng.randint(90, 160)
            size_fn = lambda r: r.choice(NTP_RESPONSE_SIZES)  # noqa: E731
        else:
            reflectors = rng.randint(3, 12)
            dominant = rng.choice(NTP_RESPONSE_SIZES)
            size_fn = lambda r: (  # noqa: E731
                dominant if r.random() < 0.93 else r.choice(NTP_RESPONSE_SIZES)
            )
    else:
        reflectors = rng.randint(12, 110)
        # A minority of ordinary windows are dominated by one or two reply
        # sizes, which pulls packet_size_std_dev down toward the flood classes
        # without needing the hard-case branch.
        if rng.random() < 0.25:
            pair = rng.sample(NTP_RESPONSE_SIZES, 2)
            size_fn = lambda r: r.choice(pair)  # noqa: E731
        else:
            size_fn = lambda r: r.choice(NTP_RESPONSE_SIZES)  # noqa: E731
    return (
        _victim_dst_fn(rng),
        lambda r: _pool_ip("192.0", r.randint(1, reflectors)),
        size_fn,
        _flood_pps(rng),
    )


def build_dataset(seed: int) -> list[tuple[list[float], str]]:
    """Emit per-window feature rows for all five traffic regimes.

    Each case gets its own RNG (seeded off the base seed) so case ordering
    cannot bleed into another case's draws. Phase 4c appends three attack
    classes; the first three cases keep their original seed offsets so their
    rows are unchanged from Phase 4a.
    """
    rng_b = random.Random(seed)
    rng_u = random.Random(seed + 1)
    rng_r = random.Random(seed + 2)
    rng_s = random.Random(seed + 3)
    rng_l = random.Random(seed + 4)
    rng_n = random.Random(seed + 5)

    benign = _emit_case(rng_b, PACKETS_PER_CASE, _window_benign, BENIGN_LABEL)
    udp_flood = _emit_case(
        rng_u,
        PACKETS_PER_CASE,
        lambda r, h: _window_udp_flood(r, h, random_dst=False),
        "UDP_FLOOD",
    )
    # The Phase 3 headline case, retained as a UDP_FLOOD variant: a tiny source
    # set spraying a broad destination range, so entropy_dst stays high and only
    # the source/size collapses give it away.
    random_dst = _emit_case(
        rng_r,
        PACKETS_PER_CASE,
        lambda r, h: _window_udp_flood(r, h, random_dst=True),
        "UDP_FLOOD",
    )
    # SYN flood: inverts the UDP_FLOOD source signature. Spoofed sources mean
    # high source cardinality and a vanishing top_src_frequency, while the
    # destination side stays pinned to one victim.
    syn_flood = _emit_case(rng_s, PACKETS_PER_CASE, _window_syn_flood, "SYN_FLOOD")
    # Slow-loris: application-layer, rate-limited, few long-lived sources. The
    # pps collapse is the primary discriminator; source cardinality and the
    # small size variance back it up.
    slowloris = _emit_case(rng_l, PACKETS_PER_CASE, _window_slowloris, "SLOWLORIS")
    # NTP amplification: reflected off a modest server pool, so source
    # cardinality sits between slow-loris and SYN. Response sizes vary, which
    # is what separates it from the fixed-size SYN flood.
    ntp_amp = _emit_case(rng_n, PACKETS_PER_CASE, _window_ntp_amp, "NTP_AMP")
    return benign + udp_flood + random_dst + syn_flood + slowloris + ntp_amp


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the synth fallback CSV (Phase 3 §3.E, Phase 4a 10 features).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="RNG seed for deterministic packet draws (default: 42)",
    )
    parser.add_argument(
        "--output",
        default=str(OUTPUT_CSV),
        help=f"output CSV path (default: {OUTPUT_CSV.relative_to(REPO_ROOT)})",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = build_dataset(seed=args.seed)

    # Use io with explicit newline="" + LF terminator so the CSV is byte-identical
    # across Windows/Linux/macOS. csv.writer's default lineterminator is \r\n on
    # Windows otherwise; locking it to \n means re-running on any OS produces
    # the same sha256.
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(HEADER)
    for features, label in rows:
        writer.writerow([f"{v:.10g}" for v in features] + [label])
    output_path.write_text(buf.getvalue(), encoding="utf-8", newline="")

    sha = _sha256(output_path)
    counts = Counter(lbl for _, lbl in rows)
    n_benign = counts[BENIGN_LABEL]
    n_attack = len(rows) - n_benign
    print(f"build_synth_dataset: wrote {output_path}")
    print(f"build_synth_dataset:   rows={len(rows)}  benign={n_benign}  attack={n_attack}")
    per_class = "  ".join(f"{lbl}={counts[lbl]}" for lbl in ALL_LABELS)
    print(f"build_synth_dataset:   per-class: {per_class}")
    print(f"build_synth_dataset:   sha256={sha}")
    print(f"build_synth_dataset:   bytes={output_path.stat().st_size}")
    print(
        "build_synth_dataset: paste the sha256 above into data/README.md "
        "(## Fallback (synth) section, OUTPUT_SAMPLE_SHA256 field)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
