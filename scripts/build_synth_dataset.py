"""Synth dataset builder (Phase 3 §3.E fallback path).

When the UNB CICDDoS2019 download isn't available at Phase 3 execution time,
this script produces samples/cicddos2019_sample.csv with the same column shape
the real-data extract_sample.py path would produce — 8 feature columns plus
a Label column — but with the rows derived from the project's own three smoke
generators scaled up.

Three traffic regimes, ~10,000 packets each (40 windows per case at window=250):

    Case 1  benign baseline           Label = "BENIGN"
            uniform 10.0.0.[2..64] dst, random 203.0.113.x src

    Case 2  single-target flood       Label = "ATTACK"
            all 10.0.0.64 dst, src=10.0.0.1

    Case 3  random-destination flood  Label = "ATTACK"   <-- the headline case
            uniform 10.0.0.[2..64] dst, src=10.0.0.1
            (entropy reports BENIGN; PCA must learn ATTACK from entropy_src ~ 0)

The 8-feature vector matches the §3.B contract exactly:

    [entropy_dst, entropy_src, pps, window_packets,
     unique_src_count, unique_dst_count,
     top_dst_frequency, top_src_frequency]

Determinism: same --seed produces a byte-identical CSV across machines and
OSes. RNGs are scoped per-case so case ordering can't bleed.

Usage:

    python scripts/build_synth_dataset.py --seed 42

Writes samples/cicddos2019_sample.csv and prints its sha256 so the value
can be pasted into data/README.md's ## Fallback (synth) section.

This script is the documented Phase 3 fallback per §3.E. If/when real
CICDDoS2019 data becomes available, regenerate samples/cicddos2019_sample.csv
via scripts/extract_sample.py and re-run notebooks/train_pca_and_rf.ipynb;
no other code changes needed.
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

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"
OUTPUT_CSV = SAMPLES_DIR / "cicddos2019_sample.csv"

WINDOW = 250
PACKETS_PER_CASE = 10000  # 40 windows per case at window=250
BENIGN_RANGE = range(2, 65)  # 10.0.0.[2..64]
SINGLE_TARGET = "10.0.0.64"
ATTACKER_SRC = "10.0.0.1"

FEATURE_COLS = (
    "entropy_dst",
    "entropy_src",
    "pps",
    "window_packets",
    "unique_src_count",
    "unique_dst_count",
    "top_dst_frequency",
    "top_src_frequency",
)
LABEL_COL = "Label"
HEADER = list(FEATURE_COLS) + [LABEL_COL]

# Constant synthetic pps; same value the runtime EntropyAnalyzer reports
# at 1ms/packet (250 packets / 0.001s = 250000), so the feature distribution
# at training matches what the runtime emits at inference.
PPS = 250000


def _shannon_bits(counter: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for c in counter.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _window_features(dsts: list[str], srcs: list[str]) -> list[float]:
    """Compute the 8-feature vector for one closed window."""
    n = len(dsts)
    dst_counts = Counter(dsts)
    src_counts = Counter(srcs)
    top_dst_count = dst_counts.most_common(1)[0][1]
    top_src_count = src_counts.most_common(1)[0][1]
    return [
        _shannon_bits(dst_counts, n),  # entropy_dst
        _shannon_bits(src_counts, n),  # entropy_src
        float(PPS),  # pps
        float(n),  # window_packets
        float(len(src_counts)),  # unique_src_count
        float(len(dst_counts)),  # unique_dst_count
        top_dst_count / n,  # top_dst_frequency
        top_src_count / n,  # top_src_frequency
    ]


def _emit_case(
    rng: random.Random,
    n_packets: int,
    dst_fn,
    src_fn,
    label: str,
) -> list[tuple[list[float], str]]:
    """Walk a synthetic packet stream and emit one feature row per closed window."""
    dsts: list[str] = []
    srcs: list[str] = []
    rows: list[tuple[list[float], str]] = []
    for _ in range(n_packets):
        dsts.append(dst_fn(rng))
        srcs.append(src_fn(rng))
        if len(dsts) >= WINDOW:
            rows.append((_window_features(dsts, srcs), label))
            dsts.clear()
            srcs.clear()
    return rows


def build_dataset(seed: int) -> list[tuple[list[float], str]]:
    rng_b = random.Random(seed)
    rng_u = random.Random(seed + 1)
    rng_r = random.Random(seed + 2)

    benign = _emit_case(
        rng_b,
        PACKETS_PER_CASE,
        dst_fn=lambda r: f"10.0.0.{r.choice(list(BENIGN_RANGE))}",
        src_fn=lambda r: f"203.0.113.{r.randint(1, 254)}",
        label="BENIGN",
    )
    udp_flood = _emit_case(
        rng_u,
        PACKETS_PER_CASE,
        dst_fn=lambda r: SINGLE_TARGET,
        src_fn=lambda r: ATTACKER_SRC,
        label="ATTACK",
    )
    random_dst = _emit_case(
        rng_r,
        PACKETS_PER_CASE,
        dst_fn=lambda r: f"10.0.0.{r.choice(list(BENIGN_RANGE))}",
        src_fn=lambda r: ATTACKER_SRC,
        label="ATTACK",
    )
    return benign + udp_flood + random_dst


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the synth fallback CSV for Phase 3 (per §3.E).",
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
    n_benign = sum(1 for _, lbl in rows if lbl == "BENIGN")
    n_attack = len(rows) - n_benign
    print(f"build_synth_dataset: wrote {output_path}")
    print(f"build_synth_dataset:   rows={len(rows)}  benign={n_benign}  attack={n_attack}")
    print(f"build_synth_dataset:   sha256={sha}")
    print(f"build_synth_dataset:   bytes={output_path.stat().st_size}")
    print(
        "build_synth_dataset: paste the sha256 above into data/README.md "
        "(## Fallback (synth) section, OUTPUT_SAMPLE_SHA256 field)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
