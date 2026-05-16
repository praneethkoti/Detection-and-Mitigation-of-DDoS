"""Stratified extraction of a tiny CICDDoS2019 sample for demo / CI use.

The Phase 3 PCA + RandomForest training pipeline consumes
samples/cicddos2019_sample.csv. That CSV is **not** committed in Phase 2 —
the user runs this script against their own download of the CICDDoS2019
dataset (see data/README.md) and the resulting file is committed alongside
the Phase 3 training notebook.

Usage:

    python scripts/extract_sample.py path/to/CICDDoS2019.csv samples/cicddos2019_sample.csv

Behavior:
- Reads the full CICDDoS2019 CSV with pandas.
- Requires a ``Label`` column; fails loudly if missing.
- Stratified-samples ~2000 rows preserving the benign/attack ratio of the source.
- Uses numpy.random.default_rng(seed) for index draws — byte-identical output
  across machines and OSes given the same input file + same --rows + same --seed.
  (pandas.DataFrame.sample(random_state=...) has had cross-version drift; the
   default_rng path is the more durable contract.)
- Prints sha256 of both the input and the output CSV on completion so the
  values can be pasted into data/README.md verbatim.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import numpy as np
import pandas as pd

LABEL_COLUMN = "Label"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stratified_sample(df: pd.DataFrame, n_rows: int, seed: int) -> pd.DataFrame:
    """Return a stratified sample of ~n_rows rows, preserving Label ratios.

    Per-group quota is round(n_rows * group_proportion). Within each group
    we pick row indices via numpy.random.default_rng(seed) — deterministic
    across pandas versions and OS.
    """
    rng = np.random.default_rng(seed)
    total = len(df)
    parts: list[pd.DataFrame] = []
    for _label, group in df.groupby(LABEL_COLUMN, sort=True):
        proportion = len(group) / total
        take = max(1, int(round(n_rows * proportion)))
        take = min(take, len(group))
        chosen_positions = np.sort(rng.choice(len(group), size=take, replace=False))
        parts.append(group.iloc[chosen_positions])
    sample = pd.concat(parts, ignore_index=False)
    # Re-sort by original row order so the output is reproducible regardless of
    # the groupby iteration order.
    return sample.sort_index()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Stratified extraction of a CICDDoS2019 sample for demo / CI use.",
    )
    parser.add_argument("input_csv", help="path to a full CICDDoS2019 per-attack-class CSV")
    parser.add_argument("output_csv", help="path to write the stratified sample")
    parser.add_argument(
        "--rows", type=int, default=2000,
        help="approximate number of rows in the output sample (default: 2000)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="RNG seed for reproducible row selection (default: 42)",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    input_path = Path(args.input_csv)
    output_path = Path(args.output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_path.is_file():
        print(f"extract_sample: input file not found: {input_path}", file=sys.stderr)
        return 2
    if args.rows <= 0:
        print("extract_sample: --rows must be > 0", file=sys.stderr)
        return 2

    df = pd.read_csv(input_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]  # CICDDoS2019 ships some leading spaces
    if LABEL_COLUMN not in df.columns:
        print(
            f"extract_sample: input file is missing the required '{LABEL_COLUMN}' column. "
            f"Got columns: {list(df.columns)[:10]}...",
            file=sys.stderr,
        )
        return 2

    sample = stratified_sample(df, n_rows=args.rows, seed=args.seed)
    sample.to_csv(output_path, index=False)

    input_sha = _sha256(input_path)
    output_sha = _sha256(output_path)

    print(f"extract_sample: read   {input_path}  sha256={input_sha}  rows={len(df)}")
    print(f"extract_sample: wrote  {output_path}  sha256={output_sha}  rows={len(sample)}")
    print(
        "extract_sample: paste both sha256 values into data/README.md under "
        "EXPECTED_SOURCE_SHA256 and EXPECTED_SAMPLE_SHA256."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
