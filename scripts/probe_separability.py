"""Separability probes for the synth dataset (Phase 4c §4c.A redo).

The first cut of scripts/build_synth_dataset.py produced five classes that a
RandomForest separated at macro F1 = 1.0000. That number was not evidence of
detector quality: the generator had pinned each class to fixed parameter
values, so the classes were disjoint point-clouds and any classifier would
score 1.0. The failure mode is invisible in the F1 alone, which is why these
probes exist as a committed script rather than as a one-off analysis.

Run after regenerating the dataset or retraining:

    python scripts/probe_separability.py

Four probes, each answering "is the reported F1 measuring the detector or the
generator?":

  1. SPREAD RATIO. Mean within-class spread against the minimum inter-class
     centroid distance, both in z-units over the whole dataset. If classes are
     tight blobs far apart (ratio well below 1), the task is trivial. Target
     is a ratio near or above 1: within-class variation comparable to the
     distance between classes.

  2. DEPTH-3 TREE. A decision tree limited to three splits. If it matches the
     full forest, the classes are separable by a handful of axis-aligned cuts
     and the forest's capacity is doing nothing. Target is a materially lower
     score than the RF, with both below 1.0.

  3. FEATURE ABLATION. Retrain with each feature dropped in turn. A class that
     survives every ablation unchanged is over-determined; a dataset where one
     feature's removal collapses the score is relying on a single artefact.

  4. NOISE ROBUSTNESS. Two variants, and the difference between them matters.
     The §4c.A redo brief asked for the multiplicative one; this script reports
     it but treats the additive one as the headline, and prints both so the
     substitution is auditable rather than hidden. See the long comment above
     the probe-4 block for the full reasoning.

       - multiplicative (x U[0.7, 1.3], the "+/-30%" probe): scales each
         feature proportionally. On THIS feature space it is close to
         useless, and reporting it without the caveat is misleading. The
         classes are separated by ratios spanning orders of magnitude (pps
         runs from ~13 for slow-loris to ~1.5e5 for a flood), and scaling a
         value by 30% cannot move it across a 4-decade gap. It reported a
         0.000 drop on the trivially-separable original dataset and 0.015 on
         this one, so it does not distinguish easy from hard.

       - additive Gaussian at k * per-feature sigma: perturbs each feature by
         a fraction of its own spread, so a class boundary that is narrow
         relative to the feature's own variation actually gets crossed. This
         is the variant that discriminates, and it is the one to read: 0.135
         macro F1 lost at k=0.10 on the committed dataset.

Exit status is always 0: this is a reporting tool, not a gate. The gates are
in tests/test_synth_dataset.py.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
from ddos_sdn.detector.features import FEATURE_COLS  # noqa: E402

SAMPLE_CSV = REPO_ROOT / "samples" / "cicddos2019_sample.csv"
LABEL_COL = "Label"
RANDOM_STATE = 42


def _fit(X_train, y_train) -> RandomForestClassifier:
    rf = RandomForestClassifier(
        n_estimators=100,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )
    rf.fit(X_train, y_train)
    return rf


def main() -> int:
    if not SAMPLE_CSV.is_file():
        print(f"probe: {SAMPLE_CSV} not found; run scripts/build_synth_dataset.py first")
        return 0
    df = pd.read_csv(SAMPLE_CSV)
    X = df[list(FEATURE_COLS)].to_numpy()
    y = df[LABEL_COL].to_numpy()
    labels = sorted(set(y))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE
    )
    rf = _fit(X_train, y_train)
    base = f1_score(y_test, rf.predict(X_test), average="macro", zero_division=0)
    print(f"probe: RF macro F1 = {base:.4f}  ({len(X_train)} train / {len(X_test)} test)")

    # 1. spread ratio ---------------------------------------------------
    sigma = np.where(X.std(axis=0) == 0, 1.0, X.std(axis=0))
    Z = (X - X.mean(axis=0)) / sigma
    centroids = {lbl: Z[y == lbl].mean(axis=0) for lbl in labels}
    spreads = {
        lbl: float(np.mean(np.linalg.norm(Z[y == lbl] - centroids[lbl], axis=1))) for lbl in labels
    }
    max_spread = max(spreads.values())
    min_dist = min(
        float(np.linalg.norm(centroids[a] - centroids[b]))
        for a, b in itertools.combinations(labels, 2)
    )
    print()
    print("probe 1: spread ratio (want ~1.0 or above; well below 1 means trivial)")
    print(f"    max within-class spread      = {max_spread:.2f} z-units")
    print(f"    min inter-class centroid gap = {min_dist:.2f} z-units")
    print(f"    ratio                        = {max_spread / min_dist:.2f}")

    # 2. depth-3 tree ---------------------------------------------------
    shallow = DecisionTreeClassifier(max_depth=3, random_state=RANDOM_STATE)
    shallow.fit(X_train, y_train)
    shallow_f1 = f1_score(y_test, shallow.predict(X_test), average="macro", zero_division=0)
    print()
    print("probe 2: depth-3 tree (want materially below RF, and both below 1.0)")
    print(f"    depth-3 macro F1 = {shallow_f1:.4f}   vs RF {base:.4f}")

    # 3. feature ablation ------------------------------------------------
    print()
    print("probe 3: feature ablation (macro F1 with each feature dropped)")
    for idx, col in enumerate(FEATURE_COLS):
        keep = [i for i in range(len(FEATURE_COLS)) if i != idx]
        ablated = _fit(X_train[:, keep], y_train)
        f1 = f1_score(y_test, ablated.predict(X_test[:, keep]), average="macro", zero_division=0)
        print(f"    without {col:<22} {f1:.4f}   ({f1 - base:+.4f})")

    # 4. noise robustness -------------------------------------------------
    #
    # WHY BOTH VARIANTS ARE HERE, AND WHY THE HEADLINE ONE CHANGED.
    #
    # The §4c.A redo brief set a target of "+/-30% multiplicative noise should
    # drop RF's macro F1 by at least 0.05". That target cannot be met on this
    # feature space, and the reason is a property of the features rather than a
    # property of the dataset's difficulty:
    #
    #   Multiplicative noise scales every feature proportionally, so it moves a
    #   value by a fraction of ITSELF. The classes here are separated on `pps`
    #   by ratios spanning four decades (slow-loris sits near 13 pps, a flood
    #   near 1.5e5). Multiplying either by anything in [0.7, 1.3] leaves it
    #   nowhere near the other. The probe therefore reports a near-zero drop
    #   whether the classes are trivially separable or genuinely hard: it read
    #   0.000 on the original point-cloud dataset and 0.015 on this one. A
    #   metric that returns the same answer for a trivial and a hard dataset is
    #   not measuring difficulty.
    #
    # Additive Gaussian noise at k * each feature's OWN standard deviation is
    # the variant that discriminates. It moves each feature by a fraction of
    # that feature's spread across the data, so a class boundary that is narrow
    # relative to the feature's own variation actually gets crossed. On this
    # dataset it costs 0.135 macro F1 at k=0.10, which is the fragility the
    # original target was trying to detect.
    #
    # Both are printed. The multiplicative row is kept rather than deleted so
    # the substitution is visible and auditable: a reader who goes looking for
    # the number the brief asked for finds it, next to the reason it is not the
    # number to read. Deleting it would hide the deviation.
    rng = np.random.default_rng(7)
    print()
    print("probe 4: noise robustness")
    mult = [
        f1_score(
            y_test,
            rf.predict(X_test * rng.uniform(0.7, 1.3, size=X_test.shape)),
            average="macro",
            zero_division=0,
        )
        for _ in range(8)
    ]
    mult_mean = float(np.mean(mult))
    print(f"    multiplicative +/-30%   {mult_mean:.4f}   (drop {base - mult_mean:+.4f})")
    print("      ^ near-zero drop is EXPECTED here and is not evidence of robustness:")
    print("        classes are separated by order-of-magnitude ratios that a 30%")
    print("        rescale cannot cross. Read the additive rows below instead.")
    for k in (0.10, 0.25, 0.50):
        vals = [
            f1_score(
                y_test,
                rf.predict(X_test + rng.normal(0.0, k * sigma, size=X_test.shape)),
                average="macro",
                zero_division=0,
            )
            for _ in range(8)
        ]
        mean = float(np.mean(vals))
        print(f"    additive {k:.2f} sigma       {mean:.4f}   (drop {base - mean:+.4f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
