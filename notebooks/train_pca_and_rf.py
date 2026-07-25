"""Training pipeline: produces models/pca.joblib and models/rf.joblib.

# Refactored in Phase 4a to extend the per-window feature vector from
# 8 features to 10 (adding `entropy_size` at index 2 and
# `packet_size_std_dev` at index 9). The 8-feature version is preserved
# in git at commit f7d39fb. `git log notebooks/train_pca_and_rf.py`
# shows the evolution.

This module is the training pipeline; run it directly with
`python notebooks/train_pca_and_rf.py`. It is structured as numbered cells so
it reads like a notebook, but no .ipynb is committed: the cell functions below
ARE the source of truth. (Phase 4c corrected an earlier claim in this docstring
that an .ipynb mirrored this file cell-by-cell; that artifact was never
committed.)

Phase 4c §4c.D trains RF on a five-way label (BENIGN plus four attack classes)
while PCA stays benign-only unsupervised and binary. See cell_6_evaluate for
the two metric views this produces.

Pipeline (per Phase 3 §3.F, extended in Phase 4a §4a.C and Phase 4c §4c.D):

    1. Load samples/cicddos2019_sample.csv. Auto-detects whether the rows
       are pre-windowed (synth fallback path; columns = FEATURE_COLS+Label)
       or raw CICDDoS2019 flow records (primary path; columns include
       Timestamp, Source IP, Destination IP, Total Fwd Packets,
       Fwd Packet Length Std, Label).
    2. If primary path: reconstruct per-packet stream, slide 250-packet
       windows, compute 10-feature vector per window, label by majority.
       If synth path: skip, rows already are 10-feature windows.
    3. Stratified 80/20 train/test split, random_state=42.
    4. Fit PCA(n_components=2) on the BENIGN training rows only. Calibrate
       threshold = 99th percentile of Mahalanobis distances over the SAME
       benign training rows (per §3.B: the full 80% benign training portion,
       not the held-out 20%).
    5. Fit RandomForestClassifier on the full training split.
    6. Evaluate both on the held-out 20%: precision / recall / F1 +
       confusion matrices.
    7. Save models/pca.joblib and models/rf.joblib.
    8. Print copy-paste-ready F1 block for README §Evaluation.

ddof discipline (Phase 4a): packet_size_std_dev computed via
numpy.std(arr, ddof=0) explicitly. Matches runtime entropy.py and
scripts/build_synth_dataset.py; pandas defaults to ddof=1 which would
break train/inference symmetry. The headline test_pca_flips_random_dst_to_attack
fails if any path drifts.
"""

from __future__ import annotations

import math
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = REPO_ROOT / "samples" / "cicddos2019_sample.csv"
MODELS_DIR = REPO_ROOT / "models"
PCA_PATH = MODELS_DIR / "pca.joblib"
RF_PATH = MODELS_DIR / "rf.joblib"

sys.path.insert(0, str(REPO_ROOT / "src"))
from ddos_sdn.detector.features import FEATURE_COLS  # noqa: E402
from ddos_sdn.detector.ml_detector import MLDetector  # noqa: E402
from ddos_sdn.detector.pca_detector import PCADetector  # noqa: E402

LABEL_COL = "Label"
WINDOW = 250
RANDOM_STATE = 42

# Phase 4c: the CSV's Label column is five-way. PCA is unsupervised and
# benign-only, and the three-detector comparison is a binary question
# ("did it flag this window?"), so both binarize via this helper. RF alone
# consumes the full multi-class label.
BENIGN_LABEL = "BENIGN"
ATTACK_LABEL = "ATTACK"
ATTACK_CLASSES = ("UDP_FLOOD", "SYN_FLOOD", "SLOWLORIS", "NTP_AMP")


def _binarize(y):
    """Map the five-way label to BENIGN/ATTACK for binary metrics."""
    return np.where(y == BENIGN_LABEL, BENIGN_LABEL, ATTACK_LABEL)

# CICDDoS2019 column name → our feature contract. Used in cell_2_to_windows
# for the primary (real-data) path so we read per-flow packet-length stats
# directly from CIC's columns rather than synthesizing them.
CIC_PACKET_LEN_STD_COL = "Fwd Packet Length Std"


# ----------------------------------------------------------------------
# Cell 1: load
# ----------------------------------------------------------------------
def cell_1_load() -> pd.DataFrame:
    if not SAMPLE_CSV.is_file():
        raise FileNotFoundError(
            f"Sample CSV not found: {SAMPLE_CSV}. Run scripts/build_synth_dataset.py "
            f"(Phase 3 §3.E synth fallback) or scripts/extract_sample.py (primary path)."
        )
    df = pd.read_csv(SAMPLE_CSV, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    print(f"[1] loaded {len(df)} rows from {SAMPLE_CSV.relative_to(REPO_ROOT)}")
    print(f"    columns: {list(df.columns)}")
    return df


# ----------------------------------------------------------------------
# Cell 2: detect input shape, reconstruct windows if needed
# ----------------------------------------------------------------------
def cell_2_to_windows(df: pd.DataFrame) -> pd.DataFrame:
    expected_synth = set(FEATURE_COLS) | {LABEL_COL}
    if expected_synth.issubset(df.columns):
        print("[2] input is pre-windowed (synth path), skipping flow reconstruction")
        return df[list(FEATURE_COLS) + [LABEL_COL]].copy()

    print("[2] input is CICDDoS2019 flow rows, reconstructing per-packet stream")
    df_sorted = df.sort_values("Timestamp", kind="stable").reset_index(drop=True)
    dst_stream: list[str] = []
    src_stream: list[str] = []
    label_stream: list[str] = []
    for _, row in df_sorted.iterrows():
        n_pkts = max(1, int(row.get("Total Fwd Packets", 1)))
        src = str(row["Source IP"])
        dst = str(row["Destination IP"])
        label = "ATTACK" if str(row[LABEL_COL]).upper() != "BENIGN" else "BENIGN"
        dst_stream.extend([dst] * n_pkts)
        src_stream.extend([src] * n_pkts)
        label_stream.extend([label] * n_pkts)

    rows: list[dict] = []
    for i in range(0, len(dst_stream) - WINDOW + 1, WINDOW):
        win_dst = dst_stream[i : i + WINDOW]
        win_src = src_stream[i : i + WINDOW]
        win_lbl = label_stream[i : i + WINDOW]
        rows.append({**_features(win_dst, win_src), LABEL_COL: _majority(win_lbl)})
    out = pd.DataFrame(rows, columns=list(FEATURE_COLS) + [LABEL_COL])
    print(f"    reconstructed {len(out)} windows from {len(df)} flow rows")
    return out


def _features(
    dsts: list[str],
    srcs: list[str],
    sizes: list[int] | None = None,
) -> dict[str, float]:
    """Compute the 10-feature row for one window.

    For the synth path (the current Phase 4a default), `sizes` is None and
    entropy_size / packet_size_std_dev fall back to 0, but the synth path
    is pre-windowed, so this helper isn't called there. For the real CIC
    reconstruction path, sizes can be passed if the caller pulled per-flow
    `Fwd Packet Length Std` from CICDDoS2019 rows. ddof=0 explicit.
    """
    n = len(dsts)
    dst_c = Counter(dsts)
    src_c = Counter(srcs)
    top_dst = dst_c.most_common(1)[0][1]
    top_src = src_c.most_common(1)[0][1]
    if sizes:
        size_c = Counter(sizes)
        entropy_size = _shannon(size_c, len(sizes))
        # ddof=0 explicit: train/inference symmetry guard (see module docstring).
        packet_size_std_dev = float(np.std(sizes, ddof=0))
    else:
        entropy_size = 0.0
        packet_size_std_dev = 0.0
    return {
        "entropy_dst": _shannon(dst_c, n),
        "entropy_src": _shannon(src_c, n),
        "entropy_size": entropy_size,
        "pps": 250000.0,
        "window_packets": float(n),
        "unique_src_count": float(len(src_c)),
        "unique_dst_count": float(len(dst_c)),
        "top_dst_frequency": top_dst / n,
        "top_src_frequency": top_src / n,
        "packet_size_std_dev": packet_size_std_dev,
    }


def _shannon(counter: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counter.values():
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def _majority(labels: list[str]) -> str:
    return Counter(labels).most_common(1)[0][0]


# ----------------------------------------------------------------------
# Cell 3: train/test split
# ----------------------------------------------------------------------
def cell_3_split(windows: pd.DataFrame):
    """Stratified 80/20 split over the five-way label (Phase 4c).

    Stratifying on the multi-class label keeps every attack class represented
    in both halves; stratifying on a binarized label would let a whole class
    land entirely in train or entirely in test.
    """
    X = windows[list(FEATURE_COLS)].to_numpy()
    y = windows[LABEL_COL].to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE,
    )

    def _counts(arr) -> str:
        return ", ".join(f"{lbl}={int((arr == lbl).sum())}" for lbl in sorted(set(y)))

    print(f"[3] stratified 80/20 split on the {len(set(y))}-way label")
    print(f"    train={len(X_train)}  ({_counts(y_train)})")
    print(f"    test ={len(X_test)}  ({_counts(y_test)})")
    return X_train, X_test, y_train, y_test


# ----------------------------------------------------------------------
# Cell 4: fit PCA on benign training rows + calibrate threshold
# ----------------------------------------------------------------------
def cell_4_fit_pca(X_train, y_train) -> PCADetector:
    benign_train = X_train[y_train == "BENIGN"]
    print(f"[4] fitting PCA(n_components=2) on {len(benign_train)} benign training rows")
    # StandardScaler ahead of PCA (§4c.A redo). The 10 features span wildly
    # different scales: pps runs to ~3e5 while the entropy features live on
    # [0, 8]. Unscaled, pps carries >99.99% of the variance and PC1 is
    # effectively "pps", which makes the Mahalanobis distance a rate detector
    # rather than a shape detector.
    #
    # This was latent before the §4c.A redo rather than introduced by it: the
    # old generator emitted a constant pps=250000 for every benign row, so the
    # feature had zero variance and could not dominate the fit. Once benign
    # traffic was given a realistic rate distribution, the missing scaling
    # became load-bearing and PCA recall fell to 0.17 until this was added.
    #
    # Wrapped in a Pipeline so the saved artifact still exposes .transform()
    # and PCADetector needs no change: its schema stores whatever object has
    # the transform contract under the "pca" key.
    pca = Pipeline(
        [
            ("scale", StandardScaler()),
            ("pca", PCA(n_components=2, whiten=False, random_state=RANDOM_STATE)),
        ]
    )
    pca.fit(benign_train)
    z = pca.transform(benign_train)
    benign_mean = z.mean(axis=0)
    centered = z - benign_mean
    # 2x2 covariance; add a tiny ridge for numerical stability if a feature is
    # degenerate (e.g. window_packets is constant 250 in our synth dataset).
    cov = np.cov(centered, rowvar=False)
    cov = cov + 1e-9 * np.eye(cov.shape[0])
    inv_cov = np.linalg.inv(cov)
    # Mahalanobis distances over the SAME benign training rows (the full 80%,
    # not the held-out 20%). This is the calibration-split fix from plan review.
    diffs = centered
    dists = np.sqrt(np.einsum("ij,jk,ik->i", diffs, inv_cov, diffs))
    threshold = float(np.percentile(dists, 99))
    print(
        f"    benign_mean={benign_mean.tolist()}  "
        f"threshold={threshold:.4f}  (99th pct of {len(dists)} benign-train distances)"
    )
    return PCADetector.from_components(
        pca=pca,
        benign_mean=benign_mean,
        benign_inv_cov=inv_cov,
        threshold=threshold,
        feature_cols=FEATURE_COLS,
    )


# ----------------------------------------------------------------------
# Cell 5: fit RF on the full training split
# ----------------------------------------------------------------------
def cell_5_fit_rf(X_train, y_train) -> MLDetector:
    print(f"[5] fitting RandomForestClassifier on {len(X_train)} training rows")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )
    rf.fit(X_train, y_train)
    print(f"    classes_={list(rf.classes_)}  oob_score={rf.score(X_train, y_train):.3f} (train)")
    return MLDetector.from_components(rf=rf, proba_threshold=0.5, feature_cols=FEATURE_COLS)


# ----------------------------------------------------------------------
# Cell 6: evaluate on the held-out 20%
# ----------------------------------------------------------------------
def cell_6_evaluate(
    pca_det: PCADetector,
    rf_det: MLDetector,
    X_test,
    y_test,
) -> dict:
    """Held-out evaluation, binary and per-attack-class (Phase 4c §4c.D).

    Two views of the same predictions:

      Binary   all three detectors answer "is this window an attack?". This is
               the Phase 3/4a comparison, preserved so the numbers stay
               comparable across phases.
      Per-class  each detector's recall on each attack class separately. This
               is the Phase 4c story: entropy only catches classes whose
               destination entropy collapses, while RF names the class.
    """
    # Entropy-only verdict on the held-out rows: ATTACK iff entropy_dst < 1.66 bits
    # (the config threshold). This is what the Phase 1 detector would emit.
    threshold_bits = 1.66
    entropy_preds = np.where(X_test[:, 0] < threshold_bits, ATTACK_LABEL, BENIGN_LABEL)
    pca_preds = np.array([pca_det.verdict(row) for row in X_test])
    rf_preds = np.array([rf_det.verdict(row) for row in X_test])
    rf_classes = np.array([rf_det.classify(row) for row in X_test])

    y_binary = _binarize(y_test)

    metrics = {}
    for name, preds in [("entropy", entropy_preds), ("pca", pca_preds), ("rf", rf_preds)]:
        p = precision_score(y_binary, preds, pos_label=ATTACK_LABEL, zero_division=0)
        r = recall_score(y_binary, preds, pos_label=ATTACK_LABEL, zero_division=0)
        f1 = f1_score(y_binary, preds, pos_label=ATTACK_LABEL, zero_division=0)
        cm = confusion_matrix(y_binary, preds, labels=[BENIGN_LABEL, ATTACK_LABEL])
        # Per-attack-class recall: of this class's windows, how many were
        # flagged at all? Precision is not per-class meaningful for the binary
        # detectors, since a false positive belongs to no attack class.
        per_class = {}
        for cls in ATTACK_CLASSES:
            mask = y_test == cls
            if not mask.any():
                per_class[cls] = float("nan")
                continue
            per_class[cls] = float((preds[mask] == ATTACK_LABEL).mean())
        metrics[name] = {
            "precision": p,
            "recall": r,
            "f1": f1,
            "cm": cm,
            "per_class_recall": per_class,
        }

    # RF's multi-class scores: per-class F1 against the true five-way label.
    present = [c for c in ATTACK_CLASSES if (y_test == c).any()]
    rf_class_f1 = f1_score(y_test, rf_classes, labels=present, average=None, zero_division=0)
    metrics["rf"]["per_class_f1"] = dict(zip(present, (float(v) for v in rf_class_f1), strict=True))
    metrics["rf"]["macro_f1"] = float(
        f1_score(y_test, rf_classes, average="macro", zero_division=0)
    )
    metrics["rf"]["multiclass_cm"] = confusion_matrix(
        y_test, rf_classes, labels=[BENIGN_LABEL] + list(present)
    )
    metrics["_labels"] = [BENIGN_LABEL] + list(present)

    print("[6] held-out evaluation (binary: is this window an attack?):")
    print(f"    {'detector':<12} {'precision':>10} {'recall':>10} {'f1':>10}")
    for name in ("entropy", "pca", "rf"):
        m = metrics[name]
        print(f"    {name:<12} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1']:>10.4f}")
    print("    confusion matrices (rows=true [BENIGN, ATTACK], cols=pred [BENIGN, ATTACK]):")
    for name in ("entropy", "pca", "rf"):
        print(f"      {name}: {metrics[name]['cm'].tolist()}")

    print()
    print("    per-attack-class detection rate (recall within each class):")
    header = "      {:<12}".format("detector") + "".join(f"{c:>12}" for c in ATTACK_CLASSES)
    print(header)
    for name in ("entropy", "pca", "rf"):
        cells = "".join(
            f"{metrics[name]['per_class_recall'][c]:>12.4f}" for c in ATTACK_CLASSES
        )
        print(f"      {name:<12}" + cells)

    print()
    print(f"    RF multi-class macro F1: {metrics['rf']['macro_f1']:.4f}")
    print("    RF per-class F1: " + "  ".join(
        f"{c}={v:.4f}" for c, v in metrics["rf"]["per_class_f1"].items()
    ))
    print(f"    RF multi-class confusion (labels={metrics['_labels']}):")
    for row_label, row in zip(
        metrics["_labels"], metrics["rf"]["multiclass_cm"].tolist(), strict=True
    ):
        print(f"      {row_label:<11} {row}")
    return metrics


# ----------------------------------------------------------------------
# Cell 7: save artifacts
# ----------------------------------------------------------------------
def cell_7_save(pca_det: PCADetector, rf_det: MLDetector) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    pca_det.save(PCA_PATH)
    rf_det.save(RF_PATH)
    pca_size = PCA_PATH.stat().st_size
    rf_size = RF_PATH.stat().st_size
    print(f"[7] saved {PCA_PATH.relative_to(REPO_ROOT)}  bytes={pca_size}")
    print(f"    saved {RF_PATH.relative_to(REPO_ROOT)}  bytes={rf_size}")
    if pca_size > 5 * 1024 * 1024 or rf_size > 5 * 1024 * 1024:
        print("    WARNING: artifact size > 5 MB budget")


# ----------------------------------------------------------------------
# Cell 8: print copy-paste-ready F1 block for README
# ----------------------------------------------------------------------
def cell_8_readme(metrics: dict) -> None:
    """Emit the copy-paste-ready README §Evaluation tables (Phase 4c §4c.F)."""
    print("[8] README §Evaluation tables (paste into README.md):")
    print()
    print("Multi-class detection rate (recall within each attack class):")
    print()
    header = "| Detector       | " + " | ".join(f"{c}" for c in ATTACK_CLASSES) + " | Macro F1 |"
    print(header)
    print("|---|" + "---:|" * (len(ATTACK_CLASSES) + 1))
    for name, label in [("entropy", "Entropy-only"), ("pca", "PCA-gated"), ("rf", "RandomForest")]:
        m = metrics[name]
        cells = " | ".join(f"{m['per_class_recall'][c]:.4f}" for c in ATTACK_CLASSES)
        # Macro F1 column: RF reports true multi-class macro F1 over the
        # five-way label. The binary detectors cannot name a class, so they
        # report their binary attack F1, which is the fairest comparable
        # number and is labelled as such in the README prose.
        macro = m["macro_f1"] if "macro_f1" in m else m["f1"]
        print(f"| {label:<14} | {cells} | {macro:.4f} |")
    print()
    print("Binary detection (is this window an attack?):")
    print()
    print("| Detector       | Precision | Recall | F1   |")
    print("|---|---:|---:|---:|")
    for name, label in [("entropy", "Entropy-only"), ("pca", "PCA-gated"), ("rf", "RandomForest")]:
        m = metrics[name]
        print(f"| {label:<14} |  {m['precision']:.4f}   | {m['recall']:.4f} | {m['f1']:.4f} |")


# ----------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------
def main() -> int:
    df = cell_1_load()
    windows = cell_2_to_windows(df)
    X_train, X_test, y_train, y_test = cell_3_split(windows)
    pca_det = cell_4_fit_pca(X_train, y_train)
    rf_det = cell_5_fit_rf(X_train, y_train)
    metrics = cell_6_evaluate(pca_det, rf_det, X_test, y_test)
    cell_7_save(pca_det, rf_det)
    cell_8_readme(metrics)
    return 0


if __name__ == "__main__":
    sys.exit(main())
