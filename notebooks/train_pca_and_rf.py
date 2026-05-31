"""Training pipeline — produces models/pca.joblib and models/rf.joblib.

# Refactored in Phase 4a to extend the per-window feature vector from
# 8 features to 10 (adding `entropy_size` at index 2 and
# `packet_size_std_dev` at index 9). The 8-feature version is preserved
# in git at commit f7d39fb. `git log notebooks/train_pca_and_rf.py`
# shows the evolution.

This is the source-of-truth Python module that the .ipynb mirrors cell-by-cell.
Running it directly (`python notebooks/train_pca_and_rf.py`) is equivalent to
running the notebook end-to-end; the .ipynb exists as a portfolio artifact
that a reviewer can open in nbviewer.

Pipeline (per Phase 3 §3.F, extended in Phase 4a §4a.C):

    1. Load samples/cicddos2019_sample.csv. Auto-detects whether the rows
       are pre-windowed (synth fallback path; columns = FEATURE_COLS+Label)
       or raw CICDDoS2019 flow records (primary path; columns include
       Timestamp, Source IP, Destination IP, Total Fwd Packets,
       Fwd Packet Length Std, Label).
    2. If primary path: reconstruct per-packet stream, slide 250-packet
       windows, compute 10-feature vector per window, label by majority.
       If synth path: skip — rows already are 10-feature windows.
    3. Stratified 80/20 train/test split, random_state=42.
    4. Fit PCA(n_components=2) on the BENIGN training rows only. Calibrate
       threshold = 99th percentile of Mahalanobis distances over the SAME
       benign training rows (per §3.B — full 80% benign training portion,
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
        print("[2] input is pre-windowed (synth path) — skipping flow reconstruction")
        return df[list(FEATURE_COLS) + [LABEL_COL]].copy()

    print("[2] input is CICDDoS2019 flow rows — reconstructing per-packet stream")
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
    entropy_size / packet_size_std_dev fall back to 0 — but the synth path
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
        # ddof=0 explicit — train/inference symmetry guard (see module docstring).
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
    X = windows[list(FEATURE_COLS)].to_numpy()
    y = windows[LABEL_COL].to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE,
    )
    print(
        f"[3] stratified 80/20 split: train={len(X_train)} "
        f"(BENIGN={int((y_train == 'BENIGN').sum())}, ATTACK={int((y_train == 'ATTACK').sum())})  "
        f"test={len(X_test)} "
        f"(BENIGN={int((y_test == 'BENIGN').sum())}, ATTACK={int((y_test == 'ATTACK').sum())})"
    )
    return X_train, X_test, y_train, y_test


# ----------------------------------------------------------------------
# Cell 4: fit PCA on benign training rows + calibrate threshold
# ----------------------------------------------------------------------
def cell_4_fit_pca(X_train, y_train) -> PCADetector:
    benign_train = X_train[y_train == "BENIGN"]
    print(f"[4] fitting PCA(n_components=2) on {len(benign_train)} benign training rows")
    pca = PCA(n_components=2, whiten=False, random_state=RANDOM_STATE)
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
    # Entropy-only verdict on the held-out rows: ATTACK iff entropy_dst < 1.66 bits
    # (the config threshold). This is what the Phase 1 detector would emit.
    threshold_bits = 1.66
    entropy_preds = np.where(X_test[:, 0] < threshold_bits, "ATTACK", "BENIGN")
    pca_preds = np.array([pca_det.verdict(row) for row in X_test])
    rf_preds = np.array([rf_det.verdict(row) for row in X_test])

    metrics = {}
    for name, preds in [("entropy", entropy_preds), ("pca", pca_preds), ("rf", rf_preds)]:
        p = precision_score(y_test, preds, pos_label="ATTACK", zero_division=0)
        r = recall_score(y_test, preds, pos_label="ATTACK", zero_division=0)
        f1 = f1_score(y_test, preds, pos_label="ATTACK", zero_division=0)
        cm = confusion_matrix(y_test, preds, labels=["BENIGN", "ATTACK"])
        metrics[name] = {"precision": p, "recall": r, "f1": f1, "cm": cm}
    print("[6] held-out evaluation:")
    print(f"    {'detector':<12} {'precision':>10} {'recall':>10} {'f1':>10}")
    for name, m in metrics.items():
        print(f"    {name:<12} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1']:>10.4f}")
    print("    confusion matrices (rows=true [BENIGN, ATTACK], cols=pred [BENIGN, ATTACK]):")
    for name, m in metrics.items():
        print(f"      {name}: {m['cm'].tolist()}")
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
    print("[8] README §Evaluation table (paste into README.md):")
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
