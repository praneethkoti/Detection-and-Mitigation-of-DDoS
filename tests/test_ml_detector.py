"""Unit tests for MLDetector (Phase 3 §3.J).

Parallel structure to test_pca_detector.py — three behavioral assertions on
the trained RandomForestClassifier, including the headline random_dst flip.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ddos_sdn.detector.ml_detector import FEATURE_COLS, MLDetector

REPO_ROOT = Path(__file__).resolve().parent.parent
RF_PATH = REPO_ROOT / "models" / "rf.joblib"


def _detector() -> MLDetector:
    if not RF_PATH.is_file():
        pytest.skip(f"models/rf.joblib not present at {RF_PATH}; run the training notebook first")
    return MLDetector(model_path=RF_PATH)


assert FEATURE_COLS == (
    "entropy_dst", "entropy_src", "pps", "window_packets",
    "unique_src_count", "unique_dst_count",
    "top_dst_frequency", "top_src_frequency",
), FEATURE_COLS


def test_rf_recognizes_benign_baseline() -> None:
    rf = _detector()
    feature_vector = [5.83, 7.11, 250000.0, 250.0, 156.0, 63.0, 0.036, 0.020]
    assert rf.verdict(feature_vector) == "BENIGN", (
        f"benign signature misclassified ATTACK: proba(ATTACK)={rf.proba(feature_vector):.4f}"
    )


def test_rf_recognizes_single_target_flood() -> None:
    rf = _detector()
    feature_vector = [0.0, 0.0, 250000.0, 250.0, 1.0, 1.0, 1.0, 1.0]
    assert rf.verdict(feature_vector) == "ATTACK", (
        f"single-target flood misclassified BENIGN: proba(ATTACK)={rf.proba(feature_vector):.4f}"
    )


def test_rf_flips_random_dst_to_attack() -> None:
    """HEADLINE (parallel to PCA): random_dst → ATTACK despite high dst-IP entropy."""
    rf = _detector()
    feature_vector = [5.79, 0.0, 250000.0, 250.0, 1.0, 61.0, 0.036, 1.0]
    verdict = rf.verdict(feature_vector)
    proba = rf.proba(feature_vector)
    assert verdict == "ATTACK", (
        f"HEADLINE TEST FAILED: RandomForest did not flip random_dst to ATTACK. "
        f"proba(ATTACK)={proba:.4f} threshold={rf.proba_threshold:.4f}."
    )
