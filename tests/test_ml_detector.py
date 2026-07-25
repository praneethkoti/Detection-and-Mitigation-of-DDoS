"""Unit tests for MLDetector (Phase 3 §3.J, extended in Phase 4a to 10 features).

Parallel structure to test_pca_detector.py: three behavioral assertions on
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


# Phase 4a: 10 features. Added entropy_size at index 2, packet_size_std_dev at index 9.
assert FEATURE_COLS == (
    "entropy_dst",
    "entropy_src",
    "entropy_size",
    "pps",
    "window_packets",
    "unique_src_count",
    "unique_dst_count",
    "top_dst_frequency",
    "top_src_frequency",
    "packet_size_std_dev",
), FEATURE_COLS


def test_rf_recognizes_benign_baseline() -> None:
    rf = _detector()
    # The median benign window from scripts/build_synth_dataset.py at --seed 42.
    # The pre-§4c.A-redo value here ([5.83, 7.11, 2.5, 250000, 250, 156, 63,
    # 0.036, 0.020, 440]) was an idealized "every host, every source, full rate"
    # window that the widened generator no longer produces: it sits outside the
    # benign range on entropy_dst, unique_src_count, unique_dst_count and
    # top_dst_frequency simultaneously. Asserting a model's verdict on a point
    # outside its training distribution tests extrapolation, not recognition.
    feature_vector = [4.887, 6.392, 1.934, 63750.0, 250.0, 114.0, 32.0, 0.056, 0.024, 490.2]
    assert (
        rf.verdict(feature_vector) == "BENIGN"
    ), f"benign signature misclassified ATTACK: proba(ATTACK)={rf.proba(feature_vector):.4f}"


def test_rf_recognizes_single_target_flood() -> None:
    rf = _detector()
    feature_vector = [0.0, 0.0, 0.0, 250000.0, 250.0, 1.0, 1.0, 1.0, 1.0, 0.0]
    assert (
        rf.verdict(feature_vector) == "ATTACK"
    ), f"single-target flood misclassified BENIGN: proba(ATTACK)={rf.proba(feature_vector):.4f}"


def test_rf_flips_random_dst_to_attack() -> None:
    """HEADLINE (parallel to PCA): random_dst → ATTACK despite high dst-IP entropy."""
    rf = _detector()
    feature_vector = [5.79, 0.0, 0.0, 250000.0, 250.0, 1.0, 61.0, 0.036, 1.0, 0.0]
    verdict = rf.verdict(feature_vector)
    proba = rf.proba(feature_vector)
    assert verdict == "ATTACK", (
        f"HEADLINE TEST FAILED: RandomForest did not flip random_dst to ATTACK. "
        f"proba(ATTACK)={proba:.4f} threshold={rf.proba_threshold:.4f}."
    )
