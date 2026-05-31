"""Unit tests for PCADetector (Phase 3 §3.J, extended in Phase 4a to 10 features).

Three behavioral assertions:

1. A clearly-benign 10-feature vector (high entropy_dst, high entropy_src,
   moderate entropy_size from a mix of UDP payload sizes, broad source/
   destination cardinality, low top-frequencies, nonzero packet_size_std_dev)
   → BENIGN.
2. A clearly-attack vector matching the udp_flood signature (zero entropies
   including entropy_size, one unique source, one unique destination,
   top-frequencies pinned to 1.0, packet_size_std_dev=0) → ATTACK.
3. **The headline assertion.** A vector matching the random_dst signature
   (high entropy_dst, zero entropy_src, zero entropy_size, one unique source,
   broad destinations, packet_size_std_dev=0) → ATTACK. This is the case the
   entropy-only detector reports BENIGN (entropy_dst stays above the 1.66-bit
   threshold); PCA's job is to flip that verdict by gating on the source-side
   and size-side collapses. If this test fails, the project's narrative
   has regressed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ddos_sdn.detector.pca_detector import FEATURE_COLS, PCADetector

REPO_ROOT = Path(__file__).resolve().parent.parent
PCA_PATH = REPO_ROOT / "models" / "pca.joblib"


def _detector() -> PCADetector:
    if not PCA_PATH.is_file():
        pytest.skip(f"models/pca.joblib not present at {PCA_PATH}; run the training notebook first")
    return PCADetector(model_path=PCA_PATH)


# Feature ordering, repeated here so the tests are self-documenting.
# Phase 4a: 10 features (added entropy_size at index 2, packet_size_std_dev at index 9).
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


def test_pca_recognizes_benign_baseline() -> None:
    """Benign signature: broad distributions on both sides AND nonzero size variance.

    Values match a representative row from samples/cicddos2019_sample.csv
    (the synth dataset PCA was trained on). Std-dev of [64, 128, 256, 512,
    1024, 1500] mix lands around 530 — not 440 — once the weights settle.
    """
    pca = _detector()
    feature_vector = [5.81, 7.06, 2.57, 250000.0, 250.0, 150.0, 62.0, 0.036, 0.02, 531.7]
    assert (
        pca.verdict(feature_vector) == "BENIGN"
    ), f"benign signature was misclassified ATTACK: score={pca.score(feature_vector):.4f}"


def test_pca_recognizes_single_target_flood() -> None:
    """Single-target flood signature: all entropies collapsed, cardinalities 1, fixed size."""
    pca = _detector()
    # udp_flood signature: every packet identical (same dst, same src, same size).
    feature_vector = [0.0, 0.0, 0.0, 250000.0, 250.0, 1.0, 1.0, 1.0, 1.0, 0.0]
    assert (
        pca.verdict(feature_vector) == "ATTACK"
    ), f"single-target flood was misclassified BENIGN: score={pca.score(feature_vector):.4f}"


def test_pca_flips_random_dst_to_attack() -> None:
    """HEADLINE: random_dst flood → ATTACK despite high dst-IP entropy.

    Entropy-only would emit BENIGN here (entropy_dst=5.79 is above the
    1.66-bit threshold). PCA must catch this case by reading entropy_src ≈ 0,
    entropy_size = 0 (single attacker uses one fixed packet size), and
    packet_size_std_dev = 0 in combination with high entropy_dst.
    """
    pca = _detector()
    # random_dst signature: one source, one packet size, broad destinations.
    feature_vector = [5.79, 0.0, 0.0, 250000.0, 250.0, 1.0, 61.0, 0.036, 1.0, 0.0]
    verdict = pca.verdict(feature_vector)
    score = pca.score(feature_vector)
    assert verdict == "ATTACK", (
        f"HEADLINE TEST FAILED: PCA did not flip random_dst to ATTACK. "
        f"score={score:.4f} threshold={pca.threshold:.4f}. "
        f"This is the case the project's whole narrative depends on. "
        f"Investigate the training data, feature ordering, or threshold calibration."
    )
