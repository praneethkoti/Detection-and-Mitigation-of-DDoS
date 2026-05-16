"""Unit tests for PCADetector (Phase 3 §3.J).

Three behavioral assertions:

1. A clearly-benign 8-feature vector (high entropy_dst, high entropy_src,
   broad source/destination cardinality, low top-frequencies) → BENIGN.
2. A clearly-attack vector matching the udp_flood signature (zero entropies,
   one unique source, one unique destination, top-frequencies pinned to 1.0)
   → ATTACK.
3. **The headline assertion.** A vector matching the random_dst signature
   (high entropy_dst, zero entropy_src, one unique source, broad destinations)
   → ATTACK. This is the case the entropy-only detector reports BENIGN
   (entropy_dst stays above the 1.66-bit threshold); PCA's job is to flip
   that verdict by gating on entropy_src ≈ 0. If this test fails, Phase 3
   has not delivered its narrative.
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


# Feature ordering, repeated here so the tests are self-documenting:
#   [entropy_dst, entropy_src, pps, window_packets,
#    unique_src_count, unique_dst_count,
#    top_dst_frequency, top_src_frequency]
assert FEATURE_COLS == (
    "entropy_dst", "entropy_src", "pps", "window_packets",
    "unique_src_count", "unique_dst_count",
    "top_dst_frequency", "top_src_frequency",
), FEATURE_COLS


def test_pca_recognizes_benign_baseline() -> None:
    """Benign signature: broad distributions on both sides."""
    pca = _detector()
    # Matches build_synth_dataset's benign-row distribution: ~5.8 dst entropy,
    # ~7.1 src entropy, ~156 unique src, ~63 unique dst, low top-frequencies.
    feature_vector = [5.83, 7.11, 250000.0, 250.0, 156.0, 63.0, 0.036, 0.020]
    assert pca.verdict(feature_vector) == "BENIGN", (
        f"benign signature was misclassified ATTACK: score={pca.score(feature_vector):.4f}"
    )


def test_pca_recognizes_single_target_flood() -> None:
    """Single-target flood signature: both entropies collapsed, cardinalities 1."""
    pca = _detector()
    # Matches build_synth_dataset's udp_flood row: zero on both sides, top-freq = 1.0.
    feature_vector = [0.0, 0.0, 250000.0, 250.0, 1.0, 1.0, 1.0, 1.0]
    assert pca.verdict(feature_vector) == "ATTACK", (
        f"single-target flood was misclassified BENIGN: score={pca.score(feature_vector):.4f}"
    )


def test_pca_flips_random_dst_to_attack() -> None:
    """HEADLINE: random_dst flood → ATTACK despite high dst-IP entropy.

    Entropy-only would emit BENIGN here (entropy_dst=5.79 is above the
    1.66-bit threshold). PCA must catch this case by reading entropy_src ≈ 0
    in combination with high entropy_dst. This is the v3 §4.1 promise and
    the project's narrative kernel.
    """
    pca = _detector()
    # Matches build_synth_dataset's random_dst row: high entropy_dst, zero
    # entropy_src, one unique source flooding many destinations, top_src_freq
    # pinned to 1.0 while top_dst_freq stays low.
    feature_vector = [5.79, 0.0, 250000.0, 250.0, 1.0, 61.0, 0.036, 1.0]
    verdict = pca.verdict(feature_vector)
    score = pca.score(feature_vector)
    assert verdict == "ATTACK", (
        f"HEADLINE TEST FAILED: PCA did not flip random_dst to ATTACK. "
        f"score={score:.4f} threshold={pca.threshold:.4f}. "
        f"This is the case the project's whole narrative depends on. "
        f"Investigate the training data, feature ordering, or threshold calibration."
    )
