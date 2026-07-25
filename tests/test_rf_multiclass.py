"""Multi-class RandomForest tests (Phase 4c §4c.G).

Phase 4c widens the trained label set from binary (BENIGN/ATTACK) to five-way
(BENIGN, UDP_FLOOD, SYN_FLOOD, SLOWLORIS, NTP_AMP). Two promises have to hold
simultaneously, and this module locks both:

  1. classify() names the specific attack class.
  2. verdict() stays binary, because the 13-field JSON telemetry contract
     consumes it as verdict_rf and Phase 4c does not widen that schema.

The representative feature vectors below are constructed in-test rather than
loaded from disk, so a corrupted or stale samples/*.csv cannot quietly turn
these assertions green.
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


# Representative per-class vectors, ordered per FEATURE_COLS:
#   [entropy_dst, entropy_src, entropy_size, pps, window_packets,
#    unique_src_count, unique_dst_count, top_dst_frequency,
#    top_src_frequency, packet_size_std_dev]
#
# Values are the per-class MEDIAN window emitted by
# scripts/build_synth_dataset.py at --seed 42. See data/README.md for what each
# class means at the packet level and which features carry its signature.
#
# Median, not mean, and not a hand-written idealized vector (§4c.A redo). Since
# the redo every class draws its parameters from a distribution and neighbouring
# classes deliberately overlap, so a class no longer has a single "typical"
# point that a human can write down correctly. The pre-redo vectors here were
# idealized (UDP_FLOOD with exactly one source, SLOWLORIS at exactly pps=500)
# and stopped matching any region of the data once the classes were widened.
# Taking the coordinate-wise median of the class's actual rows keeps these
# anchored to the generator. Regenerate with:
#
#   python -c "import pandas as pd, numpy as np; df=pd.read_csv(
#       'samples/cicddos2019_sample.csv');
#       print(np.median(df[df.Label=='NTP_AMP'].iloc[:,:10],axis=0))"
#
# These are the class centres, so they are the EASY cases and should classify
# correctly. The hard cases live in the distribution tails and are expected to
# produce the confusion documented in README §Evaluation; asserting on them
# here would be asserting on noise.
BENIGN_VEC = [4.887, 6.392, 1.934, 63750.0, 250.0, 114.0, 32.0, 0.056, 0.024, 490.2]
UDP_FLOOD_VEC = [3.315, 1.925, 0.3893, 165800.0, 250.0, 4.0, 30.5, 0.414, 0.290, 118.0]
SYN_FLOOD_VEC = [0.07834, 6.782, 0.3896, 152000.0, 250.0, 125.0, 1.0, 1.000, 0.024, 0.0]
SLOWLORIS_VEC = [0.1841, 4.273, 2.222, 13.89, 250.0, 21.0, 1.0, 1.000, 0.076, 33.12]
NTP_AMP_VEC = [0.09314, 5.863, 2.176, 139300.0, 250.0, 65.0, 1.0, 1.000, 0.036, 412.3]

ALL_VECS = [
    ("BENIGN", BENIGN_VEC),
    ("UDP_FLOOD", UDP_FLOOD_VEC),
    ("SYN_FLOOD", SYN_FLOOD_VEC),
    ("SLOWLORIS", SLOWLORIS_VEC),
    ("NTP_AMP", NTP_AMP_VEC),
]


def test_every_representative_vector_has_ten_features() -> None:
    """Guard against a vector drifting out of sync with FEATURE_COLS."""
    for name, vec in ALL_VECS:
        assert len(vec) == len(FEATURE_COLS), f"{name} vector has {len(vec)} features"


def test_multiclass_rf_distinguishes_all_four_classes() -> None:
    """HEADLINE (Phase 4c): RF names each attack class AND keeps verdict binary.

    The classify() half is the Phase 4c deliverable: the detector generalizes
    across protocol layers and attack patterns rather than answering one
    yes/no question.

    The verdict() half is the schema guard. If anyone later widens verdict_rf
    to carry a class label, the 13-field JSON contract breaks for every
    downstream consumer, and these five assertions fail loudly here rather
    than silently in a dashboard or a jq pipeline.
    """
    rf = _detector()

    if len(rf.classes_) < 5:
        pytest.skip(
            f"models/rf.joblib is a pre-Phase-4c binary artifact "
            f"(classes_={rf.classes_}); re-run notebooks/train_pca_and_rf.py"
        )

    assert rf.classify(UDP_FLOOD_VEC) == "UDP_FLOOD", (
        f"HEADLINE TEST FAILED: udp_flood classified as " f"{rf.classify(UDP_FLOOD_VEC)!r}"
    )
    assert rf.classify(SYN_FLOOD_VEC) == "SYN_FLOOD", (
        f"HEADLINE TEST FAILED: syn_flood classified as " f"{rf.classify(SYN_FLOOD_VEC)!r}"
    )
    assert rf.classify(SLOWLORIS_VEC) == "SLOWLORIS", (
        f"HEADLINE TEST FAILED: slowloris classified as " f"{rf.classify(SLOWLORIS_VEC)!r}"
    )
    assert rf.classify(NTP_AMP_VEC) == "NTP_AMP", (
        f"HEADLINE TEST FAILED: ntp_amp classified as " f"{rf.classify(NTP_AMP_VEC)!r}"
    )
    assert (
        rf.classify(BENIGN_VEC) == "BENIGN"
    ), f"HEADLINE TEST FAILED: benign classified as {rf.classify(BENIGN_VEC)!r}"

    # Schema stability: verdict() must stay binary for verdict_rf.
    assert rf.verdict(UDP_FLOOD_VEC) == "ATTACK"
    assert rf.verdict(SYN_FLOOD_VEC) == "ATTACK"
    assert rf.verdict(SLOWLORIS_VEC) == "ATTACK"
    assert rf.verdict(NTP_AMP_VEC) == "ATTACK"
    assert rf.verdict(BENIGN_VEC) == "BENIGN"


def test_verdict_only_ever_returns_two_values() -> None:
    """verdict() is binary by contract, whatever classify() reports."""
    rf = _detector()
    seen = {rf.verdict(vec) for _, vec in ALL_VECS}
    assert seen <= {"BENIGN", "ATTACK"}, f"verdict() widened beyond binary: {seen}"


def test_verdict_and_classify_agree_on_benign_vs_attack() -> None:
    """The two APIs must never disagree about whether a window is an attack."""
    rf = _detector()
    for name, vec in ALL_VECS:
        verdict_says_attack = rf.verdict(vec) == "ATTACK"
        classify_says_attack = rf.classify(vec) != "BENIGN"
        assert verdict_says_attack == classify_says_attack, (
            f"{name}: verdict()={rf.verdict(vec)!r} disagrees with "
            f"classify()={rf.classify(vec)!r}"
        )


def test_proba_sums_non_benign_mass() -> None:
    """proba() is P(any attack class), so it must track classify()'s answer."""
    rf = _detector()
    assert 0.0 <= rf.proba(BENIGN_VEC) <= 1.0
    assert rf.proba(BENIGN_VEC) < 0.5, "benign vector should carry little attack mass"
    for name, vec in ALL_VECS:
        if name == "BENIGN":
            continue
        assert rf.proba(vec) >= 0.5, f"{name} should carry majority attack mass"
