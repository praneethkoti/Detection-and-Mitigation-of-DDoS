"""Synth dataset builder smoke tests (Phase 4c §4c.G).

scripts/build_synth_dataset.py is the fallback path that produces
samples/cicddos2019_sample.csv when the real CICDDoS2019 download isn't
available. Phase 4c widened it from three regimes to six (five labels;
UDP_FLOOD covers both the single-target and random-destination variants).

The load-bearing assertion in this module is pairwise distinguishability. If
two attack classes collapse onto the same per-window feature signature, the
multi-class RF cannot separate them, macro F1 falls apart, and the Phase 4c
story fails. That failure would otherwise surface as a confusing RF metric
rather than as a dataset problem, so it is asserted directly here.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "src"))

from build_synth_dataset import (  # noqa: E402
    ALL_LABELS,
    ATTACK_LABELS,
    BENIGN_LABEL,
    PACKETS_PER_CASE,
    WINDOW,
    build_dataset,
)

from ddos_sdn.detector.features import FEATURE_COLS  # noqa: E402

SEED = 42
WINDOWS_PER_CASE = PACKETS_PER_CASE // WINDOW


def _rows():
    return build_dataset(seed=SEED)


def _means_by_label(rows) -> dict[str, list[float]]:
    buckets: dict[str, list[list[float]]] = {}
    for features, label in rows:
        buckets.setdefault(label, []).append(features)
    return {
        label: [sum(col) / len(col) for col in zip(*vectors, strict=True)]
        for label, vectors in buckets.items()
    }


def test_every_class_emits_labeled_rows() -> None:
    rows = _rows()
    seen = {label for _, label in rows}
    assert seen == set(ALL_LABELS), f"label set drift: expected {set(ALL_LABELS)}, got {seen}"
    for label in ALL_LABELS:
        count = sum(1 for _, lbl in rows if lbl == label)
        assert count > 0, f"{label} produced no rows"


def test_every_row_has_the_full_feature_vector() -> None:
    rows = _rows()
    assert rows, "builder produced no rows at all"
    for features, label in rows:
        assert len(features) == len(
            FEATURE_COLS
        ), f"{label} row has {len(features)} features, expected {len(FEATURE_COLS)}"
        assert all(isinstance(v, float) for v in features), f"{label} row has non-float values"


def test_row_counts_match_windows_per_case() -> None:
    """Six cases at WINDOWS_PER_CASE windows each; UDP_FLOOD spans two of them."""
    rows = _rows()
    counts = {label: sum(1 for _, lbl in rows if lbl == label) for label in ALL_LABELS}
    assert counts[BENIGN_LABEL] == WINDOWS_PER_CASE
    assert (
        counts["UDP_FLOOD"] == 2 * WINDOWS_PER_CASE
    ), "UDP_FLOOD should cover the single-target AND random-destination variants"
    for label in ("SYN_FLOOD", "SLOWLORIS", "NTP_AMP"):
        assert counts[label] == WINDOWS_PER_CASE
    assert len(rows) == 6 * WINDOWS_PER_CASE


def test_builder_is_deterministic_for_a_fixed_seed() -> None:
    """Same seed produces byte-identical rows; the committed sha256 depends on it."""
    assert build_dataset(seed=SEED) == build_dataset(seed=SEED)


def test_attack_classes_are_pairwise_distinguishable() -> None:
    """Every pair of attack classes differs materially on at least one feature.

    Uses a relative margin so the check is scale-free across features whose
    magnitudes span pps (~1e5) down to entropy (~1e0).
    """
    means = _means_by_label(_rows())
    margin = 0.15
    for a, b in itertools.combinations(ATTACK_LABELS, 2):
        separating = []
        for idx, col in enumerate(FEATURE_COLS):
            x, y = means[a][idx], means[b][idx]
            scale = max(abs(x), abs(y), 1e-9)
            if abs(x - y) / scale > margin:
                separating.append(col)
        assert separating, (
            f"{a} and {b} are indistinguishable in the 10-feature space. "
            f"Multi-class RF cannot separate them and macro F1 will collapse. "
            f"Revisit the generator parameters for these two classes."
        )


def test_every_attack_class_is_distinguishable_from_benign() -> None:
    """Each attack class must differ from the benign baseline somewhere."""
    means = _means_by_label(_rows())
    benign = means[BENIGN_LABEL]
    for label in ATTACK_LABELS:
        vec = means[label]
        separating = [
            col
            for idx, col in enumerate(FEATURE_COLS)
            if abs(vec[idx] - benign[idx]) / max(abs(vec[idx]), abs(benign[idx]), 1e-9) > 0.15
        ]
        assert separating, f"{label} is indistinguishable from {BENIGN_LABEL}"


def test_slowloris_is_the_only_low_rate_class() -> None:
    """pps is slow-loris's primary discriminator (Phase 4c §4c.A).

    Before Phase 4c every row carried pps=250000, so the feature was inert.
    If this regresses, slow-loris loses its strongest signal and collapses
    toward the other single-target classes.

    Asserted on the mean, not the range: since the §4c.A redo the ranges
    deliberately touch (a quiet BENIGN window and a bursting SLOWLORIS window
    occupy the same band, per test_designed_overlaps_actually_overlap). The
    class centres must still be an order of magnitude apart.
    """
    means = _means_by_label(_rows())
    pps_idx = FEATURE_COLS.index("pps")
    slowloris_pps = means["SLOWLORIS"][pps_idx]
    for label in ALL_LABELS:
        if label == "SLOWLORIS":
            continue
        assert means[label][pps_idx] > slowloris_pps * 10, (
            f"{label} pps={means[label][pps_idx]} is not clearly above "
            f"SLOWLORIS pps={slowloris_pps}"
        )


# ----------------------------------------------------------------------
# §4c.A redo: the classes must be HARD, not just distinguishable.
#
# test_attack_classes_are_pairwise_distinguishable above is a floor: classes
# must not collapse into each other. The tests below are the matching ceiling:
# classes must not be trivially separable either. Without them, a future change
# that re-pins a class to a fixed parameter value would sail through the suite
# while quietly restoring the macro F1 = 1.0000 artifact the redo removed.
# ----------------------------------------------------------------------
def _ranges_by_label(rows, feature: str) -> dict[str, tuple[float, float]]:
    idx = FEATURE_COLS.index(feature)
    buckets: dict[str, list[float]] = {}
    for features, label in rows:
        buckets.setdefault(label, []).append(features[idx])
    return {label: (min(vals), max(vals)) for label, vals in buckets.items()}


def _overlaps(a: tuple[float, float], b: tuple[float, float]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


# The pairs the generator deliberately makes collide, and the feature each pair
# is designed to be inseparable on. Mirrors the OVERLAP NOTES table in
# scripts/build_synth_dataset.py and the table in data/README.md; if those move,
# this list moves with them.
DESIGNED_OVERLAPS = [
    ("UDP_FLOOD", "NTP_AMP", "pps"),
    ("UDP_FLOOD", "NTP_AMP", "packet_size_std_dev"),
    ("SYN_FLOOD", "NTP_AMP", "unique_src_count"),
    ("SLOWLORIS", "BENIGN", "pps"),
    ("SLOWLORIS", "BENIGN", "unique_src_count"),
]


def test_designed_overlaps_actually_overlap() -> None:
    """Each engineered pair must share a value range on its named feature.

    A pair that stops overlapping is a pair the classifier can separate
    perfectly, which is how the first cut of this dataset reached macro F1 =
    1.0000. This asserts the overlap is real rather than documented.
    """
    rows = _rows()
    for a, b, feature in DESIGNED_OVERLAPS:
        ra = _ranges_by_label(rows, feature)[a]
        rb = _ranges_by_label(rows, feature)[b]
        assert _overlaps(ra, rb), (
            f"{a} and {b} no longer overlap on {feature}: "
            f"{a}={ra[0]:.4g}..{ra[1]:.4g}, {b}={rb[0]:.4g}..{rb[1]:.4g}. "
            f"This pair is supposed to be hard; a clean split here means the "
            f"reported macro F1 is measuring the generator again."
        )


def test_no_single_feature_separates_all_classes() -> None:
    """No one feature may split every class pair cleanly.

    If such a feature existed, a depth-N decision stump would solve the whole
    task and the RF's score would say nothing about the feature space.
    """
    rows = _rows()
    for feature in FEATURE_COLS:
        ranges = _ranges_by_label(rows, feature)
        pairs = list(itertools.combinations(sorted(ranges), 2))
        if all(not _overlaps(ranges[a], ranges[b]) for a, b in pairs):
            raise AssertionError(
                f"{feature} separates all {len(ranges)} classes with no overlap "
                f"anywhere. One feature solving the entire task means the "
                f"dataset is trivially separable."
            )


def test_every_class_carries_within_class_variance() -> None:
    """No class may be a fixed point in the feature space.

    The pre-redo generator emitted identical values for several features within
    a class (UDP_FLOOD's unique_src_count was always exactly 1, SLOWLORIS's pps
    always exactly 500). Any feature that is constant within a class is a free
    separator for that class.
    """
    rows = _rows()
    for label in ALL_LABELS:
        vectors = [f for f, lbl in rows if lbl == label]
        constant = [
            col
            for idx, col in enumerate(FEATURE_COLS)
            # window_packets is 250 by construction for every row in every
            # class, so it is a shared constant rather than a per-class one and
            # cannot separate anything.
            if col != "window_packets" and len({v[idx] for v in vectors}) == 1
        ]
        assert not constant, (
            f"{label} has zero within-class variance on {constant}. "
            f"A feature that is constant within a class separates that class "
            f"for free; draw it from a distribution instead."
        )
