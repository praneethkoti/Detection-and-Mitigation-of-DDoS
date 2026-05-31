"""Single source of truth for the per-window feature vector ordering.

Phase 4a §4a.B: extracts FEATURE_COLS into its own module so future feature
additions don't require synchronizing three files (pca_detector.py,
ml_detector.py, notebooks/train_pca_and_rf.py, scripts/build_synth_dataset.py).

The ordering below is the contract every consumer reads. Importing FEATURE_COLS
elsewhere guarantees the training pipeline, the runtime detectors, and the
synth-dataset builder all agree on which column is which.

Evolution:
    Phase 3 (commit f7d39fb): 8 features
        [entropy_dst, entropy_src, pps, window_packets,
         unique_src_count, unique_dst_count,
         top_dst_frequency, top_src_frequency]
    Phase 4a: 10 features (this file)
        Added entropy_size (3rd) and packet_size_std_dev (10th).

ddof discipline: packet_size_std_dev is computed via numpy.std(arr, ddof=0)
at every call site — never via pandas.DataFrame.std() (which defaults to
ddof=1) or sklearn helpers that vary. Train/inference symmetry depends on
this; if any call site drifts to ddof=1, PCA's learned variance mismatches
runtime emission and the headline test_pca_flips_random_dst_to_attack fails.
"""

from __future__ import annotations

FEATURE_COLS: tuple[str, ...] = (
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
)
