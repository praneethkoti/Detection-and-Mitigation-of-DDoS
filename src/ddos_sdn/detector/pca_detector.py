"""Unsupervised PCA-based anomaly detector (Phase 3 §3.B).

Trains 2D PCA on benign per-window feature vectors, computes Mahalanobis
distance of each new window's projection to the benign cluster centroid,
and flags as ATTACK when the distance exceeds a threshold calibrated at
the 99th percentile of benign training-set distances (the full 80%
benign training portion — not the held-out 20%, which is reserved for F1
evaluation).

Sklearn defaults justified in this docstring (per working agreement #1):
    n_components=2     — matches v3 §4.1 verbatim; 2D is the only dim
                         where the Mahalanobis ellipse is trivially
                         explainable to a reviewer.
    whiten=False       — keep the original variance scale so the
                         Mahalanobis ellipse is interpretable.
    random_state=42    — deterministic fit. Same training data → same
                         pca.joblib bytes.

The 8-feature input vector ordering (must match training):

    [entropy_dst, entropy_src, pps, window_packets,
     unique_src_count, unique_dst_count,
     top_dst_frequency, top_src_frequency]

The headline narrative this detector enables: PCA flips the
random-destination-flood case from BENIGN (entropy-only verdict) to ATTACK,
because the benign cluster centroid lives in a region of high entropy_src
+ high entropy_dst, and random_dst windows sit far from it on the
entropy_src axis even when entropy_dst is high.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
from sklearn.decomposition import PCA

from ddos_sdn.config import load_config

FEATURE_COLS = (
    "entropy_dst",
    "entropy_src",
    "pps",
    "window_packets",
    "unique_src_count",
    "unique_dst_count",
    "top_dst_frequency",
    "top_src_frequency",
)


class PCADetector:
    """Mahalanobis-distance anomaly detector backed by a 2-component PCA."""

    SCHEMA_VERSION = 1

    def __init__(self, model_path: Path | str | None = None) -> None:
        """Load a trained PCADetector from disk.

        For training, construct via `PCADetector.from_components(...)` and call
        `.save(path)`; for inference, pass `model_path` (or rely on the
        config-driven default `detector.pca.model_path`).
        """
        if model_path is None:
            cfg = load_config()
            model_path = cfg["detector"]["pca"]["model_path"]
        model_path = Path(model_path)
        if not model_path.is_absolute():
            # Resolve relative to repo root (parent of src/).
            repo_root = Path(__file__).resolve().parent.parent.parent.parent
            model_path = repo_root / model_path
        if not model_path.is_file():
            raise FileNotFoundError(
                f"PCADetector: model artifact not found at {model_path}. "
                f"Run notebooks/train_pca_and_rf.ipynb to produce it."
            )
        payload = joblib.load(model_path)
        self._validate_payload(payload)
        self.pca: PCA = payload["pca"]
        self.benign_mean: np.ndarray = np.asarray(payload["benign_mean"], dtype=float)
        self.benign_inv_cov: np.ndarray = np.asarray(payload["benign_inv_cov"], dtype=float)
        self.threshold: float = float(payload["threshold"])
        self.feature_cols: tuple[str, ...] = tuple(payload.get("feature_cols", FEATURE_COLS))

    @classmethod
    def from_components(
        cls,
        pca: PCA,
        benign_mean: np.ndarray,
        benign_inv_cov: np.ndarray,
        threshold: float,
        feature_cols: Sequence[str] = FEATURE_COLS,
    ) -> PCADetector:
        """Construct in-memory from training components (used by the notebook)."""
        instance = cls.__new__(cls)
        instance.pca = pca
        instance.benign_mean = np.asarray(benign_mean, dtype=float)
        instance.benign_inv_cov = np.asarray(benign_inv_cov, dtype=float)
        instance.threshold = float(threshold)
        instance.feature_cols = tuple(feature_cols)
        return instance

    @staticmethod
    def _validate_payload(payload: dict) -> None:
        required = {"pca", "benign_mean", "benign_inv_cov", "threshold"}
        missing = required - payload.keys()
        if missing:
            raise ValueError(f"PCADetector: artifact missing keys: {sorted(missing)}")

    def score(self, feature_vector: Sequence[float]) -> float:
        """Mahalanobis distance of `feature_vector` to the benign centroid in PCA space."""
        x = np.asarray(feature_vector, dtype=float).reshape(1, -1)
        if x.shape[1] != len(self.feature_cols):
            raise ValueError(
                f"PCADetector: expected {len(self.feature_cols)} features, got {x.shape[1]}. "
                f"Expected ordering: {self.feature_cols}"
            )
        z = self.pca.transform(x)[0]
        delta = z - self.benign_mean
        # delta @ inv_cov @ delta — guaranteed >= 0; sqrt is the standard
        # Mahalanobis-distance formulation.
        d2 = float(delta @ self.benign_inv_cov @ delta)
        return math.sqrt(max(d2, 0.0))

    def verdict(self, feature_vector: Sequence[float]) -> str:
        """Return "ATTACK" if the Mahalanobis distance exceeds the threshold."""
        return "ATTACK" if self.score(feature_vector) > self.threshold else "BENIGN"

    def save(self, model_path: Path | str) -> None:
        """Persist the detector to disk via joblib (used by the training notebook)."""
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "pca": self.pca,
                "benign_mean": self.benign_mean,
                "benign_inv_cov": self.benign_inv_cov,
                "threshold": self.threshold,
                "feature_cols": list(self.feature_cols),
                "schema_version": self.SCHEMA_VERSION,
            },
            model_path,
            compress=3,
        )
