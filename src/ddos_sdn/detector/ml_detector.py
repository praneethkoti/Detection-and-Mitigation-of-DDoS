"""Supervised RandomForest detector (Phase 3 §3.C).

`sklearn.ensemble.RandomForestClassifier` trained on the same 8-feature
per-window vectors as `PCADetector`. At inference time, returns P(attack)
via `predict_proba` and converts to a verdict at the configured
`detector.rf.proba_threshold` (default 0.5).

Sklearn defaults justified in this docstring (per working agreement #1):
    n_estimators=100        — sklearn's native default; standard rule-of-
                              thumb for tabular features in the dozens.
    max_depth=None          — no depth cap. The 8-feature space is low-dim
                              and trees won't grow pathologically deep.
    min_samples_split=2,
    min_samples_leaf=1      — sklearn defaults. Permits full granularity
                              on the modest dataset size (~120 rows from
                              the Phase 3 fallback path).
    n_jobs=-1               — parallelize fit across cores; deterministic
                              with random_state set.
    random_state=42         — deterministic fit. Same training data → same
                              rf.joblib bytes.
    class_weight="balanced" — compensates for the benign/attack imbalance
                              in CICDDoS2019 per-class CSVs (and in our
                              synth fallback: 40 BENIGN vs 80 ATTACK).
                              "balanced" sets class weights inversely
                              proportional to class frequencies, so the
                              minority class isn't drowned out.

The 8-feature input ordering (must match PCADetector and the training set):

    [entropy_dst, entropy_src, pps, window_packets,
     unique_src_count, unique_dst_count,
     top_dst_frequency, top_src_frequency]
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

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


class MLDetector:
    """RandomForest-backed supervised attack-class detector."""

    SCHEMA_VERSION = 1

    def __init__(self, model_path: Path | str | None = None) -> None:
        """Load a trained MLDetector from disk."""
        cfg = load_config()
        if model_path is None:
            model_path = cfg["detector"]["rf"]["model_path"]
        model_path = Path(model_path)
        if not model_path.is_absolute():
            repo_root = Path(__file__).resolve().parent.parent.parent.parent
            model_path = repo_root / model_path
        if not model_path.is_file():
            raise FileNotFoundError(
                f"MLDetector: model artifact not found at {model_path}. "
                f"Run notebooks/train_pca_and_rf.ipynb to produce it."
            )
        payload = joblib.load(model_path)
        self._validate_payload(payload)
        self.rf: RandomForestClassifier = payload["rf"]
        self.classes_: list[str] = list(payload["classes_"])
        self.feature_cols: tuple[str, ...] = tuple(payload.get("feature_cols", FEATURE_COLS))
        self.proba_threshold: float = float(
            payload.get("proba_threshold", cfg["detector"]["rf"]["proba_threshold"])
        )
        # Cache the column index of the ATTACK class in predict_proba output.
        if "ATTACK" not in self.classes_:
            raise ValueError(
                f"MLDetector: trained classes_ does not include 'ATTACK': {self.classes_}"
            )
        self._attack_col: int = self.classes_.index("ATTACK")

    @classmethod
    def from_components(
        cls,
        rf: RandomForestClassifier,
        proba_threshold: float = 0.5,
        feature_cols: Sequence[str] = FEATURE_COLS,
    ) -> MLDetector:
        """Construct in-memory from training components (used by the notebook)."""
        instance = cls.__new__(cls)
        instance.rf = rf
        instance.classes_ = [str(c) for c in rf.classes_]
        instance.feature_cols = tuple(feature_cols)
        instance.proba_threshold = float(proba_threshold)
        if "ATTACK" not in instance.classes_:
            raise ValueError(
                f"MLDetector: trained classes_ does not include 'ATTACK': {instance.classes_}"
            )
        instance._attack_col = instance.classes_.index("ATTACK")
        return instance

    @staticmethod
    def _validate_payload(payload: dict) -> None:
        required = {"rf", "classes_"}
        missing = required - payload.keys()
        if missing:
            raise ValueError(f"MLDetector: artifact missing keys: {sorted(missing)}")

    def proba(self, feature_vector: Sequence[float]) -> float:
        """Return P(ATTACK) ∈ [0, 1] for one feature vector."""
        x = np.asarray(feature_vector, dtype=float).reshape(1, -1)
        if x.shape[1] != len(self.feature_cols):
            raise ValueError(
                f"MLDetector: expected {len(self.feature_cols)} features, got {x.shape[1]}. "
                f"Expected ordering: {self.feature_cols}"
            )
        return float(self.rf.predict_proba(x)[0, self._attack_col])

    def verdict(self, feature_vector: Sequence[float]) -> str:
        """Return "ATTACK" if P(ATTACK) >= configured proba_threshold."""
        return "ATTACK" if self.proba(feature_vector) >= self.proba_threshold else "BENIGN"

    def save(self, model_path: Path | str) -> None:
        """Persist the detector to disk via joblib (used by the training notebook)."""
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "rf": self.rf,
                "classes_": self.classes_,
                "feature_cols": list(self.feature_cols),
                "proba_threshold": self.proba_threshold,
                "schema_version": self.SCHEMA_VERSION,
            },
            model_path,
            compress=3,
        )
