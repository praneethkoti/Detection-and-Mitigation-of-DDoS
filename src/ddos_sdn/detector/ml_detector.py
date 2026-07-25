"""Supervised RandomForest detector (Phase 3 §3.C; multi-class in Phase 4c).

`sklearn.ensemble.RandomForestClassifier` trained on the same 10-feature
per-window vectors as `PCADetector`. At inference time, returns P(attack)
via `predict_proba` and converts to a verdict at the configured
`detector.rf.proba_threshold` (default 0.5).

Phase 4c §4c.B widens the trained label set from binary (BENIGN/ATTACK) to
five-way (BENIGN, UDP_FLOOD, SYN_FLOOD, SLOWLORIS, NTP_AMP) without changing
what this class promises the telemetry layer:

    verdict()   unchanged. Returns "BENIGN" or "ATTACK". The JSON field
                verdict_rf stays binary and the 13-field telemetry contract
                is untouched; schema_version stays 1.
    proba()     unchanged signature. Now returns summed probability mass over
                every non-BENIGN class rather than indexing a single ATTACK
                column, because a five-class model has no such column. For a
                binary model the two are arithmetically identical, so old
                artifacts keep answering exactly as before.
    classify()  NEW. Returns the specific class label. Consumed by the
                training notebook's evaluation cells and by demo.py's
                [SUMMARY] block; deliberately NOT surfaced in JSON telemetry.

Artifact compatibility: binary artifacts (classes_ == [BENIGN, ATTACK]) still
load and still answer verdict()/proba() identically. classify() on such an
artifact returns "ATTACK", which is honest: that model cannot name a subclass.
The payload SCHEMA_VERSION bumps 1 -> 2 and both are accepted on load. That
version is the model-artifact version and is unrelated to the telemetry
schema_version, which Phase 4c does not touch.

Sklearn defaults justified in this docstring (per working agreement #1):
    n_estimators=100        sklearn's native default; standard rule-of-thumb
                            for tabular features in the dozens.
    max_depth=None          no depth cap. The 10-feature space is low-dim
                            and trees won't grow pathologically deep.
    min_samples_split=2,
    min_samples_leaf=1      sklearn defaults. Permits full granularity on the
                            modest dataset size (240 rows from the Phase 4c
                            fallback path).
    n_jobs=-1               parallelize fit across cores; deterministic with
                            random_state set.
    random_state=42         deterministic fit. Same training data produces the
                            same rf.joblib bytes.
    class_weight="balanced" compensates for class imbalance in CICDDoS2019
                            per-class CSVs and in our synth fallback (40 rows
                            per class except UDP_FLOOD's 80, which covers both
                            the single-target and random-destination variants).
                            "balanced" sets class weights inversely
                            proportional to class frequencies, so minority
                            classes aren't drowned out. Natively multi-class.

The 10-feature input ordering (must match PCADetector and the training set):

    [entropy_dst, entropy_src, entropy_size, pps, window_packets,
     unique_src_count, unique_dst_count,
     top_dst_frequency, top_src_frequency, packet_size_std_dev]
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ddos_sdn.config import load_config

# Phase 4a §4a.B: single source of truth for the feature ordering.
# Re-exported here so existing imports `from ddos_sdn.detector.ml_detector
# import FEATURE_COLS` keep working without changes.
from ddos_sdn.detector.features import FEATURE_COLS  # noqa: E402


class MLDetector:
    """RandomForest-backed supervised attack-class detector."""

    # Model-artifact payload version (NOT the telemetry schema_version).
    # 1 = binary BENIGN/ATTACK (Phase 3, 4a, 4b). 2 = five-way (Phase 4c).
    # Both are accepted on load.
    SCHEMA_VERSION = 2
    SUPPORTED_SCHEMA_VERSIONS = (1, 2)

    BENIGN_LABEL = "BENIGN"
    ATTACK_VERDICT = "ATTACK"

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
        self._attack_cols: list[int] = self._resolve_attack_cols(self.classes_)

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
        instance._attack_cols = cls._resolve_attack_cols(instance.classes_)
        return instance

    @classmethod
    def _resolve_attack_cols(cls, classes: list[str]) -> list[int]:
        """Return predict_proba column indices for every non-BENIGN class.

        Phase 4c §4c.B relaxation. The pre-4c guard required the literal
        "ATTACK" to be present, which a five-way model never satisfies, so
        every construction path would raise the moment the artifact was
        retrained. The invariant that actually matters is weaker: there must
        be a BENIGN class to measure against, and at least one class that
        isn't BENIGN. Binary artifacts satisfy this exactly as before.
        """
        if cls.BENIGN_LABEL not in classes:
            raise ValueError(
                f"MLDetector: trained classes_ does not include " f"'{cls.BENIGN_LABEL}': {classes}"
            )
        attack_cols = [i for i, c in enumerate(classes) if c != cls.BENIGN_LABEL]
        if not attack_cols:
            raise ValueError(
                f"MLDetector: trained classes_ contains no non-{cls.BENIGN_LABEL} "
                f"class, so no attack can ever be reported: {classes}"
            )
        return attack_cols

    @classmethod
    def _validate_payload(cls, payload: dict) -> None:
        required = {"rf", "classes_"}
        missing = required - payload.keys()
        if missing:
            raise ValueError(f"MLDetector: artifact missing keys: {sorted(missing)}")
        version = payload.get("schema_version", 1)
        if version not in cls.SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(
                f"MLDetector: unsupported artifact schema_version={version}; "
                f"supported: {list(cls.SUPPORTED_SCHEMA_VERSIONS)}"
            )

    def _as_row(self, feature_vector: Sequence[float]) -> np.ndarray:
        x = np.asarray(feature_vector, dtype=float).reshape(1, -1)
        if x.shape[1] != len(self.feature_cols):
            raise ValueError(
                f"MLDetector: expected {len(self.feature_cols)} features, got {x.shape[1]}. "
                f"Expected ordering: {self.feature_cols}"
            )
        return x

    def proba(self, feature_vector: Sequence[float]) -> float:
        """Return P(attack) in [0, 1] for one feature vector.

        Summed over every non-BENIGN class. On a binary model this is exactly
        the old single-column lookup, so verdict_rf output is unchanged; on a
        five-way model it is the total mass assigned to any attack class.
        """
        x = self._as_row(feature_vector)
        row = self.rf.predict_proba(x)[0]
        return float(sum(row[i] for i in self._attack_cols))

    def verdict(self, feature_vector: Sequence[float]) -> str:
        """Return "ATTACK" if P(attack) >= configured proba_threshold.

        Binary by contract. The telemetry field verdict_rf consumes this and
        the 13-field JSON schema depends on it staying binary; use classify()
        when the specific attack class is wanted.
        """
        proba = self.proba(feature_vector)
        return self.ATTACK_VERDICT if proba >= self.proba_threshold else self.BENIGN_LABEL

    def classify(self, feature_vector: Sequence[float]) -> str:
        """Return the specific predicted class label (Phase 4c §4c.B).

        One of BENIGN, UDP_FLOOD, SYN_FLOOD, SLOWLORIS, NTP_AMP for a Phase 4c
        artifact. A pre-4c binary artifact can only answer BENIGN or ATTACK,
        since it was never trained to name a subclass.

        Deliberately not surfaced in JSON telemetry: the 13-field contract and
        schema_version=1 are unchanged by Phase 4c.
        """
        x = self._as_row(feature_vector)
        return str(self.rf.predict(x)[0])

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
