"""Shannon entropy of destination IPs over fixed-size packet windows.

This is the low-cost first-stage detection signal described in the companion
report (docs/SDN_DDoS_Report.pdf §4.1) and grounded in the Lakhina-Crovella-Diot
SIGCOMM 2005 entropy-anomaly framework. Under benign traffic the destination-IP
distribution is broad and entropy stays close to log2(window); under a
single-target volumetric flood the distribution collapses to one destination
and entropy drops toward 0.

Each closed window emits exactly one JSON line through TelemetryEmitter — the
external contract every downstream consumer reads. See
ddos_sdn.detector.telemetry for the 13-field schema.

The detector deliberately does not catch the "new-type DDoS" case where a
single source targets randomized destinations (the report's chapter 6 case 3).
That case keeps dst-IP entropy high and motivates the PCA / RandomForest
detectors. tests/test_three_case_smoke.py asserts this failure mode
explicitly so the Phase 3 PCA detector has a baseline to beat. The Phase 4a
runtime packet-size tracking adds entropy_size + packet_size_std_dev as
additional discriminators for the PCA/RF feature vector.
"""

from __future__ import annotations

import logging
import math
from collections import Counter

import numpy as np

from ddos_sdn.config import load_config
from ddos_sdn.detector.features import FEATURE_COLS
from ddos_sdn.detector.telemetry import TelemetryEmitter

try:
    from pox.core import core

    logger = core.getLogger()
except ImportError:
    logger = logging.getLogger(__name__)


class EntropyAnalyzer:
    """Streaming destination-IP entropy detector with JSON-line telemetry."""

    def __init__(
        self,
        window: int | None = None,
        threshold_bits: float | None = None,
        telemetry: TelemetryEmitter | None = None,
        pca_detector=None,
        ml_detector=None,
    ) -> None:
        """Construct an EntropyAnalyzer.

        The optional `pca_detector` and `ml_detector` arguments, when supplied,
        score each closed window's 10-feature vector and populate the
        pca_mahalanobis / rf_proba / verdict_pca / verdict_rf fields in the
        emitted telemetry record. When None, those fields stay JSON null per
        the Phase 1 schema contract.

        Phase 4a added packet-size tracking: callers passing `packet_size` to
        collect_statistics() get real `entropy_size` and `packet_size_std_dev`
        in the feature vector and emitted telemetry; callers not passing it
        (legacy three-case smoke streams) keep entropy_size=null and
        std_dev=0.0, preserving backward compatibility.
        """
        cfg = load_config()["detector"]
        self.window: int = window if window is not None else cfg["window_packets"]
        self.threshold_bits: float = (
            threshold_bits if threshold_bits is not None else cfg["entropy_threshold_bits"]
        )
        self.telemetry: TelemetryEmitter = (
            telemetry if telemetry is not None else TelemetryEmitter()
        )
        self.pca_detector = pca_detector
        self.ml_detector = ml_detector

        # Mutable per-window state. Reset by reset_stats() at the end of each window.
        self.packet_count: int = 0
        self.dst_ips: list[str] = []
        self.src_ips: list[str] = []
        self.packet_sizes: list[int] = (
            []
        )  # Phase 4a §4a.A — tracks pkt sizes for entropy_size + std_dev
        self._window_start_t: float | None = None

        # History of per-window entropy values. Kept across windows so a caller
        # can replay or plot them (the report's "deltaY vs time" figures).
        self.dst_entropy: list[float] = []

        # Last top_src / top_dst — read by the POX controller's monitor_ddos
        # and by anything else that wants the attacker / victim hint without
        # parsing the JSON-line stream.
        self.top_src: str | None = None
        self.top_dst: str | None = None

        # Last verdict / value — read by the POX controller's is_attack() gate.
        self.entropy_value: float = float(math.log2(self.window)) if self.window > 1 else 1.0

    def is_attack(self) -> bool:
        """The single source of truth for the entropy-only verdict."""
        return self.entropy_value < self.threshold_bits

    def collect_statistics(self, dst_ip, src_ip=None, packet_size: int | None = None) -> None:
        """Record one packet. Triggers window close + telemetry emit on the Nth call.

        Args:
            dst_ip: destination IP (any value with a __str__; POX hands us
                    pox.lib.addresses.IPAddr instances, the smoke test hands
                    us plain strings).
            src_ip: optional source IP. When provided, feeds top_src + entropy_src
                    in the emitted telemetry record.
            packet_size: optional packet size in bytes (Phase 4a §4a.A). When
                    provided, feeds entropy_size in the telemetry record AND
                    packet_size_std_dev in the PCA/RF feature vector. When
                    None, entropy_size stays JSON null and packet_size_std_dev
                    falls back to 0.0 in the feature vector.
        """
        if self._window_start_t is None:
            self._window_start_t = self.telemetry.now()

        self.packet_count += 1
        self.dst_ips.append(str(dst_ip))
        if src_ip is not None:
            self.src_ips.append(str(src_ip))
        if packet_size is not None:
            self.packet_sizes.append(int(packet_size))

        if self.packet_count >= self.window:
            self._close_window()

    def _close_window(self) -> None:
        dst_counts = Counter(self.dst_ips)
        src_counts: Counter = Counter()
        size_counts: Counter = Counter()
        entropy = self._shannon_bits(dst_counts, total=self.packet_count)

        top_dst = dst_counts.most_common(1)[0][0]
        top_src: str | None = None
        entropy_src: float | None = None
        if self.src_ips:
            src_counts = Counter(self.src_ips)
            top_src = src_counts.most_common(1)[0][0]
            entropy_src = self._shannon_bits(src_counts, total=len(self.src_ips))

        # Phase 4a §4a.A — packet-size statistics.
        entropy_size: float | None = None
        # ddof=0 explicit per features.py docstring — train/inference symmetry guard.
        packet_size_std_dev: float = 0.0
        if self.packet_sizes:
            size_counts = Counter(self.packet_sizes)
            entropy_size = self._shannon_bits(size_counts, total=len(self.packet_sizes))
            packet_size_std_dev = float(np.std(self.packet_sizes, ddof=0))

        t_now = self.telemetry.now()
        window_seconds = max(t_now - (self._window_start_t or t_now), 1e-3)
        pps = int(self.packet_count / window_seconds)

        self.entropy_value = entropy
        self.dst_entropy.append(entropy)
        # Persist top_dst/top_src on the instance so the POX controller's
        # monitor_ddos can read entropy_instance.top_src to populate the
        # nw_src field of the ofp_flow_mod drop rule (Phase 3 §3.A).
        self.top_dst = top_dst
        self.top_src = top_src
        verdict = "ATTACK" if self.is_attack() else "BENIGN"

        # Phase 4a: 10-feature vector consumed by PCA/RF.
        feature_vector = self._feature_vector(
            dst_counts=dst_counts,
            src_counts=src_counts,
            entropy_dst=entropy,
            entropy_src=entropy_src,
            entropy_size=entropy_size,
            pps=pps,
            top_dst=top_dst,
            top_src=top_src,
            packet_size_std_dev=packet_size_std_dev,
        )
        pca_mahalanobis: float | None = None
        verdict_pca: str | None = None
        if self.pca_detector is not None and feature_vector is not None:
            pca_mahalanobis = self.pca_detector.score(feature_vector)
            verdict_pca = self.pca_detector.verdict(feature_vector)
        rf_proba: float | None = None
        verdict_rf: str | None = None
        if self.ml_detector is not None and feature_vector is not None:
            rf_proba = self.ml_detector.proba(feature_vector)
            verdict_rf = self.ml_detector.verdict(feature_vector)

        self.telemetry.emit(
            t=t_now,
            window_packets=self.packet_count,
            entropy_dst=entropy,
            entropy_src=entropy_src,  # Phase 3 §3.D.1
            entropy_size=entropy_size,  # Phase 4a §4a.A (was None)
            pps=pps,
            pca_mahalanobis=pca_mahalanobis,  # Phase 3 §3.B
            rf_proba=rf_proba,  # Phase 3 §3.C
            verdict_entropy=verdict,
            verdict_pca=verdict_pca,  # Phase 3 §3.B
            verdict_rf=verdict_rf,  # Phase 3 §3.C
            top_dst=top_dst,
            top_src=top_src,
        )

        logger.info(
            "window closed: packets=%d entropy_bits=%.3f verdict=%s top_dst=%s top_src=%s",
            self.packet_count,
            entropy,
            verdict,
            top_dst,
            top_src,
        )

        self.reset_stats()

    @staticmethod
    def _shannon_bits(counts: Counter, total: int) -> float:
        if total <= 0:
            return 0.0
        entropy = 0.0
        for c in counts.values():
            if c <= 0:
                continue
            p = c / total
            entropy -= p * math.log2(p)
        return entropy

    def _feature_vector(
        self,
        dst_counts: Counter,
        src_counts: Counter,
        entropy_dst: float,
        entropy_src: float | None,
        entropy_size: float | None,
        pps: int,
        top_dst: str,
        top_src: str | None,
        packet_size_std_dev: float,
    ) -> list[float] | None:
        """Build the 10-feature vector consumed by PCADetector and MLDetector.

        Feature ordering matches FEATURE_COLS in ddos_sdn.detector.features:
        [entropy_dst, entropy_src, entropy_size, pps, window_packets,
         unique_src_count, unique_dst_count,
         top_dst_frequency, top_src_frequency, packet_size_std_dev]

        Returns None if no source IPs are tracked — the feature vector
        requires entropy_src, and a window with no src information can't be
        scored. Phase 1/2 callers that don't pass src_ip continue to work;
        their telemetry records just keep verdict_pca / verdict_rf as null.

        When packet_size is not tracked (legacy callers), entropy_size falls
        back to 0.0 in the feature vector slot (the JSON telemetry still
        emits null for entropy_size — feature vector uses 0.0 because the
        ML inputs must be numeric; null is a JSON concept not a feature).
        """
        if not src_counts or entropy_src is None or top_src is None:
            return None
        n = float(self.packet_count)
        top_dst_count = dst_counts[top_dst]
        top_src_count = src_counts[top_src]
        # Order MUST match FEATURE_COLS in features.py.
        return [
            float(entropy_dst),  # entropy_dst
            float(entropy_src),  # entropy_src
            float(entropy_size) if entropy_size is not None else 0.0,  # entropy_size
            float(pps),  # pps
            n,  # window_packets
            float(len(src_counts)),  # unique_src_count
            float(len(dst_counts)),  # unique_dst_count
            top_dst_count / n,  # top_dst_frequency
            top_src_count / n,  # top_src_frequency
            float(packet_size_std_dev),  # packet_size_std_dev (ddof=0)
        ]

    def reset_stats(self) -> None:
        self.dst_ips = []
        self.src_ips = []
        self.packet_sizes = []
        self.packet_count = 0
        self._window_start_t = None


# Re-export for callers that want to grep for the feature contract from this module.
__all__ = ["EntropyAnalyzer", "FEATURE_COLS"]
