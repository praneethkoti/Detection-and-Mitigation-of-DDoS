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
detectors on the roadmap. tests/test_three_case_smoke.py asserts this
failure mode explicitly so the roadmap detectors have a baseline to beat.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from typing import Optional

from ddos_sdn.config import load_config
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
        window: Optional[int] = None,
        threshold_bits: Optional[float] = None,
        telemetry: Optional[TelemetryEmitter] = None,
    ) -> None:
        cfg = load_config()["detector"]
        self.window: int = window if window is not None else cfg["window_packets"]
        self.threshold_bits: float = (
            threshold_bits if threshold_bits is not None else cfg["entropy_threshold_bits"]
        )
        self.telemetry: TelemetryEmitter = telemetry if telemetry is not None else TelemetryEmitter()

        # Mutable per-window state. Reset by reset_stats() at the end of each window.
        self.packet_count: int = 0
        self.dst_ips: list[str] = []
        self.src_ips: list[str] = []
        self._window_start_t: Optional[float] = None

        # History of per-window entropy values. Kept across windows so a caller
        # can replay or plot them (the report's "deltaY vs time" figures).
        self.dst_entropy: list[float] = []

        # Last verdict / value — read by the POX controller's is_attack() gate.
        self.entropy_value: float = float(math.log2(self.window)) if self.window > 1 else 1.0

    def is_attack(self) -> bool:
        """The single source of truth for the entropy-only verdict."""
        return self.entropy_value < self.threshold_bits

    def collect_statistics(self, dst_ip, src_ip=None) -> None:
        """Record one packet. Triggers window close + telemetry emit on the Nth call.

        Args:
            dst_ip: destination IP (any value with a __str__; POX hands us
                    pox.lib.addresses.IPAddr instances, the smoke test hands
                    us plain strings).
            src_ip: optional source IP. When provided, it feeds top_src in
                    the emitted telemetry record; when None, top_src is left
                    as the last-known value or None.
        """
        if self._window_start_t is None:
            self._window_start_t = self.telemetry.now()

        self.packet_count += 1
        self.dst_ips.append(str(dst_ip))
        if src_ip is not None:
            self.src_ips.append(str(src_ip))

        if self.packet_count >= self.window:
            self._close_window()

    def _close_window(self) -> None:
        dst_counts = Counter(self.dst_ips)
        entropy = self._shannon_bits(dst_counts, total=self.packet_count)

        top_dst = dst_counts.most_common(1)[0][0]
        top_src: Optional[str] = None
        if self.src_ips:
            top_src = Counter(self.src_ips).most_common(1)[0][0]

        t_now = self.telemetry.now()
        window_seconds = max(t_now - (self._window_start_t or t_now), 1e-3)
        pps = int(self.packet_count / window_seconds)

        self.entropy_value = entropy
        self.dst_entropy.append(entropy)
        verdict = "ATTACK" if self.is_attack() else "BENIGN"

        self.telemetry.emit(
            t=t_now,
            window_packets=self.packet_count,
            entropy_dst=entropy,
            entropy_src=None,    # Phase 4 §3.10
            entropy_size=None,   # Phase 4 §3.10
            pps=pps,
            pca_mahalanobis=None,  # Phase 3 §4.1
            rf_proba=None,         # Phase 3 §4.2
            verdict_entropy=verdict,
            verdict_pca=None,      # Phase 3
            verdict_rf=None,       # Phase 3
            top_dst=top_dst,
            top_src=top_src,
        )

        logger.info(
            "window closed: packets=%d entropy_bits=%.3f verdict=%s top_dst=%s top_src=%s",
            self.packet_count, entropy, verdict, top_dst, top_src,
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

    def reset_stats(self) -> None:
        self.dst_ips = []
        self.src_ips = []
        self.packet_count = 0
        self._window_start_t = None
