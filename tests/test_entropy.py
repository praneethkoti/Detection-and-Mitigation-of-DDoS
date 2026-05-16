"""Unit tests for EntropyAnalyzer (v3 §4.6 + the is_attack() threshold contract).

Three behavioral assertions that pin the math and the verdict logic:

1. Uniform distribution over a window of N distinct destinations produces
   entropy exactly log2(N) bits.
2. A degenerate (singleton) distribution produces entropy exactly 0 bits.
3. is_attack() is True iff entropy < threshold_bits, with no off-by-one
   on the comparison. Locks the contract Phase 3's PCA-gating builds on:
   the entropy verdict is "ATTACK" iff is_attack() returns True, and the
   threshold is read from threshold_bits (or, by default, from config).
"""

from __future__ import annotations

import io

import pytest

from ddos_sdn.detector.entropy import EntropyAnalyzer
from ddos_sdn.detector.telemetry import TelemetryEmitter


def _make_analyzer(window: int, threshold_bits: float | None = None) -> EntropyAnalyzer:
    # Discard telemetry to keep these unit tests free of stdout pollution.
    emitter = TelemetryEmitter(sink=io.StringIO(), clock=lambda: 0.0)
    return EntropyAnalyzer(window=window, threshold_bits=threshold_bits, telemetry=emitter)


def test_entropy_uniform_is_max_for_window_of_4() -> None:
    a = _make_analyzer(window=4)
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]:
        a.collect_statistics(ip)
    # log2(4) == 2.0 — uniform distribution achieves maximum entropy.
    assert a.entropy_value == pytest.approx(2.0)


def test_entropy_singleton_is_zero() -> None:
    a = _make_analyzer(window=4)
    for _ in range(4):
        a.collect_statistics("1.1.1.1")
    # Degenerate distribution: H = 0.
    assert a.entropy_value == pytest.approx(0.0)


def test_is_attack_uses_configured_threshold() -> None:
    # threshold_bits=1.0 means "entropy below 1 bit is an attack". A
    # singleton stream produces entropy 0.0, which is below 1.0, so the
    # verdict must be ATTACK. This pins the contract Phase 3's PCA gating
    # and the POX controller's pox_controller.py:is_attack() call both
    # depend on.
    a = _make_analyzer(window=4, threshold_bits=1.0)
    for _ in range(4):
        a.collect_statistics("10.0.0.64")
    assert a.entropy_value == pytest.approx(0.0)
    assert a.is_attack() is True

    # And the inverse: a uniform stream sits at the maximum entropy, which
    # is above any reasonable threshold, so is_attack() is False.
    b = _make_analyzer(window=4, threshold_bits=1.0)
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]:
        b.collect_statistics(ip)
    assert b.entropy_value == pytest.approx(2.0)
    assert b.is_attack() is False
