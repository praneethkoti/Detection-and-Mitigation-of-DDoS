"""Three-generator smoke test (Phase 1 baseline for Phase 3 PCA evaluation).

Drives EntropyAnalyzer directly with synthesized destination/source IP streams
that match each of the three traffic regimes the companion report's chapter 6
enumerates:

    Case 1  benign baseline           — uniform 10.0.0.[2..64]      -> BENIGN
    Case 2  single-target flood       — all 10.0.0.64                -> ATTACK
    Case 3  random-destination flood  — one src, uniform dst range   -> BENIGN (entropy fails here)

Case 3 is the case the report calls the "new-type DDoS" — destination-IP
entropy stays high, so the entropy-only detector reports BENIGN. That failure
mode is asserted explicitly so the Phase 3 PCA detector has a concrete number
to beat. The README and the commit body both reference these baseline numbers.

The 13-field telemetry schema is also exercised — every emitted JSON line is
parsed and every key from TelemetryEmitter.FIELDS is asserted present. Phase 1
populates 7 fields with real values; the other 6 are JSON null.

Runnable as a plain script in Phase 1:

    python tests/test_three_case_smoke.py [--seed 42] [--verbose]

Phase 2 will wrap this file as a pytest case; the assertions and the exit
code are already compatible.
"""

from __future__ import annotations

import argparse
import io
import json
import random
import sys
from dataclasses import dataclass

from ddos_sdn.config import load_config
from ddos_sdn.detector.entropy import EntropyAnalyzer
from ddos_sdn.detector.telemetry import TelemetryEmitter

WINDOW_PACKETS = 250
PACKETS_PER_CASE = 1000   # closes 4 windows per case
EXPECTED_WINDOWS_PER_CASE = PACKETS_PER_CASE // WINDOW_PACKETS

BENIGN_RANGE = range(2, 65)     # 10.0.0.[2..64]
SINGLE_TARGET = "10.0.0.64"
RANDOM_DST_SOURCE = "10.0.0.1"


@dataclass
class CaseResult:
    name: str
    windows: int
    attack_windows: int
    entropy_dst_min: float
    verdict_match: bool
    note: str = ""


def _build_analyzer() -> tuple[EntropyAnalyzer, io.StringIO]:
    buf = io.StringIO()
    emitter = TelemetryEmitter(sink=buf, clock=lambda: 0.0)
    analyzer = EntropyAnalyzer(window=WINDOW_PACKETS, telemetry=emitter)
    return analyzer, buf


def _parse_records(buf: io.StringIO) -> list[dict]:
    raw = buf.getvalue().strip().splitlines()
    return [json.loads(line) for line in raw]


def _assert_schema(records: list[dict]) -> None:
    expected = set(TelemetryEmitter.FIELDS)
    assert len(expected) == 13, f"schema must be 13 fields, got {len(expected)}"
    for r in records:
        got = set(r.keys())
        assert got == expected, f"telemetry schema drift: missing={expected - got}, extra={got - expected}"


def run_case_benign(rng: random.Random) -> CaseResult:
    analyzer, buf = _build_analyzer()
    for _ in range(PACKETS_PER_CASE):
        dst = f"10.0.0.{rng.choice(list(BENIGN_RANGE))}"
        src = f"203.0.113.{rng.randint(1, 254)}"   # TEST-NET-3, public-ish
        analyzer.collect_statistics(dst, src_ip=src)

    records = _parse_records(buf)
    _assert_schema(records)
    attack_windows = sum(1 for r in records if r["verdict_entropy"] == "ATTACK")
    entropy_min = min(r["entropy_dst"] for r in records)
    benign_windows = len(records) - attack_windows
    verdict_match = benign_windows >= EXPECTED_WINDOWS_PER_CASE - 1
    return CaseResult(
        name="benign", windows=len(records), attack_windows=attack_windows,
        entropy_dst_min=entropy_min, verdict_match=verdict_match,
    )


def run_case_udp_flood(rng: random.Random) -> CaseResult:
    analyzer, buf = _build_analyzer()
    src = "10.0.0.1"
    for _ in range(PACKETS_PER_CASE):
        analyzer.collect_statistics(SINGLE_TARGET, src_ip=src)

    records = _parse_records(buf)
    _assert_schema(records)
    attack_windows = sum(1 for r in records if r["verdict_entropy"] == "ATTACK")
    entropy_min = min(r["entropy_dst"] for r in records)
    verdict_match = attack_windows == len(records) and entropy_min == 0.0
    return CaseResult(
        name="udp_flood", windows=len(records), attack_windows=attack_windows,
        entropy_dst_min=entropy_min, verdict_match=verdict_match,
    )


def run_case_random_dst(rng: random.Random) -> CaseResult:
    analyzer, buf = _build_analyzer()
    for _ in range(PACKETS_PER_CASE):
        dst = f"10.0.0.{rng.choice(list(BENIGN_RANGE))}"
        analyzer.collect_statistics(dst, src_ip=RANDOM_DST_SOURCE)

    records = _parse_records(buf)
    _assert_schema(records)
    attack_windows = sum(1 for r in records if r["verdict_entropy"] == "ATTACK")
    entropy_min = min(r["entropy_dst"] for r in records)
    benign_windows = len(records) - attack_windows

    # The headline assertion: entropy-only DOES NOT catch this case.
    # If a future code change makes entropy catch random_dst_flood the assert
    # below will fail and someone has to make a real decision.
    verdict_match = benign_windows >= EXPECTED_WINDOWS_PER_CASE - 1

    # And we also check the source-IP signals that the Phase 3 mitigation +
    # PCA detector key on: top_src must be the attacker, and entropy_src
    # must collapse to ~0 (single source flooding random destinations).
    # The entropy_src signal is what PCA learns to distinguish random_dst
    # from benign traffic, since dst-IP entropy alone cannot.
    assert records[-1]["top_src"] == RANDOM_DST_SOURCE, records[-1]
    assert records[-1]["entropy_src"] is not None, records[-1]
    assert records[-1]["entropy_src"] < 0.1, records[-1]

    return CaseResult(
        name="random_dst", windows=len(records), attack_windows=attack_windows,
        entropy_dst_min=entropy_min, verdict_match=verdict_match,
        note="expected: entropy fails to detect — Phase 3 PCA addresses this",
    )


# ------------------------------------------------------------------
# pytest-discoverable wrappers (Phase 2 §2.C). The run_case_* logic
# above is the single code path; these are one-liner asserts so
# `python -m pytest` picks up the same coverage that `python tests/
# test_three_case_smoke.py` exercises via main(). Each wrapper seeds
# its own Random(42) for pytest's test isolation.
# ------------------------------------------------------------------

def test_benign_baseline_is_recognized_as_benign() -> None:
    assert run_case_benign(random.Random(42)).verdict_match


def test_single_target_flood_is_recognized_as_attack() -> None:
    assert run_case_udp_flood(random.Random(42)).verdict_match


def test_random_dst_flood_is_known_failure_of_entropy_only_detector() -> None:
    # verdict_match==True here means "entropy reports BENIGN as expected" —
    # the case the report's chapter 6 calls out and Phase 3's PCA detector
    # will be the one to flip from BENIGN to ATTACK.
    assert run_case_random_dst(random.Random(42)).verdict_match


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Three-generator smoke test for entropy detection.")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for deterministic IP draws (default: 42)")
    parser.add_argument("--verbose", action="store_true", help="print every emitted JSON record")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    rng = random.Random(args.seed)

    # Sanity: the analyzer's defaults must come from config.yaml / DEFAULTS.
    cfg = load_config()
    assert cfg["detector"]["window_packets"] == WINDOW_PACKETS, cfg["detector"]

    results = [
        run_case_benign(rng),
        run_case_udp_flood(rng),
        run_case_random_dst(rng),
    ]

    for r in results:
        suffix = f"   ({r.note})" if r.note else ""
        print(
            f"[SMOKE] case={r.name:<12} windows={r.windows}   "
            f"attack_windows={r.attack_windows}   "
            f"entropy_dst_min={r.entropy_dst_min:.2f}   "
            f"verdict_match={r.verdict_match}{suffix}"
        )

    all_passed = all(r.verdict_match for r in results)
    if all_passed:
        print("[SMOKE] PASS")
        return 0
    else:
        print("[SMOKE] FAIL")
        return 1


if __name__ == "__main__":
    sys.exit(main())
