"""PCAP corpus builder tests (Phase 4d.1 §4d.1.H).

scripts/build_sample_pcaps.py grew from two PCAPs to five in Phase 4d.1. Two
properties matter enough to lock:

  1. DETERMINISM. Same seed produces byte-identical files. demo.py's locked
     "[PASS] attack detected within first 500 packets" line and
     tests/test_pcap_replay.py both read committed PCAPs, so a builder that
     drifted between runs would silently invalidate them.

  2. THE ORIGINAL TWO ARE FROZEN. normal.pcap and attack.pcap must be
     unchanged by the addition of the three new attack classes. The new classes
     take their own RNG seed offsets precisely so they cannot perturb the
     original streams; this test is what would catch someone reusing an offset.

The size budget is asserted too: the corpus is committed to git and ships to
Streamlit Community Cloud on every cold start.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

ALL_PCAPS = (
    "normal.pcap",
    "attack.pcap",
    "attack_syn_flood.pcap",
    "attack_slowloris.pcap",
    "attack_ntp_amp.pcap",
)

# Committed budget. The corpus measured 3.22 MiB at the Phase 4d.1 commit;
# 5 MiB leaves headroom without letting it grow unbounded.
SIZE_BUDGET_BYTES = 5 * 1024 * 1024


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_every_pcap_in_the_corpus_exists() -> None:
    missing = [name for name in ALL_PCAPS if not (SAMPLES_DIR / name).is_file()]
    assert not missing, f"missing PCAPs: {missing}; run `make samples`"


def test_corpus_fits_the_size_budget() -> None:
    """The corpus is committed and ships to Cloud on every cold start."""
    total = sum(
        (SAMPLES_DIR / name).stat().st_size for name in ALL_PCAPS if (SAMPLES_DIR / name).is_file()
    )
    assert total <= SIZE_BUDGET_BYTES, (
        f"PCAP corpus is {total / 1024 / 1024:.2f} MiB, over the "
        f"{SIZE_BUDGET_BYTES / 1024 / 1024:.0f} MiB budget"
    )


def test_builder_is_deterministic_for_a_fixed_seed(tmp_path: Path) -> None:
    """Same seed, same bytes. Run twice into separate directories and compare."""
    pytest.importorskip("scapy")
    from build_sample_pcaps import main

    first, second = tmp_path / "a", tmp_path / "b"
    assert main(["--seed", "42", "--out-dir", str(first)]) == 0
    assert main(["--seed", "42", "--out-dir", str(second)]) == 0

    for name in ALL_PCAPS:
        assert _sha256(first / name) == _sha256(second / name), f"{name} is not deterministic"


def test_new_classes_do_not_perturb_the_original_pcaps(tmp_path: Path) -> None:
    """normal.pcap and attack.pcap must match the committed bytes exactly.

    This is the regression guard for the seed-offset discipline: the three
    Phase 4d.1 classes use offsets 2-4 so they draw from independent RNG
    streams. Reusing offset 0 or 1 would shift the original files and break
    demo.py's locked [PASS] line.
    """
    pytest.importorskip("scapy")
    from build_sample_pcaps import main

    out = tmp_path / "regen"
    assert main(["--seed", "42", "--out-dir", str(out)]) == 0

    for name in ("normal.pcap", "attack.pcap"):
        committed = SAMPLES_DIR / name
        if not committed.is_file():
            pytest.skip(f"{name} not committed; nothing to compare against")
        assert _sha256(out / name) == _sha256(committed), (
            f"{name} changed. The Phase 4d.1 attack classes must not perturb the "
            f"original two PCAPs; check the RNG seed offsets in build_sample_pcaps.main()."
        )


def test_each_attack_pcap_has_the_expected_shape() -> None:
    """1000 packets each, with a benign prefix before the attack begins."""
    pytest.importorskip("scapy")
    from build_sample_pcaps import ATTACK_PCAP_BENIGN_PREFIX, ATTACK_PCAP_PACKETS
    from scapy.all import rdpcap

    for name in (
        "attack.pcap",
        "attack_syn_flood.pcap",
        "attack_slowloris.pcap",
        "attack_ntp_amp.pcap",
    ):
        path = SAMPLES_DIR / name
        if not path.is_file():
            pytest.skip(f"{name} not present; run `make samples`")
        packets = rdpcap(str(path))
        assert len(packets) == ATTACK_PCAP_PACKETS, f"{name} has {len(packets)} packets"
        # The benign prefix keeps the first window benign, which is what makes
        # the "detection within the first 500 packets" structure generalize.
        assert ATTACK_PCAP_BENIGN_PREFIX < ATTACK_PCAP_PACKETS


def test_slowloris_pcap_carries_a_low_rate_timeline() -> None:
    """Slow-loris timing is load-bearing, not decoration (Phase 4d.1 §4d.1.B).

    `pps` is derived from packet timestamps when the dashboard replays with
    use_pcap_clock=True. If this PCAP were written at the default 1 ms spacing
    like the other classes, its windows would report ~1004 pps and the RF would
    name them NTP_AMP.
    """
    pytest.importorskip("scapy")
    from build_sample_pcaps import ATTACK_PCAP_BENIGN_PREFIX
    from scapy.all import rdpcap

    path = SAMPLES_DIR / "attack_slowloris.pcap"
    if not path.is_file():
        pytest.skip("attack_slowloris.pcap not present; run `make samples`")

    times = [float(p.time) for p in rdpcap(str(path))]
    attack_times = times[ATTACK_PCAP_BENIGN_PREFIX:]
    span = attack_times[249] - attack_times[0]
    implied_pps = 250 / span
    assert 5 <= implied_pps <= 20, (
        f"slow-loris windows imply {implied_pps:.1f} pps, outside the trained "
        f"SLOWLORIS band of 5-20. The class will not classify correctly."
    )
