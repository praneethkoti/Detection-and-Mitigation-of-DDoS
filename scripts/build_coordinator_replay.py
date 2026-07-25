"""Coordinator replay fixture builder (Phase 4d.1 §4d.1.F).

Generates samples/coordinator_replay.jsonl: a scripted, deterministic sequence
of WORKER_TELEMETRY messages that the dashboard's Panel 5 animates to
illustrate Phase 4b's East-West correlation.

WHY A FIXTURE RATHER THAN A LIVE SIMULATION. Streamlit Community Cloud cannot
run POX or Mininet, and importing the coordinator machinery into the dashboard
would pull a threading/socket server into a page render. The panel is therefore
read-only illustrative content driven by this file, and dashboard.py never
imports ddos_sdn.coordinator.

WHY THE FIXTURE CANNOT DRIFT INTO FICTION. A committed fixture describing
behavior the real coordinator would never produce is worse than no panel at
all. tests/test_dashboard.py feeds this exact file through the REAL
CoordinatorServer.correlate() and asserts the drop rules it yields are the ones
Panel 5 claims. If the scenario below and server.py ever disagree, that test
fails.

THE SCENARIO (20 records). Built to demonstrate the correlation LOGIC, not just
a coincidence. A fixture where two workers happen to agree would show nothing
about why the coordinator exists.

    1-4    benign lead-in, both workers, rotating top_src   -> nothing
    5      worker-1 ATTACK on 10.0.0.1                      -> below threshold
    6      worker-2 ATTACK on 10.0.0.3 (DIFFERENT src)      -> NO drop rule:
           two simultaneous ATTACK reports that correctly produce nothing,
           because correlation keys on top_src, not on attack-ness
    7      worker-1 ATTACK on 10.0.0.5                      -> still unmatched
    8      worker-2 ATTACK on 10.0.0.5 (MATCHES #7)         -> DROP RULE for
           10.0.0.5, dispatched to both workers
    9-12   post-mitigation, both workers benign             -> nothing
    13-16  attacker retries from 10.0.0.5, both corroborate -> SECOND drop rule
    17-20  sustained benign, rule holding                   -> nothing

Records 5-6 are the load-bearing part of the story: they are what proves the
coordinator requires a matching source rather than merely two alarms.

WIRE FORMAT. Field-exact against src/ddos_sdn/coordinator/protocol.py:
WORKER_TELEMETRY requires (type, schema_version, worker_id, record). The three
extra keys inside `record` (dpid, in_port, hard_timeout) are legal: validate()
is lax on extras, and server.correlate() reads exactly those three when it
builds the DROP_RULE_COMMAND. Serialized with json.dumps(separators=(",", ":"))
to match protocol.encode() byte-for-byte.

Determinism: no RNG at all. The scenario is a literal table, so the output is
identical on every run and every machine.

Usage:

    python scripts/build_coordinator_replay.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from ddos_sdn.coordinator.protocol import SCHEMA_VERSION, MessageType  # noqa: E402

SAMPLES_DIR = REPO_ROOT / "samples"
OUTPUT_JSONL = SAMPLES_DIR / "coordinator_replay.jsonl"

WORKER_1 = "worker-1"
WORKER_2 = "worker-2"

# dpid/in_port per worker: matches the two-worker partition in config.yaml
# (worker-1 owns dpids 1-2, worker-2 owns 3-4). server.correlate() reads these
# off each worker's own record, so each worker's drop rule is scoped to the
# switch it actually reported.
WORKER_DPID = {WORKER_1: 1, WORKER_2: 3}
WORKER_IN_PORT = {WORKER_1: 3, WORKER_2: 2}
HARD_TIMEOUT = 30

VICTIM = "10.0.0.64"
ATTACKER = "10.0.0.5"  # the source both workers eventually agree on

# (worker, top_src, verdict) per record. Timestamps are assigned below.
# Kept as a literal table so the scenario is reviewable at a glance and diffs
# legibly if it is ever revised.
SCENARIO: tuple[tuple[str, str, str], ...] = (
    # 1-4: benign lead-in, rotating sources, no correlation possible.
    (WORKER_1, "203.0.113.11", "BENIGN"),
    (WORKER_2, "203.0.113.24", "BENIGN"),
    (WORKER_1, "203.0.113.37", "BENIGN"),
    (WORKER_2, "203.0.113.52", "BENIGN"),
    # 5: worker-1 alone flags an attacker. One worker is below threshold.
    (WORKER_1, "10.0.0.1", "ATTACK"),
    # 6: worker-2 flags a DIFFERENT source. Two ATTACKs, no match, no rule.
    (WORKER_2, "10.0.0.3", "ATTACK"),
    # 7-8: both workers converge on the same source -> first drop rule.
    (WORKER_1, ATTACKER, "ATTACK"),
    (WORKER_2, ATTACKER, "ATTACK"),
    # 9-12: post-mitigation quiet.
    (WORKER_1, "203.0.113.63", "BENIGN"),
    (WORKER_2, "203.0.113.78", "BENIGN"),
    (WORKER_1, "203.0.113.91", "BENIGN"),
    (WORKER_2, "203.0.113.104", "BENIGN"),
    # 13-16: attacker retries from the same source; both corroborate again.
    (WORKER_1, ATTACKER, "ATTACK"),
    (WORKER_2, ATTACKER, "ATTACK"),
    (WORKER_1, ATTACKER, "ATTACK"),
    (WORKER_2, ATTACKER, "ATTACK"),
    # 17-20: sustained benign, drop rule holding.
    (WORKER_1, "203.0.113.117", "BENIGN"),
    (WORKER_2, "203.0.113.130", "BENIGN"),
    (WORKER_1, "203.0.113.143", "BENIGN"),
    (WORKER_2, "203.0.113.156", "BENIGN"),
)

# Seconds between consecutive records. Well inside the default
# tolerance_window_seconds=1.0 so a worker-1/worker-2 pair lands in the same
# (or an adjacent) correlation bucket, which is what server.correlate()
# requires to see them as corroborating.
RECORD_INTERVAL_S = 0.2


def _telemetry_record(top_src: str, verdict: str, worker_id: str, t: float) -> dict:
    """One 13-field telemetry record plus the three routing keys correlate() reads."""
    attack = verdict == "ATTACK"
    return {
        # --- the locked 13 fields, in TelemetryEmitter.FIELDS order ---
        "t": round(t, 3),
        "window_packets": 250,
        "entropy_dst": 0.0 if attack else 5.83,
        "entropy_src": 0.0 if attack else 7.18,
        "entropy_size": 0.0 if attack else 2.57,
        "pps": 1004,
        "pca_mahalanobis": 51.14 if attack else 1.98,
        "rf_proba": 0.99 if attack else 0.01,
        "verdict_entropy": verdict,
        "verdict_pca": verdict,
        "verdict_rf": verdict,
        "top_dst": VICTIM if attack else "10.0.0.19",
        "top_src": top_src,
        # --- extras: not part of the 13-field contract, read by correlate() ---
        "dpid": WORKER_DPID[worker_id],
        "in_port": WORKER_IN_PORT[worker_id],
        "hard_timeout": HARD_TIMEOUT,
    }


def build_messages() -> list[dict]:
    """Build the WORKER_TELEMETRY message list for the scripted scenario."""
    messages = []
    for i, (worker_id, top_src, verdict) in enumerate(SCENARIO):
        messages.append(
            {
                "type": MessageType.WORKER_TELEMETRY.value,
                "schema_version": SCHEMA_VERSION,
                "worker_id": worker_id,
                "record": _telemetry_record(top_src, verdict, worker_id, i * RECORD_INTERVAL_S),
            }
        )
    return messages


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build samples/coordinator_replay.jsonl (Phase 4d.1 §4d.1.F).",
    )
    parser.add_argument(
        "--output",
        default=str(OUTPUT_JSONL),
        help=f"output path (default: {OUTPUT_JSONL.relative_to(REPO_ROOT)})",
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    messages = build_messages()
    # Explicit "\n" join + newline="" so the file is byte-identical across
    # Windows/Linux/macOS, matching the determinism discipline in
    # scripts/build_synth_dataset.py.
    body = "".join(json.dumps(m, separators=(",", ":")) + "\n" for m in messages)
    output_path.write_text(body, encoding="utf-8", newline="")

    n_attack = sum(1 for _, _, v in SCENARIO if v == "ATTACK")
    print(f"build_coordinator_replay: wrote {output_path}")
    print(f"build_coordinator_replay:   records={len(messages)}  attack={n_attack}")
    print(f"build_coordinator_replay:   sha256={_sha256(output_path)}")
    print(f"build_coordinator_replay:   bytes={output_path.stat().st_size}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
