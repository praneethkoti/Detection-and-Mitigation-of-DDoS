"""Phase 4b §4b.F — wire protocol unit tests.

Five tests:
    - 3 round-trip tests, one per message type (WORKER_TELEMETRY,
      DROP_RULE_COMMAND, ACK). Encode -> decode must reconstruct the
      original dict.
    - Unknown type rejection: decode() raises ProtocolError on a
      message whose `type` is not in MessageType's enum.
    - Schema version mismatch rejection: decode() raises ProtocolError
      on a message whose `schema_version` differs from SCHEMA_VERSION.

These tests lock the cross-phase contract. If a future phase adds a
new message type without updating the enum, or bumps SCHEMA_VERSION
without updating the test integer, these fail loudly first.
"""

from __future__ import annotations

import pytest

from ddos_sdn.coordinator.protocol import (
    SCHEMA_VERSION,
    MessageType,
    ProtocolError,
    decode,
    encode,
)


def test_encode_decode_round_trip_worker_telemetry() -> None:
    msg = {
        "type": MessageType.WORKER_TELEMETRY.value,
        "schema_version": SCHEMA_VERSION,
        "worker_id": "worker-1",
        "record": {
            "t": 1.234,
            "window_packets": 250,
            "entropy_dst": 5.91,
            "entropy_src": 7.11,
            "entropy_size": 2.57,
            "pps": 287,
            "pca_mahalanobis": None,
            "rf_proba": None,
            "verdict_entropy": "BENIGN",
            "verdict_pca": None,
            "verdict_rf": None,
            "top_dst": "10.0.0.7",
            "top_src": "203.0.113.170",
        },
    }
    wire = encode(msg)
    assert wire.endswith(b"\n")
    decoded = decode(wire)
    assert decoded == msg


def test_encode_decode_round_trip_drop_rule_command() -> None:
    msg = {
        "type": MessageType.DROP_RULE_COMMAND.value,
        "schema_version": SCHEMA_VERSION,
        "command_id": "abc-123-def-456",
        "dpid": 1,
        "in_port": 3,
        "nw_src": "10.0.0.1",
        "hard_timeout": 30,
        "reason": "cross-worker correlation: top_src=10.0.0.1 seen on worker-1, worker-2",
    }
    decoded = decode(encode(msg))
    assert decoded == msg


def test_encode_decode_round_trip_ack() -> None:
    msg = {
        "type": MessageType.ACK.value,
        "schema_version": SCHEMA_VERSION,
        "worker_id": "worker-1",
        "command_id": "abc-123-def-456",
        "dispatched_at_t": 12.345,
    }
    decoded = decode(encode(msg))
    assert decoded == msg


def test_unknown_type_raises_protocol_error() -> None:
    """A v1 reader must reject messages whose `type` is not in MessageType."""
    raw = b'{"type":"NOPE","schema_version":1}\n'
    with pytest.raises(ProtocolError, match="unknown message type"):
        decode(raw)


def test_schema_version_mismatch_raises_protocol_error() -> None:
    """A v1 reader must reject messages from a future or past schema_version."""
    raw = b'{"type":"ACK","schema_version":999,' b'"worker_id":"w","command_id":"x"}\n'
    with pytest.raises(ProtocolError, match="schema_version mismatch"):
        decode(raw)
