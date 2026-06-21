"""Phase 4b §4b.A — East-West wire protocol.

JSON over TCP, line-delimited. Pure-stdlib, no new dependencies. The
serialization shape mirrors the existing telemetry contract from
ddos_sdn.detector.telemetry; the cross-phase forward-compat story is
the same one Phase 1 §1.E baked into the 13-field schema.

Three message types, distinguished by a top-level `type` field:

    WORKER_TELEMETRY   — worker → coordinator, one per closed entropy window.
                         Carries the existing 13-field telemetry record
                         verbatim under a `record` field, plus a `worker_id`
                         envelope so the coordinator knows who reported it.

    DROP_RULE_COMMAND  — coordinator → worker, when cross-worker correlation
                         decides to mitigate. Carries the (dpid, in_port,
                         nw_src, hard_timeout) tuple plus a UUID command_id.

    ACK                — worker → coordinator, confirms the drop rule was
                         dispatched as an ofp_flow_mod. Echoes the
                         command_id so the coordinator can close the loop.

# ---------------------------------------------------------------------
# SCHEMA_VERSION = 1.  Bump-on-change rule (mirrors Phase 1 §1.E):
# ---------------------------------------------------------------------
#
#   1. Never remove a message type.
#   2. Never repurpose a field. (A field named `nw_src` always means
#      "the source IP the drop rule targets", forever.)
#   3. New fields can be APPENDED to existing message types without
#      bumping SCHEMA_VERSION. Readers MUST tolerate unknown
#      additional fields — that is the additive-evolution path.
#   4. SCHEMA_VERSION bumps if and only if the field set semantically
#      breaks — e.g. renaming `nw_src` to `attacker_ip`, changing
#      `hard_timeout` from seconds to milliseconds, or removing a
#      message type. After a bump, the prior schema is dead; mixed
#      clusters at boundary versions are unsupported.
#   5. The bump itself is one line: SCHEMA_VERSION += 1. Document the
#      change in this module docstring with a "v1 → v2" section and
#      update every test that hardcodes the integer.
#
# validate() contract — strict on identity, lax on additions:
#
#   - RAISES ProtocolError when:
#       * `type` is missing
#       * `type` is not one of MessageType's defined enum values
#       * `schema_version` is missing
#       * `schema_version` does not equal SCHEMA_VERSION
#       * any required field for the declared type is missing
#         (e.g. WORKER_TELEMETRY without `worker_id` or `record`)
#   - DOES NOT RAISE on:
#       * unknown additional fields beyond the required set
#         (rule-3 additive-evolution path; a v1 reader must accept a
#          v1 message that carries a future-added optional field and
#          silently ignore it)
#
# The strict/lax split is the whole reason this contract has a
# forward-compat story at all. Strict on type values + schema_version
# keeps mixed-version clusters safely rejected at the boundary;
# lax on extra fields means an upgrade can add an optional field
# without forcing a version bump.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = 1


class MessageType(StrEnum):
    """Closed set of message types on the East-West channel."""

    WORKER_TELEMETRY = "WORKER_TELEMETRY"
    DROP_RULE_COMMAND = "DROP_RULE_COMMAND"
    ACK = "ACK"


class ProtocolError(ValueError):
    """Raised by validate() and decode() when the message shape is wrong."""


# Required field set per message type. validate() raises if any of these
# are absent from the decoded dict. Additional unknown fields are tolerated.
_REQUIRED_FIELDS: dict[MessageType, tuple[str, ...]] = {
    MessageType.WORKER_TELEMETRY: ("type", "schema_version", "worker_id", "record"),
    MessageType.DROP_RULE_COMMAND: (
        "type",
        "schema_version",
        "command_id",
        "dpid",
        "in_port",
        "nw_src",
        "hard_timeout",
    ),
    MessageType.ACK: ("type", "schema_version", "worker_id", "command_id"),
}


def validate(msg: dict[str, Any]) -> None:
    """Raise ProtocolError if `msg` violates the v1 schema.

    Strict on `type` and `schema_version`; strict on required fields per
    type; LAX on extra fields (rule 3, additive-evolution path).
    """
    if not isinstance(msg, dict):
        raise ProtocolError(f"message must be a dict, got {type(msg).__name__}")

    if "type" not in msg:
        raise ProtocolError("missing required field: type")
    msg_type_raw = msg["type"]
    try:
        msg_type = MessageType(msg_type_raw)
    except ValueError as exc:
        raise ProtocolError(
            f"unknown message type: {msg_type_raw!r}; "
            f"expected one of {[m.value for m in MessageType]}"
        ) from exc

    if "schema_version" not in msg:
        raise ProtocolError("missing required field: schema_version")
    if msg["schema_version"] != SCHEMA_VERSION:
        raise ProtocolError(
            f"schema_version mismatch: got {msg['schema_version']!r}, " f"expected {SCHEMA_VERSION}"
        )

    required = _REQUIRED_FIELDS[msg_type]
    missing = [f for f in required if f not in msg]
    if missing:
        raise ProtocolError(f"{msg_type.value} message missing required field(s): {missing}")


def encode(msg: dict[str, Any]) -> bytes:
    """Serialize `msg` to a UTF-8 JSON line (newline-terminated)."""
    validate(msg)
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


def decode(line: bytes) -> dict[str, Any]:
    """Parse a single newline-terminated JSON line; validate; return dict.

    The caller is responsible for delimiting frames on the wire (one JSON
    object per `\\n`-terminated chunk). This function expects exactly one
    object's worth of bytes (trailing `\\n` is optional).
    """
    if not isinstance(line, (bytes, bytearray)):
        raise ProtocolError(f"decode() expects bytes, got {type(line).__name__}")
    text = line.decode("utf-8").rstrip("\n").rstrip("\r")
    try:
        msg = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc
    validate(msg)
    return msg
