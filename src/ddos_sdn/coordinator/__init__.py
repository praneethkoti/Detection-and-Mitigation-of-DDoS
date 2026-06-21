"""ddos_sdn.coordinator — Phase 4b multi-controller East-West coordination.

Three sub-modules:

    protocol  — wire format (JSON over TCP, line-delimited). Defines the
                three message types (WORKER_TELEMETRY, DROP_RULE_COMMAND,
                ACK), encode()/decode()/validate(), SCHEMA_VERSION.
    server    — coordinator process. Accepts worker connections, correlates
                per-window telemetry via tolerance-window bucketing,
                dispatches DROP_RULE_COMMAND when min_corroborating_workers
                report the same top_src + verdict_entropy=ATTACK.
    client    — worker-side TCP client embedded in pox_controller.py. Long-
                lived connection with reader thread; fail-open semantics
                (drop telemetry on disconnect; periodic reconnect).

See PROJECT_IMPROVEMENT_PROMPT.md §4.11 and the Phase 4b plan for the
locked decisions: JSON-over-TCP, min_corroborating_workers=2 with
tolerance bucketing + current+previous bucket lookup, static
mutually-exclusive partition_dpids, fail-open standalone fallback,
unit-only tests.
"""
