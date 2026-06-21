"""Phase 4b §4b.B — Coordinator TCP server.

Accepts JSON-over-TCP connections from worker controllers, correlates
per-window telemetry across workers using tolerance-window bucketing,
and dispatches DROP_RULE_COMMAND when min_corroborating_workers report
the same top_src + verdict_entropy=ATTACK within the same time bucket
(or the immediately-prior bucket — see §4b.B current+previous lookup).

Correlation rule (locked decisions Q2 + user note a):

    time_bucket = floor(coordinator_receive_time / tolerance_window_seconds)

    On every WORKER_TELEMETRY with verdict_entropy=="ATTACK", look up
    other recent messages with the same top_src in BOTH:
        bucket B   (the current bucket)
        bucket B-1 (the previous bucket — boundary-crossing lookup
                    so messages straddling a bucket boundary still
                    correlate; see test_correlation_across_bucket_boundary)

    If the count of DISTINCT workers across the union of buckets is
    >= min_corroborating_workers, fire _issue_drop_rule(...) which
    dispatches DROP_RULE_COMMAND to each worker in the corroborating
    group.

Topology partitioning is static and mutually exclusive (locked Q3 +
user note b): coordinator config lists workers with their partition_dpids,
and _validate_partition_dpids() raises ValueError at startup if any
dpid appears in two workers' lists. The regression guard is
tests/test_coordinator_correlation.py::test_overlapping_partition_dpids_raises.

This module's correlate() entry point is designed for unit testing
without sockets (locked Q5): tests call correlate(record, worker_id,
sender=fake_sender_fn) directly with an injectable clock and an
injectable sender. The serve_forever() socket path is verified via
the docker-compose --profile distributed walkthrough in the README,
not pytest.
"""

from __future__ import annotations

import logging
import math
import socket
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from ddos_sdn.coordinator.protocol import (
    SCHEMA_VERSION,
    MessageType,
    ProtocolError,
    decode,
    encode,
)

logger = logging.getLogger(__name__)


class CoordinatorServer:
    """JSON-over-TCP coordinator. Correlates per-window telemetry across workers."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9876,
        tolerance_window_seconds: float = 1.0,
        min_corroborating_workers: int = 2,
        workers: list[dict[str, Any]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Construct the coordinator.

        Args:
            host, port: TCP listen address.
            tolerance_window_seconds: bucket size for per-window correlation.
                Default 1.0s. See module docstring for the boundary-crossing
                lookup semantic.
            min_corroborating_workers: how many distinct workers must report
                the same top_src + ATTACK within the correlation window for
                the coordinator to issue a DROP_RULE_COMMAND. Default 2.
            workers: list of {"worker_id": str, "partition_dpids": list[int]}.
                Validates mutually-exclusive partition_dpids at __init__;
                raises ValueError on overlap.
            clock: monotonic-time callable for testability. Defaults to
                time.monotonic. Tests inject a deterministic clock so
                tolerance-window behavior is reproducible without sleeps.
        """
        self.host = host
        self.port = port
        self.tolerance_window_seconds = float(tolerance_window_seconds)
        if self.tolerance_window_seconds <= 0:
            raise ValueError(
                f"tolerance_window_seconds must be > 0, got {tolerance_window_seconds}"
            )
        self.min_corroborating_workers = int(min_corroborating_workers)
        if self.min_corroborating_workers < 1:
            raise ValueError(
                f"min_corroborating_workers must be >= 1, " f"got {min_corroborating_workers}"
            )

        self.workers = workers or []
        self._validate_partition_dpids(self.workers)
        # dpid -> worker_id, used by _issue_drop_rule when a coordinating group
        # is found across buckets and the coordinator needs to know which
        # worker owns the affected dpid.
        self._dpid_to_worker_id: dict[int, str] = {}
        for w in self.workers:
            for d in w.get("partition_dpids", []):
                self._dpid_to_worker_id[d] = w["worker_id"]

        self.clock: Callable[[], float] = clock if clock is not None else time.monotonic

        # Correlation state: bucket_index -> top_src -> list of (worker_id, record).
        # Old buckets older than current_bucket - 1 are evicted on every
        # correlate() call (2-bucket retention to support current+previous
        # lookup).
        self._buckets: dict[int, dict[str, list[tuple[str, dict]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._buckets_lock = threading.Lock()

        # Issued-command tracking: command_id -> (issued_at_t, target_worker_id).
        # Tests inspect this; runtime uses it to correlate ACKs.
        self.issued_commands: dict[str, dict[str, Any]] = {}
        # ACK tracking: command_id -> ack dict.
        self.received_acks: dict[str, dict[str, Any]] = {}

        # Open client sockets keyed by worker_id (populated by serve_forever()).
        # Tests don't touch this; they call correlate() with a custom sender.
        self._worker_sockets: dict[str, socket.socket] = {}
        self._sockets_lock = threading.Lock()

        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Startup validation (locked Q3 + user note b)
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_partition_dpids(workers: list[dict[str, Any]]) -> None:
        """Fail loudly if any dpid appears in more than one worker's partition.

        Prevents the silent failure mode where two workers both think they
        own dpid 3 and the cross-worker "correlation" degrades into
        self-correlation. The regression guard is
        tests/test_coordinator_correlation.py::test_overlapping_partition_dpids_raises.
        """
        seen: dict[int, str] = {}
        for w in workers:
            wid = w.get("worker_id")
            if wid is None:
                raise ValueError(f"coordinator config: worker entry missing worker_id: {w!r}")
            for dpid in w.get("partition_dpids", []):
                if dpid in seen:
                    raise ValueError(
                        f"coordinator config: dpid={dpid} assigned to both "
                        f"{seen[dpid]!r} and {wid!r} — partition_dpids must be "
                        f"mutually exclusive across workers."
                    )
                seen[dpid] = wid

    # ------------------------------------------------------------------
    # Correlation core (unit-testable without sockets)
    # ------------------------------------------------------------------

    def _bucket_index(self, t: float) -> int:
        """floor(t / tolerance_window_seconds). The bucket key."""
        return math.floor(t / self.tolerance_window_seconds)

    def _evict_old_buckets(self, current_bucket: int) -> None:
        """Drop buckets older than current_bucket - 1 (2-bucket retention).

        The 2-bucket retention is the minimum that supports the
        current+previous lookup pattern in correlate().
        """
        # Snapshot the keys before mutation to avoid "dict changed size
        # during iteration".
        for b in list(self._buckets.keys()):
            if b < current_bucket - 1:
                del self._buckets[b]

    def correlate(
        self,
        record: dict[str, Any],
        worker_id: str,
        sender: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Ingest one WORKER_TELEMETRY record. Return list of issued commands.

        This is the unit-testable entry point. The serve_forever() path
        calls this method after decoding a frame off the wire; tests call
        it directly with a fake sender that just appends commands to a
        list (no real sockets).

        Args:
            record: the 13-field telemetry record (the "record" payload of
                a WORKER_TELEMETRY message). Must include "top_src" and
                "verdict_entropy"; "dpid" is optional (used to pick the
                target worker for the drop rule).
            worker_id: who reported it.
            sender: callable (target_worker_id, command_dict) -> None,
                invoked once per worker in the corroborating group. If
                None, defaults to self._send_command_via_socket which
                writes to the registered worker socket.

        Returns:
            list of DROP_RULE_COMMAND dicts issued this call (may be empty).
        """
        receive_time = self.clock()
        current_bucket = self._bucket_index(receive_time)
        top_src = record.get("top_src")
        verdict = record.get("verdict_entropy")

        with self._buckets_lock:
            self._evict_old_buckets(current_bucket)

            # Only ATTACK records participate in correlation. BENIGN records
            # are still stored (a future verdict might still need them for
            # debugging) but they will never trigger a command on their own.
            self._buckets[current_bucket][str(top_src)].append((worker_id, record))

            if verdict != "ATTACK" or top_src is None:
                return []

            # Boundary-crossing lookup: aggregate distinct workers across
            # bucket B and bucket B-1.
            corroborating: dict[str, dict[str, Any]] = {}  # worker_id -> their record
            for b in (current_bucket, current_bucket - 1):
                for entry_worker_id, entry_record in self._buckets.get(b, {}).get(str(top_src), []):
                    if entry_record.get("verdict_entropy") != "ATTACK":
                        continue
                    # Take the FIRST record seen per worker_id (don't
                    # overwrite with a later one; the first ATTACK report
                    # is the one we want to corroborate against).
                    if entry_worker_id not in corroborating:
                        corroborating[entry_worker_id] = entry_record

            if len(corroborating) < self.min_corroborating_workers:
                return []

            # Build DROP_RULE_COMMAND for each corroborating worker.
            send = sender if sender is not None else self._send_command_via_socket
            issued: list[dict[str, Any]] = []
            for w_id, w_record in corroborating.items():
                cmd = self._build_drop_rule_command(
                    target_worker_id=w_id,
                    target_record=w_record,
                    nw_src=str(top_src),
                    reason=(
                        f"cross-worker correlation: top_src={top_src} "
                        f"seen on {sorted(corroborating.keys())}"
                    ),
                )
                self.issued_commands[cmd["command_id"]] = {
                    "issued_at_t": receive_time,
                    "target_worker_id": w_id,
                    "command": cmd,
                }
                logger.info(
                    "INSTALL: dpid=%s in_port=%s nw_src=%s target=%s command_id=%s",
                    cmd["dpid"],
                    cmd["in_port"],
                    cmd["nw_src"],
                    w_id,
                    cmd["command_id"],
                )
                try:
                    send(w_id, cmd)
                except Exception as exc:
                    logger.warning(
                        "coordinator: failed to dispatch command to %s: %s",
                        w_id,
                        exc,
                    )
                issued.append(cmd)
            return issued

    def _build_drop_rule_command(
        self,
        target_worker_id: str,
        target_record: dict[str, Any],
        nw_src: str,
        reason: str,
    ) -> dict[str, Any]:
        """Construct a DROP_RULE_COMMAND dict matching the §4b.A schema."""
        dpid = target_record.get("dpid", 1)
        in_port = target_record.get("in_port", 0)
        hard_timeout = int(target_record.get("hard_timeout", 30))
        return {
            "type": MessageType.DROP_RULE_COMMAND.value,
            "schema_version": SCHEMA_VERSION,
            "command_id": str(uuid.uuid4()),
            "dpid": int(dpid),
            "in_port": int(in_port),
            "nw_src": nw_src,
            "hard_timeout": hard_timeout,
            "reason": reason,
        }

    def handle_ack(self, ack: dict[str, Any]) -> None:
        """Record an ACK for a previously issued command. Used by both the
        live socket path and the unit tests."""
        cmd_id = ack.get("command_id")
        if cmd_id is None:
            logger.warning("coordinator: received ACK without command_id: %r", ack)
            return
        self.received_acks[cmd_id] = ack
        logger.info(
            "coordinator: ACK from %s for command_id=%s dispatched_at_t=%s",
            ack.get("worker_id"),
            cmd_id,
            ack.get("dispatched_at_t"),
        )

    # ------------------------------------------------------------------
    # Live-socket path (verified via docker-compose, not pytest)
    # ------------------------------------------------------------------

    def _send_command_via_socket(self, target_worker_id: str, command: dict[str, Any]) -> None:
        """Write an encoded command to the worker's registered socket.

        Called by correlate()'s default sender. Tests pass their own sender
        so this path isn't exercised in pytest.
        """
        with self._sockets_lock:
            sock = self._worker_sockets.get(target_worker_id)
        if sock is None:
            logger.warning(
                "coordinator: no socket registered for worker_id=%r; " "command_id=%s dropped",
                target_worker_id,
                command.get("command_id"),
            )
            return
        try:
            sock.sendall(encode(command))
        except OSError as exc:
            logger.warning(
                "coordinator: send failed to %s: %s; dropping socket",
                target_worker_id,
                exc,
            )
            with self._sockets_lock:
                self._worker_sockets.pop(target_worker_id, None)

    def _handle_client(self, sock: socket.socket, addr: tuple[str, int]) -> None:
        """Worker thread for one accepted socket. Reads line-delimited JSON."""
        logger.info("coordinator: worker connected from %s:%d", addr[0], addr[1])
        worker_id: str | None = None
        buf = b""
        try:
            while not self._stop_event.is_set():
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        msg = decode(line + b"\n")
                    except ProtocolError as exc:
                        logger.warning(
                            "coordinator: decode error from %s: %s; dropping connection",
                            addr,
                            exc,
                        )
                        return
                    mtype = msg["type"]
                    if mtype == MessageType.WORKER_TELEMETRY.value:
                        worker_id = msg["worker_id"]
                        with self._sockets_lock:
                            self._worker_sockets[worker_id] = sock
                        self.correlate(msg["record"], worker_id)
                    elif mtype == MessageType.ACK.value:
                        self.handle_ack(msg)
                    else:
                        logger.warning(
                            "coordinator: unexpected message type from worker: %s",
                            mtype,
                        )
                        return
        except OSError as exc:
            logger.info("coordinator: socket error from %s: %s", addr, exc)
        finally:
            if worker_id is not None:
                with self._sockets_lock:
                    self._worker_sockets.pop(worker_id, None)
            try:
                sock.close()
            except OSError:
                pass
            logger.info("coordinator: worker %s disconnected", worker_id or addr)

    def serve_forever(self) -> None:
        """Accept loop. Each connection runs in its own daemon thread."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(8)
            listener.settimeout(0.5)  # so we can poll _stop_event
            logger.info(
                "coordinator: listening on %s:%d (tolerance=%.2fs, min_workers=%d)",
                self.host,
                self.port,
                self.tolerance_window_seconds,
                self.min_corroborating_workers,
            )
            while not self._stop_event.is_set():
                try:
                    client_sock, addr = listener.accept()
                except TimeoutError:
                    continue
                except OSError as exc:
                    logger.warning("coordinator: accept() failed: %s", exc)
                    continue
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                t.start()

    def shutdown(self) -> None:
        """Signal serve_forever() to stop on its next iteration."""
        self._stop_event.set()


def _load_config_and_run() -> int:
    """CLI entrypoint: python -m ddos_sdn.coordinator.server."""
    from ddos_sdn.config import load_config

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config()
    coord_cfg = cfg.get("coordinator", {})
    if not coord_cfg.get("enabled", False):
        logger.warning(
            "coordinator: config.yaml::coordinator.enabled is False; "
            "starting anyway (the live process is the source of truth)"
        )
    server = CoordinatorServer(
        host=coord_cfg.get("host", "0.0.0.0"),
        port=coord_cfg.get("port", 9876),
        tolerance_window_seconds=coord_cfg.get("tolerance_window_seconds", 1.0),
        min_corroborating_workers=coord_cfg.get("min_corroborating_workers", 2),
        workers=coord_cfg.get("workers", []),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(_load_config_and_run())
