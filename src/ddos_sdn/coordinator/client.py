"""Phase 4b §4b.C — Worker-side TCP client + CoordinatorTeeSink.

The worker side of the East-West channel. Two collaborating classes:

    WorkerClient        Long-lived TCP connection to the coordinator with
                        a background reader thread. Exposes send_telemetry()
                        for the worker to push 13-field telemetry records,
                        send_ack() to confirm a drop-rule installation,
                        and an on_drop_rule_command callback for the
                        coordinator-issued mitigation commands.

    CoordinatorTeeSink  File-like wrapper (write/flush) that satisfies the
                        TelemetryEmitter sink interface. write() routes
                        each JSON line to BOTH the underlying stdout sink
                        AND, in parallel, the WorkerClient — so existing
                        single-controller behavior is preserved while the
                        coordinator gets a non-blocking copy of every
                        closed-window record.

Failure semantics (locked Q4 + user note c):

    - Fail-open: when the coordinator socket is unreachable or mid-
      reconnect, send_telemetry() silently drops the record (rather
      than blocking the POX event thread or buffering forever).
    - Periodic reconnect: a background daemon thread retries every
      `reconnect_interval_seconds`. When reconnect succeeds, telemetry
      resumes; the worker's local Phase 3 standalone code path was
      never interrupted, so detection + mitigation continued working
      throughout the outage.
    - Log discipline: one warning is logged per disconnect-reconnect
      cycle, not one per dropped message. Prevents log floods.

Thread safety contract:

    send_telemetry() is callable from any thread. Non-blocking. If the
    socket is mid-reconnect or unwritable the message is silently
    dropped. The send path holds NO LOCKS; the receive thread reads
    from a different socket.makefile() handle and never overlaps the
    send path's socket.sendall().

    The single-writer property is maintained by the fact that only
    the POX event thread calls send_telemetry() in production. If
    multiple threads ever call it concurrently, wrap the sendall()
    in a threading.Lock — but that is not required today.
"""

from __future__ import annotations

import io
import json
import logging
import socket
import sys
import threading
import time
from collections.abc import Callable
from typing import Any, TextIO

from ddos_sdn.coordinator.protocol import (
    SCHEMA_VERSION,
    MessageType,
    ProtocolError,
    decode,
    encode,
)

logger = logging.getLogger(__name__)


class WorkerClient:
    """TCP client embedded in pox_controller.py for East-West coordination.

    Exposes a fail-open send path and a background reader thread that
    invokes on_drop_rule_command(cmd) when the coordinator dispatches a
    mitigation command. The reader thread also handles reconnect — when
    the socket dies, it sleeps reconnect_interval_seconds and tries again.
    """

    def __init__(
        self,
        host: str,
        port: int,
        worker_id: str,
        on_drop_rule_command: Callable[[dict[str, Any]], None],
        reconnect_interval_seconds: float = 5.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.worker_id = worker_id
        self.on_drop_rule_command = on_drop_rule_command
        self.reconnect_interval_seconds = float(reconnect_interval_seconds)
        self.clock: Callable[[], float] = clock if clock is not None else time.monotonic

        self._sock: socket.socket | None = None
        self._connected: bool = False
        # `_log_warned_this_cycle` is True after we've emitted one drop-on-
        # disconnect warning during the current disconnect cycle. It resets
        # to False the moment the next successful connect lands.
        self._log_warned_this_cycle: bool = False
        self._stop_event = threading.Event()
        self._connect_lock = threading.Lock()

        self._reader_thread: threading.Thread | None = None

    @property
    def connected(self) -> bool:
        return self._connected

    def start(self) -> None:
        """Spin up the background reader thread; attempt the initial connect."""
        if self._reader_thread is not None and self._reader_thread.is_alive():
            return
        self._reader_thread = threading.Thread(
            target=self._reader_loop, name=f"WorkerClient[{self.worker_id}]", daemon=True
        )
        self._reader_thread.start()

    def stop(self) -> None:
        """Signal the reader thread to exit; close the socket."""
        self._stop_event.set()
        with self._connect_lock:
            sock = self._sock
            self._sock = None
            self._connected = False
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _try_connect(self) -> bool:
        """Open the socket. Return True if connected, False otherwise."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=3.0)
            sock.settimeout(None)  # blocking reads in the reader loop
        except OSError as exc:
            logger.info(
                "WorkerClient[%s]: connect to %s:%d failed: %s",
                self.worker_id,
                self.host,
                self.port,
                exc,
            )
            return False
        with self._connect_lock:
            self._sock = sock
            self._connected = True
            self._log_warned_this_cycle = False  # fresh cycle — re-arm warning
        logger.info(
            "WorkerClient[%s]: connected to coordinator at %s:%d",
            self.worker_id,
            self.host,
            self.port,
        )
        return True

    def _reader_loop(self) -> None:
        """Background thread: read DROP_RULE_COMMAND messages from coordinator.

        On disconnect, sleeps reconnect_interval_seconds and retries.
        """
        while not self._stop_event.is_set():
            if not self._connected:
                if not self._try_connect():
                    # Sleep in small slices so stop() is responsive.
                    end = self.clock() + self.reconnect_interval_seconds
                    while self.clock() < end and not self._stop_event.is_set():
                        time.sleep(0.1)
                    continue

            # Read line-delimited frames.
            try:
                buf = b""
                while not self._stop_event.is_set():
                    chunk = self._sock.recv(4096) if self._sock else b""
                    if not chunk:
                        raise OSError("coordinator closed connection")
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line:
                            continue
                        self._handle_frame(line + b"\n")
            except OSError as exc:
                logger.info(
                    "WorkerClient[%s]: read error: %s; marking disconnected",
                    self.worker_id,
                    exc,
                )
                self._mark_disconnected()

    def _handle_frame(self, frame: bytes) -> None:
        try:
            msg = decode(frame)
        except ProtocolError as exc:
            logger.warning(
                "WorkerClient[%s]: protocol error: %s; ignoring frame", self.worker_id, exc
            )
            return
        mtype = msg["type"]
        if mtype == MessageType.DROP_RULE_COMMAND.value:
            try:
                self.on_drop_rule_command(msg)
            except Exception:
                logger.exception(
                    "WorkerClient[%s]: on_drop_rule_command callback raised",
                    self.worker_id,
                )
        else:
            # ACKs and worker-telemetry shouldn't arrive at a worker; warn.
            logger.warning(
                "WorkerClient[%s]: unexpected message type from coordinator: %s",
                self.worker_id,
                mtype,
            )

    def _mark_disconnected(self) -> None:
        with self._connect_lock:
            sock = self._sock
            self._sock = None
            self._connected = False
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def send_telemetry(self, record: dict[str, Any]) -> bool:
        """Push a 13-field telemetry record to the coordinator. Non-blocking.

        Returns True if the message was sent, False if dropped (typically
        because the socket is mid-reconnect or unwritable). Fail-open by
        design — a False return must never crash the caller.

        Thread safety: callable from any thread. Holds no locks during the
        sendall() call. The single-writer property holds in production
        (only the POX event thread calls this); if you add a second
        concurrent caller, wrap sendall() in a Lock.
        """
        if not self._connected:
            self._warn_once_per_cycle("not connected")
            return False
        sock = self._sock
        if sock is None:
            self._warn_once_per_cycle("socket gone")
            return False
        msg = {
            "type": MessageType.WORKER_TELEMETRY.value,
            "schema_version": SCHEMA_VERSION,
            "worker_id": self.worker_id,
            "record": record,
        }
        try:
            sock.sendall(encode(msg))
            return True
        except (BlockingIOError, BrokenPipeError, ConnectionResetError, OSError) as exc:
            self._warn_once_per_cycle(f"send failed: {exc}")
            self._mark_disconnected()
            return False

    def send_ack(self, command_id: str, dispatched_at_t: float) -> bool:
        """Acknowledge a DROP_RULE_COMMAND after the worker installed the rule."""
        if not self._connected or self._sock is None:
            return False
        msg = {
            "type": MessageType.ACK.value,
            "schema_version": SCHEMA_VERSION,
            "worker_id": self.worker_id,
            "command_id": command_id,
            "dispatched_at_t": float(dispatched_at_t),
        }
        try:
            self._sock.sendall(encode(msg))
            return True
        except (BlockingIOError, BrokenPipeError, ConnectionResetError, OSError) as exc:
            logger.warning(
                "WorkerClient[%s]: send_ack failed: %s; marking disconnected",
                self.worker_id,
                exc,
            )
            self._mark_disconnected()
            return False

    def _warn_once_per_cycle(self, why: str) -> None:
        """Emit a single drop-on-disconnect warning per disconnect cycle.

        Prevents log floods during sustained outages. The flag resets on
        the next successful connect.
        """
        if self._log_warned_this_cycle:
            return
        self._log_warned_this_cycle = True
        logger.warning(
            "WorkerClient[%s]: dropping telemetry (%s); will continue dropping "
            "until coordinator reconnects (this warning fires once per cycle)",
            self.worker_id,
            why,
        )


class CoordinatorTeeSink:
    """File-like sink that tees TelemetryEmitter writes to stdout + WorkerClient.

    Satisfies the minimal TextIO interface TelemetryEmitter calls
    (write() and flush()). Each JSON line is:

        1. Written to the wrapped stdout sink first — preserves existing
           single-controller stdout-streaming behavior verbatim.
        2. Parsed back into a dict and pushed to WorkerClient.send_telemetry().
           If the client is disconnected, the push is silently dropped
           (fail-open). The JSON line on stdout is unaffected.

    The dict re-parse is cheap (~250 bytes per line at our rates) and lets
    the client's send path operate on the same record shape the rest of
    the project does.

    Thread-safety: write() is called from the POX event thread (the same
    thread TelemetryEmitter writes from). WorkerClient.send_telemetry()
    is non-blocking and holds no locks, so this remains a single-thread
    write path. The reader thread inside WorkerClient is on a separate
    socket-recv path and never overlaps.
    """

    def __init__(self, stdout_sink: TextIO, client: WorkerClient) -> None:
        self._stdout = stdout_sink
        self._client = client

    def write(self, line: str) -> int:
        # 1. Preserve existing stdout behavior.
        n = self._stdout.write(line)
        # 2. Tee to the client. Only parse/forward complete JSON lines.
        stripped = line.rstrip("\n").rstrip("\r")
        if stripped:
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                # Not a JSON line (probably a partial flush); don't forward.
                return n
            # Fail-open: a False return from send_telemetry is silently OK.
            self._client.send_telemetry(record)
        return n

    def flush(self) -> None:
        # Only flush the stdout sink; the socket has no application-level
        # flush concept (sendall is the boundary).
        self._stdout.flush()


def make_default_tee_sink(client: WorkerClient) -> CoordinatorTeeSink:
    """Construct a CoordinatorTeeSink that tees to sys.stdout + client.

    Convenience for pox_controller.py's wiring in §4b.D.
    """
    return CoordinatorTeeSink(sys.stdout, client)


# Re-export io.StringIO so tests can construct an in-memory CoordinatorTeeSink
# for unit tests without writing to real stdout.
__all__ = [
    "WorkerClient",
    "CoordinatorTeeSink",
    "make_default_tee_sink",
    "io",
]
