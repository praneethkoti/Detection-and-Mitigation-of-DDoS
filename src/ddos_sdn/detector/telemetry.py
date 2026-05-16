"""JSON-line telemetry emitter — the project's external contract.

One closed entropy window  ->  one JSON line on the configured sink.
Every downstream consumer (demo.py, dashboard.py, CI smoke tests, jq pipelines)
reads this contract; the field set is closed for Phase 1 and forward-compatible
with Phase 3 / Phase 4 additions:

- never remove a field
- never repurpose a field
- new fields are appended
- "not yet shipped" is signalled by JSON ``null``, never a missing key, 0, or -1

The 13 fields, in order:
    t, window_packets, entropy_dst, entropy_src, entropy_size, pps,
    pca_mahalanobis, rf_proba,
    verdict_entropy, verdict_pca, verdict_rf,
    top_dst, top_src

See PROJECT_IMPROVEMENT_PROMPT.md §5.2 for the field-by-field semantics.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from typing import Any, TextIO


class TelemetryEmitter:
    SCHEMA_VERSION = 1
    FIELDS: tuple[str, ...] = (
        "t",
        "window_packets",
        "entropy_dst",
        "entropy_src",
        "entropy_size",
        "pps",
        "pca_mahalanobis",
        "rf_proba",
        "verdict_entropy",
        "verdict_pca",
        "verdict_rf",
        "top_dst",
        "top_src",
    )

    def __init__(
        self,
        sink: TextIO | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Construct an emitter.

        Args:
            sink:  Where to write JSON lines. Defaults to ``sys.stdout`` so
                   that a developer running the controller sees the stream
                   without configuring anything. Live deployments pass a
                   file handle pointing at ``telemetry.path`` from config.
            clock: Callable returning current time in seconds. Defaults to
                   ``time.monotonic``; tests inject a deterministic clock.
        """
        self._sink: TextIO = sink if sink is not None else sys.stdout
        self._clock: Callable[[], float] = clock if clock is not None else time.monotonic
        self._t0: float = self._clock()

    def now(self) -> float:
        """Seconds since this emitter was instantiated."""
        return self._clock() - self._t0

    def emit(self, **fields: Any) -> dict[str, Any]:
        """Write one JSON line. Returns the dict that was written.

        Missing fields are auto-filled with ``None``. Fields outside the
        13-field schema are rejected — appending new fields requires editing
        ``FIELDS`` in this module so that the contract stays grep-able.
        """
        unknown = set(fields) - set(self.FIELDS)
        if unknown:
            raise ValueError(
                f"telemetry: unknown field(s) {sorted(unknown)}; "
                f"the schema is {self.FIELDS}"
            )
        record: dict[str, Any] = {name: fields.get(name) for name in self.FIELDS}
        self._sink.write(json.dumps(record, separators=(",", ":")))
        self._sink.write("\n")
        self._sink.flush()
        return record
