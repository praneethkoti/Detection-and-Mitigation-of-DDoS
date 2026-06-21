# Phase 4b §4b.G — East-West coordinator image.
#
# Minimal python:3.11-slim base. The coordinator is a pure-stdlib TCP server
# (no POX, no scapy, no ML stack) — it just terminates JSON-over-TCP frames
# from worker controllers and dispatches DROP_RULE_COMMANDs when correlation
# fires. Total image footprint is small by design.
#
# docker-compose entry: `coordinator` service under the `distributed` profile.

FROM python:3.11-slim

WORKDIR /app

# Only PyYAML is needed to read config.yaml. Everything else the
# coordinator uses is stdlib (socket, threading, uuid, math, json).
RUN pip install --no-cache-dir pyyaml

# The project package itself.
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
RUN pip install --no-cache-dir -e /app

# Default config. docker-compose mounts the host's config.yaml read-only
# over this path; this COPY is the fallback for `docker run` without the
# compose volume.
COPY config.yaml /app/config.yaml

# East-West JSON-over-TCP port.
EXPOSE 9876

# `python -m ddos_sdn.coordinator.server` reads config and runs serve_forever().
CMD ["python", "-m", "ddos_sdn.coordinator.server"]
