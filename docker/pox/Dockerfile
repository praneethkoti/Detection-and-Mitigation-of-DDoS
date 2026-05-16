# POX controller image — loads ddos_sdn.detector.pox_controller and exposes
# OpenFlow 1.0 on TCP/6633.
#
# Multi-arch: amd64 and arm64 (Apple Silicon reviewers).
# Phase 3 §3.K.

FROM python:3.11-slim

# System deps for scapy and POX.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        git \
        ca-certificates \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# POX is git-cloned (not pip-installable). Pin to a known-good tag.
RUN git clone --depth 1 --branch gar https://github.com/noxrepo/pox /opt/pox

WORKDIR /app

# Install the project's own deps. requirements.txt covers scapy / psutil /
# pyyaml / scikit-learn / joblib / numpy / pandas; the editable install of
# the package itself happens in the next layer.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# The package source itself.
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
RUN pip install --no-cache-dir -e /app

# Config + models. config.yaml is mounted read-only by docker-compose so the
# operator can edit it without rebuilding. models/ holds the .joblib artifacts.
COPY config.yaml /app/config.yaml
COPY models /app/models

# POX expects to be run from inside its own directory.
WORKDIR /opt/pox

# OpenFlow southbound port.
EXPOSE 6633

# Default command. Compose overrides this with a fuller `pox.py log.level
# --DEBUG ddos_sdn.detector.pox_controller` invocation.
CMD ["python", "pox.py", "ddos_sdn.detector.pox_controller"]
