# Mininet topology image — runs the project's reference tree topology
# (9 switches, 64 hosts) and points it at the pox container.
#
# Multi-arch: amd64 only — Mininet's kernel-namespace dependencies do not
# work cleanly on linux/arm64 hosts. (Apple Silicon reviewers can run pox +
# the detector standalone; full mininet topology requires linux/amd64.)
#
# Phase 3 §3.K. Privileged container — see docker-compose.yml.

FROM ubuntu:22.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        mininet \
        openvswitch-switch \
        iproute2 \
        net-tools \
        tcpdump \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Default: bring up the same tree topology the README live-SDN section uses.
# docker-compose.yml overrides with --controller=remote,ip=pox,port=6633 so
# the pox service is the southbound target.
CMD ["mn", "--switch", "ovsk", "--topo", "tree,depth=2,fanout=8", "--controller=remote,ip=pox,port=6633"]
