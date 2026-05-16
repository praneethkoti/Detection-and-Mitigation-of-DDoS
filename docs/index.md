---
title: Detection and Mitigation of DDoS Attacks in Software-Defined Networks
layout: default
---

# Detection and Mitigation of DDoS Attacks in Software-Defined Networks

Programmable network defense on a POX/OpenFlow control plane: streaming
Shannon entropy of destination IPs identifies volumetric L3/L4 floods at
the controller, and the controller installs flow-table mitigation on the
affected switch port.

## Why this matters

The SDN control plane is itself a target. A volumetric flood toward a single
victim does not only stress the victim — it exhausts the controller, because
every new `[srcip, dstip]` pair triggers a `PACKET_IN`. When the controller
falls behind, every flow in the network falls behind with it. Detecting and
acting on flood signatures *at the controller* is the only place where a
single mitigation primitive (a flow-table drop rule) can defend the entire
data plane.

## How it works

A streaming entropy analyzer closes one window every 250 packets and computes
Shannon entropy (in bits) of the destination-IP distribution within that
window. Under benign traffic, entropy approaches `log₂(window) ≈ 7.97`;
under a single-target flood, entropy collapses toward `0`. The controller
treats the window-level entropy as a single boolean signal — *under* the
configured threshold means the controller increments per-port packet
counters, and a periodic timer evaluates those counters and dispatches
mitigation. Every closed window also emits a structured JSON telemetry line
on stdout, which downstream tools (a CI smoke test, an optional dashboard)
consume without coupling to POX.

The detector deliberately does not catch the case where a single source
targets randomized destinations across the same subnet — destination
entropy stays high in that regime. PCA over standardized per-window flow
features and a RandomForest classifier are on the roadmap to close that
gap.

## More

- [Repository on GitHub](https://github.com/praneethkoti/Detection-and-Mitigation-of-DDoS)
- [Companion academic report (PDF)](SDN_DDoS_Report.pdf)
- [Project improvement prompt — senior-engineer review notes](../PROJECT_IMPROVEMENT_PROMPT.md)
