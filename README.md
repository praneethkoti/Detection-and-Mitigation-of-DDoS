# Detection and Mitigation of DDoS Attacks in Software-Defined Networks

[![CI](https://github.com/praneethkoti/Detection-and-Mitigation-of-DDoS/actions/workflows/ci.yml/badge.svg)](https://github.com/praneethkoti/Detection-and-Mitigation-of-DDoS/actions/workflows/ci.yml)

*Programmable network defense on a POX/OpenFlow control plane: streaming Shannon entropy of destination IPs identifies volumetric L3/L4 floods at the controller, and the controller installs flow-table mitigation on the affected switch port.*

*K. Sai Praneeth and A. Meher Sudhakar — SRM Institute of Science and Technology, November 2021. Academic background: [docs/SDN_DDoS_Report.pdf](docs/SDN_DDoS_Report.pdf).*

---

## At a glance

- **Detection signal.** Streaming Shannon entropy of destination IPs, computed in bits over fixed 250-packet windows.
- **Attack threshold.** Entropy below **1.66 bits** (equivalent to the report's original `0.5` in log₁₀ units) flags the window as attack.
- **Mitigation primitive.** Per-(switch, port) packet counters drive an OpenFlow flow-table drop rule on the offending ingress port.

## Quickstart (offline demo, no SDN required)

```bash
git clone https://github.com/praneethkoti/Detection-and-Mitigation-of-DDoS
cd Detection-and-Mitigation-of-DDoS
pip install -e .
python demo.py
```

Expected last line: `[PASS] attack detected within first 500 packets of attack.pcap`.

The demo runs on macOS, Linux, and Windows without sudo, root, or SDN/Mininet/POX — it replays committed `.pcap` corpora through the entropy detector and exits non-zero if the attack is not detected within budget, so it doubles as a CI smoke test. See [§ Live SDN run](#live-sdn-run) below for the full POX + Mininet path.

## Overview

Software-Defined Networking (SDN) separates the control plane from the data plane: a single logically-centralized controller programs flow-table rules on every switch in the network. That centralization is also the weakness — a volumetric Distributed Denial of Service (DDoS) attack toward any host in the network forces every new `[srcip, dstip]` pair through the controller as a `PACKET_IN` event, and the controller's queue depth and flow-installation rate become the actual bottleneck before the victim is.

This project applies the classical entropy-anomaly detection signal at the controller (NIST SP 800-94; Lakhina, Crovella, and Diot, *SIGCOMM 2005*) to flag flood signatures in real time, and uses the OpenFlow southbound channel to install drop rules on the affected switch ports — the SDN-native equivalent of an inbound ACL on a campus uplink. The detector currently ships entropy-based detection; PCA over standardized flow features and a RandomForest classifier are on the roadmap (see [§ Roadmap](#roadmap)) to address the "new-type DDoS" case where a single source targets randomized destinations and destination-IP entropy stays high.

## Architecture

```
                       +---------------------------+
benign + flood         |    POX controller          |
hosts (Mininet)  --->  |  L3Switch  ---->  Entropy  | ---> JSON-line telemetry
                       |  ARP cache       Analyzer  |       (stdout / file / dashboard)
                       |       \                /   |
                       |        v              v    |
                       |   port counters  ->  is_attack()
                       |        |                   |
                       |        v                   |
                       |   ofp_flow_mod drop rule   |   <-- Phase 3 deliverable
                       +---------------------------+
                                 |  OpenFlow 1.0 (southbound)
                                 v
                       +---------------------------+
                       |     Open vSwitch  (s1..s9) |
                       +---------------------------+
```

## Real-world parallel — programmable defense meets operational network engineering

The same defensive primitives that this project expresses as OpenFlow flow-mods are, in traditional enterprise networking, configured at the switchport. The work pairs naturally with operational network-security experience as a Graduate Teaching Assistant at the University of Maryland College of Information's networking and cybersecurity course sequence — managing a campus segment under **UMD IT-20** ("Operation of Networking Devices and Identity Management Systems"): VLANs, ACLs, broadcast storm-control on Cisco Catalyst gear, MAC-registered network access control on **UMD-IoT** and **EDU-Roam**.

The mapping:

| Traditional primitive (GTA / UMD IT-20) | SDN equivalent (this project) |
|---|---|
| `switchport access vlan 3276` on Cisco Catalyst | `ofp_flow_mod` with `match.dl_vlan` action |
| `storm-control broadcast level 1.00` + `action shutdown` | Entropy-collapse detection + `ofp_flow_mod` drop with `hard_timeout=30` |
| Inbound ACL on a campus uplink | Controller-installed flow-table drop rule on the affected `in_port` |
| MAC-registered NAC on UMD-IoT / EDU-Roam | OpenFlow learning + per-`dl_src` flow installation |
| SNMP broadcast-storm telemetry from a wiring closet | JSON-line entropy stream from the controller (see [§ Telemetry contract](#telemetry-contract)) |
| Spanning-tree `portfast` on edge ports | Default OpenFlow forwarding + reactive rule install on attack |

Different plane, same job. The two views — wire-and-VLAN at the bottom, controller-and-flow-table in the middle — are complementary network-security skill sets, not separate ones.

## Detection methodology

The entropy analyzer maintains a rolling per-window record of destination IPs and computes the Shannon entropy of that distribution every time the window closes. The window size is fixed at **250 packets** (matching the companion report, §5.2) and entropy is computed in **bits** (log₂), the convention in the IDS/IPS and SIGCOMM-era anomaly-detection literature.

Three traffic regimes are exercised, each with a Scapy generator under `src/ddos_sdn/generators/`:

- **Benign baseline** (`benign_traffic.py`): random source IPs drawn from non-RFC-1918 / non-loopback / non-link-local space, random destinations across `10.0.0.[start..end]`. The destination distribution is broad, entropy approaches `log₂(250) ≈ 7.97` bits, verdict is **BENIGN**.
- **Single-target volumetric flood** (`udp_flood.py`): single source, single destination, single UDP port. The destination distribution degenerates, entropy drops to **0.0** bits, verdict is **ATTACK**. This is the case the controller's mitigation primitive is designed for.
- **Random-destination flood** (`random_dst_flood.py`): single source, destinations spread uniformly across the same subnet as the benign baseline. Destination entropy stays high — *entropy fails to detect this attack*. This is the "new-type DDoS" the report's chapter 6 case 3 calls out, and it motivates the source-IP-entropy and PCA / RandomForest detectors on the roadmap.

The smoke test [`tests/test_three_case_smoke.py`](tests/test_three_case_smoke.py) drives the analyzer directly with synthesized streams from all three cases and asserts the verdict pattern — including the explicit known-failure mode on case 3.

## Telemetry contract

One closed entropy window emits one JSON line on the configured sink (stdout by default). This is the project's external interface — every downstream consumer (a CI smoke test, a future Streamlit dashboard, a `jq` pipeline) reads this contract:

| # | Field | Type | Units | Semantics | Phase 1 |
|---:|---|---|---|---|---|
| 1 | `t` | float | seconds | monotonic time since emitter start | real |
| 2 | `window_packets` | int | packets | packet count in this closed window | real |
| 3 | `entropy_dst` | float | bits | Shannon entropy of destination IPs | real |
| 4 | `entropy_src` | float \| null | bits | Shannon entropy of source IPs (roadmap) | null |
| 5 | `entropy_size` | float \| null | bits | Shannon entropy of packet sizes (roadmap) | null |
| 6 | `pps` | int | pkts/sec | packets per second across this window | real |
| 7 | `pca_mahalanobis` | float \| null | — | Mahalanobis distance in PCA-projected space (roadmap) | null |
| 8 | `rf_proba` | float \| null | [0,1] | RandomForest attack-class probability (roadmap) | null |
| 9 | `verdict_entropy` | enum | — | `"BENIGN"` or `"ATTACK"` (entropy-only verdict) | real |
| 10 | `verdict_pca` | enum \| null | — | PCA-gated verdict (roadmap) | null |
| 11 | `verdict_rf` | enum \| null | — | RandomForest verdict (roadmap) | null |
| 12 | `top_dst` | string | IPv4 | most-frequent destination IP in this window | real |
| 13 | `top_src` | string \| null | IPv4 | most-frequent source IP — the field the drop rule reads | real |

Sample line from a benign window (PCA + RF detectors loaded):

```json
{"t":0.0,"window_packets":250,"entropy_dst":5.80,"entropy_src":7.25,"entropy_size":null,"pps":250000,"pca_mahalanobis":1.98,"rf_proba":0.0,"verdict_entropy":"BENIGN","verdict_pca":"BENIGN","verdict_rf":"BENIGN","top_dst":"10.0.0.19","top_src":"203.0.113.170"}
```

Sample line during a single-target flood (PCA + RF detectors loaded):

```json
{"t":0.0,"window_packets":250,"entropy_dst":0.0,"entropy_src":0.0,"entropy_size":null,"pps":250000,"pca_mahalanobis":51.99,"rf_proba":1.0,"verdict_entropy":"ATTACK","verdict_pca":"ATTACK","verdict_rf":"ATTACK","top_dst":"10.0.0.64","top_src":"10.0.0.1"}
```

**Forward-compatibility rules** for this contract:

- Fields are never removed and never repurposed.
- New fields are appended.
- "Not yet shipped" is signalled by JSON `null` — never `0`, never `-1`, never a missing key.

This makes `jq '.rf_proba // 0' telemetry.jsonl` safe across detector configurations — `null` propagates as `0` for any consumer that doesn't care about whether a detector was loaded.

## Evaluation

Three detectors run on the same per-window 8-feature vector and emit through the same telemetry contract. Numbers below are reproducible from [notebooks/train_pca_and_rf.py](notebooks/train_pca_and_rf.py) (held-out 20% split of `samples/cicddos2019_sample.csv`) and from `python tests/test_three_case_smoke.py` (synthetic three-case suite).

### Held-out evaluation split (synthetic — see [data/README.md](data/README.md))

The `samples/cicddos2019_sample.csv` shipped in this commit was produced via the documented synth-fallback path (`scripts/build_synth_dataset.py`) because the real CICDDoS2019 dataset was not available at execution time. F1 numbers are computed on a stratified 80/20 split of that synth dataset (96 training rows, 24 held-out). When the real CIC data becomes available, regenerating the sample CSV and re-running the notebook will refresh these numbers without any other code change.

| Detector       | Precision | Recall | F1     |
|---|---:|---:|---:|
| Entropy-only   |   1.0000  | 0.5000 | 0.6667 |
| PCA-gated      |   1.0000  | 1.0000 | 1.0000 |
| RandomForest   |   1.0000  | 1.0000 | 1.0000 |

Confusion matrices (rows = true `[BENIGN, ATTACK]`, cols = predicted `[BENIGN, ATTACK]`):

- entropy: `[[8, 0], [8, 8]]` — the 8 missed ATTACK windows are random-destination floods, the case `entropy_dst` cannot catch
- PCA-gated: `[[8, 0], [0, 16]]` — random_dst caught via `entropy_src` collapse
- RandomForest: `[[8, 0], [0, 16]]` — same

### Synthetic three-case suite (`tests/test_three_case_smoke.py`)

| Case                                    | Entropy | PCA      | RandomForest |
|---|---|---|---|
| benign baseline                         | BENIGN  | BENIGN   | BENIGN       |
| single-target flood (`udp_flood`)       | ATTACK  | ATTACK   | ATTACK       |
| random-destination flood                | ⚠️ BENIGN — entropy fails | **ATTACK** | **ATTACK** |

The random-destination case is the headline. Entropy reports BENIGN by design (`entropy_dst` stays high — the destination distribution is broad even though the packets are a flood); PCA and RandomForest catch it via the per-window 8-feature vector — primarily `entropy_src`, which collapses to ~0 when a single source floods many destinations.

The headline assertion lives in [tests/test_pca_detector.py::test_pca_flips_random_dst_to_attack](tests/test_pca_detector.py). If that test ever fails, the project's narrative arc has regressed.

## Live SDN run

For the full live SDN run (Linux + POX + Mininet):

```bash
# Terminal 1 — POX controller with the entropy detector loaded
cd ~/pox
PYTHONPATH=~/Detection-and-Mitigation-of-DDoS/src \
  ./pox.py log.level --DEBUG ddos_sdn.detector.pox_controller

# Terminal 2 — Mininet tree topology, 9 switches, 64 hosts
sudo mn --switch ovsk \
        --topo tree,depth=2,fanout=8 \
        --controller=remote,ip=127.0.0.1,port=6633

# Inside mininet>, open xterms and run the generators
mininet> xterm h1
# python -m ddos_sdn.generators.benign_traffic -s 2 -e 65
mininet> xterm h2 h3
# python -m ddos_sdn.generators.udp_flood 10.0.0.64
```

Live POX terminal shows JSON-line telemetry; on a flood, `verdict_entropy` flips to `ATTACK`, `entropy_dst` collapses to ~0, and the controller logs `DDOS detected on Switch X, Port Y`. Screenshots of a working run are captured per [docs/screenshots/CHECKLIST.md](docs/screenshots/CHECKLIST.md).

For a guided developer workflow, the `Makefile` exposes the common entry points: `make demo` (offline demo), `make test` (pytest), `make samples` (rebuild the PCAP corpus), `make lint` (compile-check every tracked `.py`).

## Configuration

Every tunable (window size, entropy threshold, port-count threshold, ARP timeout, telemetry sink) lives in [config.yaml](config.yaml) at the repo root. Override location resolves in this order: explicit `load_config(path=...)` argument > `$DDOS_SDN_CONFIG_FILE` environment variable > `config.yaml` at the repo root > built-in defaults in `src/ddos_sdn/config.py`. Tests use the built-in defaults so they need no file on disk.

## Engineering skills demonstrated

**Network Security (primary).**
SDN / OpenFlow 1.0; POX controller framework; L2/L3 switching and ARP cache management; flow-table programming (`ofp_flow_mod`, `ofp_packet_out`, match/actions); network telemetry (per-window flow features, dst/src/payload entropy, packets-per-second per port); DDoS detection and mitigation (volumetric L3/L4 floods, control-plane saturation, low-and-slow reflection); packet capture and replay (Scapy, `.pcap`, `rdpcap`/`sendp`); topology design (Mininet, tree/star/mesh, parameterized link characteristics); IDS/IPS lineage (entropy-anomaly per Lakhina–Crovella–Diot; NIST SP 800-94; MITRE D3FEND Network Traffic Filtering); operational network engineering (VLAN segmentation, ACLs, port security, MAC-based NAC, WiFi SSID/power/channel discipline, UMD IT-20 compliance).

**Cybersecurity (secondary).**
ML for security (PCA-based unsupervised anomaly detection — roadmap; RandomForest supervised classification — roadmap; train/test discipline on CICDDoS2019); threat modeling (STRIDE for SDN control planes — roadmap); Python tooling (type hints, argparse, structured JSON-line logging, pytest); CI/CD — roadmap; threat intelligence and OSINT in companion work.

## Roadmap

The 5-phase implementation plan is captured in [PROJECT_IMPROVEMENT_PROMPT.md](PROJECT_IMPROVEMENT_PROMPT.md). Current status:

- **Phase 0 — Make it run.** ✅ Source tree restructured, runtime errors fixed, package pip-installable (commit `5714d69`).
- **Phase 1 — Make it honest.** ✅ This commit. Window 250, entropy in bits, JSON-line telemetry contract locked, argparse on all generators, config-driven thresholds, README rewritten.
- **Phase 2 — Make it demoable.** Sample `.pcap` corpus, `demo.py` single-command interview entry point, `pytest` wiring around the smoke test, `.pcap`-replay integration test.
- **Phase 3 — Make it credible.** Real `ofp_flow_mod` drop rule (replaces the empty `ofp_packet_out`); PCA + RandomForest detectors trained on CICDDoS2019, with `pca_mahalanobis` / `rf_proba` / `verdict_pca` / `verdict_rf` populated in telemetry; `THREAT_MODEL.md`; Docker compose for POX + Mininet + detector; GitHub Actions CI; ruff/black/pre-commit.
- **Phase 4 — Make it shine.** Source-IP and packet-size entropy; Streamlit dashboard reading the JSON-line stream; multi-controller East-West coordination; comparative evaluation across attack classes.

## Real execution evidence

Pre-rewrite screenshots are preserved under [docs/screenshots/legacy/](docs/screenshots/legacy/) for git-history continuity; they show output of code that no longer runs (Phase 0 fixed import errors the repo had inherited). New screenshots, captured against the current code on a Linux host with POX + Mininet, will land under `docs/screenshots/` per the capture plan in [docs/screenshots/CHECKLIST.md](docs/screenshots/CHECKLIST.md).

## Acknowledgments

This project is MIT-licensed; see [LICENSE](LICENSE). The POX controller scaffolding adapted in `src/ddos_sdn/detector/pox_controller.py` is © 2012-2013 James McCauley under the Apache License 2.0; the Apache header is preserved at the top of that file.

## References

- NIST SP 800-94 — *Guide to Intrusion Detection and Prevention Systems (IDPS)*.
- MITRE D3FEND — *Network Traffic Filtering* and *Inbound Traffic Filtering* techniques.
- Lakhina, Crovella, and Diot. *Mining Anomalies Using Traffic Feature Distributions*. SIGCOMM 2005.
- K. Sai Praneeth and A. Meher Sudhakar. *Detection and Mitigation of Distributed Denial of Service (DDoS) Attack in Software Defined Networks*. SRM Institute of Science and Technology, November 2021. [docs/SDN_DDoS_Report.pdf](docs/SDN_DDoS_Report.pdf).
