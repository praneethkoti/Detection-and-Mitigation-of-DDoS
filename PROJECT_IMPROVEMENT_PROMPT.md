# Project Improvement Prompt v3 — Detection and Mitigation of DDoS in Software-Defined Networks

> **Audience.** A hiring reviewer screening for **Network Security** or **Cybersecurity** roles, skimming this repo to get an understaanding of my network knowledge.
>
> **Purpose.** An internal senior-engineer code review of the *current* state of the repository plus a prioritized punch-list to take it from a final-year proof-of-concept to a portfolio piece. Every gap below cites a real file and a real line; the follow-on implementation pass ships no stubs, no `TODO`s, no `pass # placeholder`.
>
> ---
>
> ## Portfolio positioning (read this before anything else)
>
> The candidate is applying to roles spanning two adjacent profiles in the current market:
>
> 1. **Network Security** — primary lane for this project. Roles in this lane care about: traffic analysis, intrusion detection, network telemetry, packet capture, SDN/OpenFlow, firewall and ACL design, anomaly detection on flows, DDoS mitigation, threat hunting at the network layer, and operational discipline on enterprise switching/routing infrastructure.
>
> 2. **Cybersecurity (broader)** — secondary lane. Roles here care about: threat intelligence, vulnerability research, ML/AI for security, security tooling in Python, incident response, threat modeling.
>
> This repo is the **headline Network Security asset** of a three-piece portfolio. It must read first as network-security work — terminology, framing, README architecture diagram, evaluation language — and only secondarily as ML/AI-flavored cybersecurity work. Lead with packets, flows, controllers, and flow-table rules; let "machine learning" appear as a *method* applied to the network problem, not the headline.
>
> The three portfolio pieces and how this one fits between them:
>
> | Project | Profile served | What it demonstrates |
> |---|---|---|
> | **Graduate Teaching Assistant — UMD College of Information** (instructional support for INST 346, INST 347, INST 365, HACS 479 under UMD IT-20 "Operation of Networking Devices and Identity Management Systems") | Network Security — *operational* | Real enterprise networking on Cisco/Ubiquiti gear: VLANs (3276), ACLs, port security, broadcast storm-control, spanning-tree portfast, DHCP/NAT scoping, MAC-registered NAC for IoT (EDU-Roam / UMD-IoT), WiFi SSID/power/channel discipline. The candidate has *operated* a real campus-segment network under a real security standard. |
> | **This repo — Detection and Mitigation of DDoS in SDN** | Network Security — *programmable* | The software counterpart of the GTA work: the same primitives (drop rules, port-based action, broadcast/flood detection, network telemetry) but expressed as `ofp_flow_mod` instructions on an OpenFlow controller instead of `switchport` configuration on a Catalyst. Adds anomaly detection (entropy, PCA, RandomForest) on per-window flow features. |
> | **Dark Web Threat Intelligence Toolkit** (separate repo, ~11k LOC, 207 tests, 8 modules) | Cybersecurity — *breadth* | OSINT collection, IOC extraction, classification (keyword + TF-IDF + zero-shot + ATT&CK mapping), STIX/MISP export, Streamlit dashboard, LLM-backed summarization. |
>
> Together: traditional/operational network security (GTA) + programmable network security (this repo) + threat-intel cybersecurity tooling (Dark Web). Network security is covered top-to-bottom — cable-and-VLAN at the bottom, controller-and-flow-table in the middle, with the cybersecurity tooling sitting alongside.
>
> ## What this means for the README and the writeup
>
> - **Lead with network-security terminology.** Title and abstract use *traffic analysis*, *flow-table mitigation*, *programmable data plane*, *control-plane saturation*, *anomaly detection on flow features*. Do not lead with "machine learning" or "AI."
> - **Frame the methodology in the IDS/IPS lineage.** Cite NIST SP 800-94 (Guide to IDS/IPS), Lakhina–Crovella–Diot on entropy-based anomaly detection, and MITRE D3FEND for *Network Traffic Filtering* / *Inbound Traffic Filtering*. Map the detector to D3FEND techniques explicitly in the README.
> - **Bridge to the GTA work in one paragraph.** A short "Real-world parallel" section in the README (see §4.13) draws the line from a `switchport access vlan` config on a campus port to an `ofp_flow_mod` drop rule on a virtual port — same defensive primitive, different plane.
> - **Cybersecurity credentials reinforce, don't dominate.** ML is a section, not the section. Threat modeling (§4.5) and CI/security-hygiene (§4.8) earn the cybersecurity points without diluting the network-security lead.
>
> ---
>
> **Candidate background to thread through README, docstrings, and any blog post:**
> Master's in Cybersecurity, University of Maryland College Park (May 2026); 2+ years at HP Inc. as a Cybersecurity Engineer (Python vulnerability parsing, web scraping, ML classification, GenAI integration); Graduate Teaching Assistant for UMD College of Information's networking/cloud/cybersecurity course sequence under IT-20.
>
> **Repo facts at time of review:** 4 Python files in `Py Scripts/`, 295 LOC of source, 0 LOC of tests, last commit 2025-03-26, no `requirements.txt`, no `LICENSE`, no `.gitignore`, no CI, no Dockerfile, no captured `.pcap`, no trained model artifacts. The companion academic report (1.5 MB PDF, 25 pages) describes a PCA-based detector that the code does not implement.

---

## §1 — What the project currently has

### 1.1 Module breakdown (corrected against actual file contents)

| File | LOC | Role *(actual behavior, not name)* | Runs today? |
|---|---:|---|---|
| `Py Scripts/ddos_detection_trainer.py` | 49 | `EntropyAnalyzer` — Shannon entropy of destination IPs over fixed 50-packet windows. The control-plane signal that triggers mitigation. | Imports cleanly in isolation, but is *not actually trained* — the name is misleading. |
| `Py Scripts/l3_pox_controller.py` | 106 | POX L3 learning switch + entropy-driven mitigation hook. The SDN control-plane entry point. | **No.** Three runtime errors before the first packet (§2.1–§2.3). |
| `Py Scripts/attack_simulator.py` | 51 | **Benign-looking traffic generator** despite the file name — random source IPs (excluding RFC-1918 / loopback / 169.254 / 192.* prefixes) toward `10.0.0.x`, `getopt -s/-e` for the destination range, 1000-packet loop with `inter=0.1` (~10 pps, ~100 s runtime). The "background traffic" the detector must not false-positive on. | Runs on Linux only; shells out to `ifconfig`+`awk`. |
| `Py Scripts/traffic_simulator.py` | 89 | **Actual DDoS attacker** despite the file name — `multiprocessing.Process` running `sendp()` of `Ether()/IP(dst=target)/UDP(dport=80)/("X"*982)` in a tight loop bounded by `time.sleep(1.0/ATTACK_RATE)`. Duration is read from `input()`. The volumetric L3/L4 flood the detector must catch. | Runs on Linux only; blocks on `input()`. |
| `README.md` | 122 | Setup story + claims. | Claims do not match code (§2.7). |
| `screenshot/*.png` | — | 8 PNGs of past runs (POX boot, Mininet up, traffic.py output, deltaY console, attack xterm, DDoS-detected banner). | Static evidence only — not embedded anywhere, not reproducible. |
| `Report ... .pdf` | 1.5 MB | Academic report on the project. **Filename contains spaces** so raw GitHub URLs break without percent-encoding. Not linked from README. | Reference material — the source of truth for what the project was *intended* to do (entropy + PCA dual-detector). |
| `_config.yml` | 1 | `theme: jekyll-theme-cayman` — enables a free GitHub Pages site at `<user>.github.io/<repo>`, currently unused. | Cosmetic; either use it or delete it (§2.10). |

**Total source:** 295 LOC of Python. **Total tests:** 0 LOC. **Total config:** 1 line.

### 1.2 What each Python file actually does (in network-security terms)

**`ddos_detection_trainer.py`** — defines `EntropyAnalyzer` with a single externally-called method, `collect_statistics(ip)`. Every 50 packets it computes `H = -Σ p · log₁₀(p)` over the distribution of destination IPs in that window — the classical Lakhina/Crovella/Diot signal: under a volumetric flood toward a single victim, the destination-IP entropy of the traffic mix collapses; under benign Internet-like traffic, it stays high. Append the per-window entropy to `self.dst_entropy`, and once 80 such windows have accumulated, dump the list with `print(...)`. The name "trainer" is a misnomer — nothing is trained, no model is fit, no file is written. It is a streaming windowed statistic, suitable as a low-cost first-stage filter ahead of any ML stage.

**`l3_pox_controller.py`** — POX `EventMixin` named `L3Switch` plus two module-level helpers (`monitor_ddos`, `check_ddos`) and an `Entry` ARP-cache record. On each `ipv4` packet the controller (a) feeds `dstip` into the shared `EntropyAnalyzer`, (b) if entropy drops below `0.5` increments a per-(switch, port) counter and *re-arms* a 2-second recurring timer, (c) when that timer fires, any port whose counter ≥ 50 receives a single `ofp_packet_out(in_port=port)` and the counter dict is wiped. There is no `ofp_flow_mod` install, so there is no actual block — the next packet on that port flows again. *In data-plane terms: the controller detects but never installs a drop rule, so mitigation is theoretical.*

**`attack_simulator.py`** *(misnamed — see §2.0)*. Scapy script that emits L2/L3 packets with randomized source IPs and `10.0.0.x` destinations. This is the *benign background traffic* used to establish the no-attack entropy baseline.

**`traffic_simulator.py`** *(misnamed — see §2.0)*. Scapy script that emits a sustained, single-destination UDP flood from one source — a textbook volumetric L3/L4 DDoS. Used to drive entropy below threshold and trigger mitigation.

### 1.3 What the README and report *claim* the project does

The README states **(a)** PCA-based detection on top of entropy (`README.md:4, :16, :21`), **(b)** windowing every 250 packets (`README.md:52`), **(c)** invocation `python traffic_simulator.py --f 2 --e 65` (`README.md:43`), **(d)** automated IP blocking (`README.md:22`). None of these is true of the code currently in the repo (§2.7). The companion PDF additionally presents three "Standard Deviation vs Time" graphs as evidence of PCA-based detection working under no-attack / classic-DDoS / new-type-DDoS scenarios — those graphs exist in the report, but the corresponding PCA implementation does not exist in this repo. **This is the single most important narrative gap to close**: the project's story becomes *"the academic report described a dual-stage entropy+PCA anomaly detector for the SDN control plane; this repo now implements both stages, validates them on labelled traffic captures, and installs an OpenFlow drop rule when the detector fires."* See §4.1.

---

## §2 — Critical gaps (reviewer-closes-the-tab tier)

### 2.0 The two simulator files are swapped — rename them first

**`attack_simulator.py`** generates benign background traffic. **`traffic_simulator.py`** performs the volumetric flood. The README's testing section (`README.md:113-119`) instructs the reviewer to "run `traffic.py` to generate normal traffic" — but the actual `traffic_simulator.py` in this repo *is* the attacker, and `attack_simulator.py` *is* the benign generator. A reviewer reading the report, then the README, then the code, will be lost inside a minute.

**Fix.** Rename to match behavior. Suggested layout:

```
src/
  detector/
    entropy.py               # was ddos_detection_trainer.py
    pox_controller.py        # was l3_pox_controller.py
    pca_detector.py          # new — §4.1
    ml_detector.py           # new — §4.2
  generators/
    benign_traffic.py        # was attack_simulator.py
    udp_flood.py             # was traffic_simulator.py
```

Update every reference in `README.md`, in the report PDF's recommended commands, and in any future `demo.py`. The `Trafficlaunch.py` banner at `traffic_simulator.py:85` should be removed as part of the rename. This rename matters more than any line-level bug below — those are visible only when the code runs, but the naming confusion is visible the moment a reviewer opens the directory.

### 2.1 The controller will not import. `l3_pox_controller.py:25`

```python
from .detection import EntropyAnalyzer
```

There is no module named `detection`, and `Py Scripts/` is not a Python package (no `__init__.py`, and the folder name has a space in it which makes it non-importable anyway). The `EntropyAnalyzer` class lives in `ddos_detection_trainer.py`. Fix the import *and* either rename the folder to `src/detector/` and add `__init__.py`, or restructure so the detector is installed alongside `pox/pox/forwarding/`.

### 2.2 `NameError: name 'time' is not defined`. `l3_pox_controller.py:106`

```python
self.timeout = time.time() + 120
```

`time` is never imported in this file. Construction of the very first `Entry` raises. Add `import time` at the top, or `from time import time as now`.

### 2.3 `UnboundLocalError` on `set_timer`. `l3_pox_controller.py:36`

```python
def monitor_ddos(event):
    global port_stats
    if not set_timer:        # read of module-level
        set_timer = True     # write → Python treats whole function as local
```

`set_timer` is declared at module scope (line 29) but only `port_stats` is declared `global` inside the function. The assignment at line 36 promotes `set_timer` to a local, so the read on the same line raises. Add `global set_timer` — or, much better, delete `set_timer` entirely (it is never read after being set; see §2.4).

### 2.4 Timer leak: a new `recurring=True` POX `Timer` is created on every offending packet. `l3_pox_controller.py:80`

```python
if entropy_instance.entropy_value < 0.5:
    monitor_ddos(event)
    Timer(2, check_ddos, recurring=True)   # ← brand-new timer, every time
```

Within seconds you have hundreds of overlapping recurring timers all calling `check_ddos`, all racing on the same global `port_stats`. Create the timer **once**, at controller startup, and let `check_ddos` decide whether the state warrants action.

### 2.5 ARP cache `KeyError`. `l3_pox_controller.py:93`

```python
if a.protosrc not in self.arp_cache[event.connection.dpid]:
```

`self.arp_cache` is initialized to `{}` in `L3Switch.__init__` and is only ever indexed with `.get(..., {})` *once* (line 82). The first ARP packet from any new switch raises `KeyError`. Use `self.arp_cache.setdefault(dpid, {})` at the top of `handle_arp`.

### 2.6 "Mitigation" doesn't actually install a flow-table drop rule. `l3_pox_controller.py:53`

```python
msg = of.ofp_packet_out(in_port=port)
core.openflow.sendToDPID(switch, msg)
```

`ofp_packet_out` with no actions is a one-shot, empty packet-out — it does nothing to subsequent traffic. The promised "automated IP blocking" requires `ofp_flow_mod` with `command=OFPFC_ADD`, a match on the offending `nw_src`/`in_port`, an empty action list (drop), and a non-trivial `idle_timeout`/`hard_timeout`. *This is the project's headline network-security primitive — the SDN equivalent of an inbound deny ACL on a campus switchport — and it is currently a no-op.* Fixing it is what makes the project credibly "mitigation," not just "detection."

### 2.7 README ↔ code mismatches

The README ships several claims that aren't true of the code currently in the tree.

| README says | Code does | Where |
|---|---|---|
| "calculates the entropy value for each set of **250 packets**" | Window of **50** packets | `README.md:52` vs `ddos_detection_trainer.py:17` |
| Example: `python traffic_simulator.py --f 2 --e 65` | `getopt` only accepts `-s`/`--start` and `-e`/`--end` (no `--f`); and the script described is not the right one anyway (§2.0) | `README.md:43` vs `attack_simulator.py:29` |
| "Principal Component Analysis (PCA) is integrated" | No PCA anywhere — `sklearn` is not imported, no model file exists | `README.md:21` |
| Usage banner: `Usage: python Trafficlaunch.py <target_ip>` | The script is `traffic_simulator.py`; `Trafficlaunch.py` does not exist | `traffic_simulator.py:85` |
| "Create the detection script in the POX forwarding directory" | The import path `.detection` doesn't survive that placement either — see §2.1 | `README.md:81-86` |
| "run `traffic.py` to generate normal traffic" | The benign generator is `attack_simulator.py`; `traffic_simulator.py` is the attacker | `README.md:113-119` vs §2.0 |

### 2.8 Shared state in `EntropyAnalyzer` is at class scope, not instance scope. `ddos_detection_trainer.py:6-11`

```python
class EntropyAnalyzer:
    packet_count = 0
    entropy_dict = {}
    ip_addresses = []
    dst_entropy = []
    entropy_value = 1
```

`__init__` does not rebind these. Two instances of `EntropyAnalyzer` share the same `entropy_dict`/`ip_addresses` lists. Today there is only one instance, so the bug is dormant — but for a hiring reviewer this is the single most damning line in the repo because it is a textbook Python mistake. Move every attribute into `__init__`.

### 2.9 Project hygiene files missing

- No `requirements.txt` / `pyproject.toml` — reviewer can't `pip install` anything.
- No `LICENSE` at the repo root (Apache header lives only inside `l3_pox_controller.py:1-13` and applies to McCauley's POX code, not yours).
- No `.gitignore` — every reviewer who clones will see whatever `__pycache__`/IDE crud you commit next.
- No `tests/` and no test files. The entropy formula is the easiest thing in the world to unit-test, and it isn't.
- No CI config (`.github/workflows/`).
- No `Dockerfile` or `docker-compose.yml`. POX + Mininet are notoriously painful to install; containerizing them is the single biggest "I respect your time, reviewer" move you can make.
- No `samples/*.pcap`. Nothing is reproducible offline.
- `Py Scripts/` — the folder name has a space. Rename per §2.0.
- The companion **report PDF filename contains spaces**. Rename to `docs/SDN_DDoS_Report.pdf` and link from README under "Academic background."

### 2.10 `_config.yml`: use it or delete it

The lone-line `_config.yml` auto-publishes a free GitHub Pages project site at `https://praneethkoti.github.io/Detection-and-Mitigation-of-DDoS`. Either populate `docs/index.md` with the executive summary + a screenshot of the dashboard (§4.10) + a link to the report PDF + a link to the demo asciicast, or delete the file. Don't leave it as default-theme cosmetic.

### 2.11 The `screenshot/` directory is a graveyard of unreproducible PNGs

Eight PNGs with no captions, no embedding, and no way to regenerate them — they show output of code that no longer runs (§2.1–§2.3). After Phases 0–2 are complete, **retake** them against the fixed code, give them descriptive filenames (`screenshot/01_pox_boot.png`, `screenshot/02_benign_entropy_baseline.png`, `screenshot/03_flood_entropy_collapse.png`, `screenshot/04_flow_mod_installed.png`, etc.), and embed them in the README under each phase of the demo walkthrough.

---

## §3 — Important gaps (polish that separates "student project" from "engineer's project")

### 3.1 Magic numbers everywhere, no config surface

Every threshold is hardcoded:

- Entropy window size **50** (`ddos_detection_trainer.py:17`)
- Batch-print size **80** (`ddos_detection_trainer.py:38`)
- Entropy threshold **`< 0.5`** (`l3_pox_controller.py:78`)
- Port-count threshold **`>= 50`** (`l3_pox_controller.py:51`)
- Timer period **2 s** (`l3_pox_controller.py:80`)
- Attack rate **100 pps**, packet size **1024 B**, default duration **10 s** (`traffic_simulator.py:9-11`)
- Loop count **1000** (`attack_simulator.py:44`)
- Inter-packet delay **0.1 s** (`attack_simulator.py:48`)
- ARP entry timeout **120 s** (`l3_pox_controller.py:106`)

Move all of these into a single `config.yaml` parsed once at startup. A network engineer expects every threshold to be a tunable knob, not a baked-in constant.

### 3.2 Cross-platform interface lookup

`attack_simulator.py:42`:

```python
network_interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read().strip()
```

Linux-only, the regex is wrong (`ifconfig` prints `eth0:` on modern distros so `$1` is `eth0:`, not the IP — and `print $1` returns the interface *name*, not the IP, despite the surrounding code clearly expecting the latter), and `os.popen` has been discouraged for over a decade. Replace with `psutil.net_if_addrs()` or `scapy.all.conf.iface`.

### 3.3 `getopt` → `argparse`

Both simulators use `getopt` with no `--help`, no type coercion, and no defaults. `attack_simulator.py:39` checks `if not start_range` — those variables aren't even bound if neither flag is passed, so the error is `UnboundLocalError`. Use `argparse` with `required=True`, `type=int`, `--help`.

### 3.4 `input()` in a script that should be batch-runnable

`traffic_simulator.py:60` blocks on stdin asking for duration. That makes the script un-scriptable. Make `--duration` a flag.

### 3.5 `print` vs `logging`

Pick one mechanism and apply it everywhere. The entropy values that today are flushed via `print(self.dst_entropy)` should go to a structured JSON-line log so a downstream tool (Grafana, jq, the demo script, the dashboard) can consume them. *This is the network-telemetry contract for the whole project — everything else hangs off it.*

### 3.6 O(n²) inner loop in entropy computation. `ddos_detection_trainer.py:18-22`

Replace with `collections.Counter(self.ip_addresses)`. Today's 50-element window hides the problem; a realistic per-second window of 10k+ packets would not.

### 3.7 Use `log₂`, not `log₁₀`

The networking literature (Lakhina, Crovella, Diot; the original entropy-anomaly papers) uses bits — `log₂`. Switch and recompute thresholds (`0.5` in log₁₀ ≈ `1.66` in log₂). Any reviewer who cites that literature will flag the unit mismatch on sight.

### 3.8 No type hints, no docstrings

`EntropyAnalyzer` is the project's only meaningful class and has zero docstrings. Add module-, class-, and method-level docstrings, plus `from __future__ import annotations` and `def collect_statistics(self, ip: IPAddr) -> None:` signatures.

### 3.9 Time-based windowing

Packet-count windows mean that during a slow legitimate period it can take minutes to close a window, and a burst can close several windows in milliseconds. Add an optional `window_seconds` mode and prefer it for the live controller path; keep count-based for the offline replay tests.

### 3.10 Multi-feature detection — not just per-destination entropy

The current detector only looks at *dst-IP* entropy: a flood toward one victim collapses it → attack. But a *low-and-slow* reflective attack with one source against many destinations collapses *src-IP* entropy instead, and a fixed-payload flood collapses *packet-size* entropy. Track all three; alert on any. A single-feature detector is exactly the kind of thing a network-security interviewer will grill you on.

---

## §4 — Nice-to-have improvements (turn the repo into a portfolio piece)

### 4.1 Actually deliver the PCA the README *and the report* promise

Highest-leverage addition. The companion report's Chapters 4–6 motivate and graph PCA-based detection over an entropy baseline but ship no implementation. Build `scripts/train_pca.py` that:

1. Loads a labelled feature CSV (§4.12 below on data acquisition).
2. Fits `sklearn.decomposition.PCA(n_components=2)` on the benign training portion.
3. Computes Mahalanobis distance of held-out windows in PCA space.
4. Saves `models/pca.joblib` (< 1 MB).

At inference time, the controller (or the offline replay) projects each window's feature vector and gates the entropy-only verdict on the Mahalanobis distance. The README's claim becomes accurate, the report's narrative becomes "the implementation that closes the report's loop," and you have a concrete artifact to walk through in an interview.

### 4.2 An actual ML detector with metrics

Add a `RandomForestClassifier` on top of the same per-window feature vector. Train on a labelled split (§4.12), ship `models/rf.joblib` (< 5 MB), and add an `## Evaluation` section to README with a confusion matrix and precision/recall/F1 on a held-out attack split. Run **all three** detectors side-by-side: entropy baseline, PCA-gated, RF. *Position this as a "defense-in-depth at the detector layer" — exactly the framing a network-security reviewer will recognize.*

### 4.3 Replayable `.pcap` corpus

Capture (or extract from CICDDoS2019) ~30 s of normal traffic and ~30 s of UDP flood, save as `samples/normal.pcap` and `samples/attack.pcap` (< 2 MB each, well within Git). The demo (§5) replays these via `scapy.rdpcap` instead of requiring Mininet — *the* unlock for cross-platform reproducibility. Bonus: a Wireshark screenshot of one pcap, embedded in README, is worth several paragraphs of explanation.

### 4.4 Mininet topology as code

Replace the README's bare `sudo mn --topo tree,depth=2,fanout=8` with a `topology.py` using `mininet.topo.Topo`. Parameterize host count, link bandwidth, link delay, and queue depth. *Note the structural parallel with the GTA work's INST 346 rack topology — both are tree topologies sized for a small enterprise segment. Call this out in the README.*

### 4.5 Threat model

Add a `THREAT_MODEL.md` with a STRIDE table specifically for an SDN controller: spoofing (compromised southbound channel), tampering (forged flow-mods), repudiation (unsigned OpenFlow events), information disclosure (`PACKET_IN` exfiltration of payload bytes), DoS of the controller itself (which is exactly what this project defends against — the section writes itself), elevation of privilege (crafted OpenFlow messages). Three paragraphs, citing NIST SP 800-94 and MITRE D3FEND. *This is the artifact that lets you talk fluently in an interview about both network security and threat modeling at once.*

### 4.6 Unit tests for the entropy

```python
def test_entropy_uniform_is_max():
    a = EntropyAnalyzer(window=4)
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]:
        a.collect_statistics(ip)
    assert a.entropy_value == pytest.approx(2.0)   # log2(4)

def test_entropy_singleton_is_zero():
    a = EntropyAnalyzer(window=4)
    for _ in range(4):
        a.collect_statistics("1.1.1.1")
    assert a.entropy_value == pytest.approx(0.0)
```

Two tests. Twenty lines. Massive credibility delta.

### 4.7 Integration test using `samples/*.pcap`

```python
def test_attack_pcap_drops_entropy_below_threshold():
    a = EntropyAnalyzer(window=250)
    for pkt in rdpcap("samples/attack.pcap"):
        if IP in pkt:
            a.collect_statistics(str(pkt[IP].dst))
    assert min(a.history) < 0.5
```

### 4.8 Dev tooling

- `pyproject.toml` with `ruff` + `black` config
- `.pre-commit-config.yaml`
- `.github/workflows/ci.yml` running `ruff check . && pytest -q` — **matrix on `ubuntu-latest` and `macos-latest`**; the SDN path is Linux-only but the demo path must run on a reviewer's Mac.
- `Makefile` with `make demo`, `make test`, `make lint`

### 4.9 Containerized full stack

`docker compose up` brings up: a `pox` container running the controller, a `mininet` container running the topology, and a `detector` container tailing logs. Bonus: a `grafana` container reading entropy values from a Prometheus exporter. *This is the cleanest answer to "how do I show this works without sudo on a Mac" — and the topology + container architecture is itself a network-security artifact worth walking through.*

### 4.10 Live dashboard (Streamlit)

A ~150-line `dashboard.py` plotting:

1. Entropy over time (dst, src, packet-size — three lines), threshold drawn as horizontal line
2. Packets/sec per switch port (mirroring the SNMP-style telemetry a NOC engineer would see)
3. Currently-installed `ofp_flow_mod` drop rules with their match criteria and timeouts
4. PCA scatter (benign cluster vs attack outliers)

The dashboard reads the JSON-line log produced by the detector — no direct POX coupling, so it works for the offline `demo.py` path too.

### 4.11 Multi-controller distributed detection (the report's stated future work)

The companion report's Chapter 7 explicitly proposes "distributed multi-controllers in SDN" as the natural next step. Implement a thin version: two POX controllers each running the detector on a partition of the tree topology, communicating per-window summaries to a coordinator that decides on global mitigation. *This is the East-West problem in real SDN deployments (and a known weakness in flat OpenFlow control planes); a working sketch is a strong interview talking point.*

### 4.12 Data acquisition strategy (must accompany §4.1 and §4.2)

CICDDoS2019 is multi-GB and license-restricted; it cannot be committed to the repo. Without an explicit strategy, §4.1 and §4.2 are unimplementable. The right move:

1. Ship `samples/cicddos2019_sample.csv` — a deliberately-tiny (~50 KB, ~2k rows) labelled extract, enough to train a toy PCA and a toy RandomForest end-to-end in `<5` seconds. This is what `make demo` and CI use.
2. Add `data/README.md` with: official CICDDoS2019 download URL (UNB), license/citation, expected sha256, and `scripts/download_data.py` that fetches and verifies.
3. In README's Evaluation section, report numbers on the *full* dataset (not the toy sample), and note that the toy sample is for demo/CI only.

### 4.13 "Real-world parallel" section in the README — the GTA bridge

Add a short section (≤ 8 lines of prose, plus a 2-column table) drawing the line from traditional/operational network security to this project. This is what makes the GTA work and this project read as one coherent network-security story rather than two unrelated bullet points.

Suggested table:

| Traditional network primitive (GTA / IT-20 lab work) | SDN equivalent (this project) |
|---|---|
| `switchport access vlan 3276` on Cisco Catalyst 6/20 | OpenFlow `ofp_flow_mod` with `match.dl_vlan` action |
| `storm-control broadcast level 1.00` + `action shutdown` | Entropy-collapse detection + `ofp_flow_mod` drop with `hard_timeout=30` |
| Inbound ACL on a campus uplink | Controller-installed flow-table drop rule on the affected `in_port` |
| MAC-registered NAC on UMD-IoT | OpenFlow learning + per-`dl_src` flow installation |
| Wiring-closet broadcast-storm telemetry (SNMP) | JSON-line entropy stream from the controller |
| Spanning-tree `portfast` on edge ports | Default OpenFlow forwarding + reactive rule install on attack |

Suggested prose: *"This project applies, in software, the same defensive primitives I configure in hardware as a Graduate Teaching Assistant for the University of Maryland College of Information's networking and cybersecurity course sequence. The GTA work operates a small campus segment under UMD IT-20 ("Operation of Networking Devices and Identity Management Systems") — VLANs, ACLs, broadcast storm-control, MAC-registered network access for IoT. This repo expresses the same defenses through an OpenFlow controller: flow-mod drop rules in place of port-level ACLs, entropy-based broadcast-storm detection in place of switchport storm-control, controller-driven NAC in place of static MAC registration. Different plane, same job."*

### 4.14 Skills demonstrated, mapped to JD keywords

Add an `## Engineering skills demonstrated` section to README with two columns, one for each role lane. Reviewers and ATS systems both scan for keywords; this is where they live without polluting the prose. Suggested content:

**Network Security:**

- Software-Defined Networking (SDN), OpenFlow 1.0, POX controller framework
- L2/L3 switching, ARP cache management, flow-table programming (`ofp_flow_mod`, `ofp_packet_out`, match/actions)
- Network telemetry: per-window flow features, dst/src/payload entropy, packets-per-second per port
- DDoS detection and mitigation: volumetric L3/L4 floods, control-plane saturation, low-and-slow reflection
- Packet capture & replay: Scapy, `.pcap` corpora, `rdpcap`/`sendp`
- Topology design: Mininet, tree/star/mesh, parameterized link characteristics
- IDS/IPS lineage: entropy-anomaly (Lakhina–Crovella–Diot), NIST SP 800-94, MITRE D3FEND mapping
- Operational network engineering (from GTA): VLAN segmentation, ACLs, port security, MAC-based NAC, WiFi SSID/power/channel discipline, compliance under UMD IT-20

**Cybersecurity (broader):**

- ML for security: PCA-based unsupervised anomaly detection, RandomForest supervised classification, train/test discipline on CICDDoS2019
- Threat modeling (STRIDE for SDN control planes)
- Python tooling: type hints, argparse, structured logging, pytest, ruff, pre-commit
- CI/CD: GitHub Actions matrix on Linux + macOS, Docker-Compose multi-service builds
- Threat intelligence and OSINT (in the companion repo — link)

---

## §5 — Demo version spec (single-command interview demo)

The hiring conversation will not include "let me install POX and Mininet on this Mac." The demo therefore **must not require Mininet, POX, root, sudo, or Linux**. The full SDN path stays in the repo for credibility; the demo is a thin offline replay.

### 5.1 One command

```bash
python demo.py
```

(or `make demo` if you ship a Makefile).

### 5.2 What it does

1. Loads `samples/normal.pcap` (≈30 s, ≈3 k packets) and replays it through `EntropyAnalyzer(window=250)`.
2. Loads `samples/attack.pcap` (≈30 s of UDP flood from a few sources toward one dest) and replays it through the same analyzer.
3. Loads `models/pca.joblib` + `models/rf.joblib` (shipped in-repo, <5 MB combined) and runs the PCA and ML detectors on the same window stream.
4. Prints one JSON line per closed window (this is the *telemetry contract* the whole project hangs off — keep it stable):

   ```json
   {"t": 1.23, "window_packets": 250, "entropy_dst": 5.91, "entropy_src": 5.74, "entropy_size": 4.12, "pps": 287, "pca_mahalanobis": 1.42, "rf_proba": 0.04, "verdict_entropy": "BENIGN", "verdict_pca": "BENIGN", "verdict_rf": "BENIGN", "top_dst": "10.0.0.7"}
   ```

5. Prints a final plain-text summary (no emoji unless explicitly requested):

   ```
   [SUMMARY] benign windows: 12   attack windows detected (entropy): 8   (pca): 9   (rf): 9   first detection at packet #3417
   [SUMMARY] entropy_dst min during benign: 5.91   entropy_dst min during attack: 0.42
   [SUMMARY] entropy-only F1: 0.81   PCA-gated F1: 0.88   RF F1: 0.94
   [SUMMARY] would-install flow_mod: nw_src=192.0.2.17, in_port=3, hard_timeout=30
   [PASS] attack detected within first 500 packets of attack.pcap
   ```

6. Exits with code `0` on detection within budget, `1` otherwise. The demo doubles as a smoke test runnable from CI.

### 5.3 What it deliberately does *not* do

- No Scapy `sendp` (no root, no NIC).
- No POX import (no SDN runtime).
- No model download at first run (artifacts ship in-repo).
- No interactive prompts.
- No requirement for CICDDoS2019 full dataset.

### 5.4 README section to add

```markdown
## Quickstart (offline demo, no SDN required)

    git clone <repo> && cd Detection-and-Mitigation-of-DDoS
    pip install -r requirements.txt
    python demo.py

Expected last line: `[PASS] attack detected within first 500 packets of attack.pcap`

For the full SDN simulation (POX + Mininet on Linux), see [docs/SDN_SETUP.md](docs/SDN_SETUP.md).
```

---

## §6 — How to work through the fixes (priority-ordered, with checkpoints)

Five phases. End each with a `git commit` and `pytest -q` green (once tests exist).

### Phase 0 — Make it run (≈ half a day)

1. **Rename the two simulator files per §2.0.** Update every reference.
2. **Restructure the source tree** per §2.0 — `Py Scripts/` → `src/` with `detector/` and `generators/` subpackages, each with `__init__.py`.
3. Fix the import in `l3_pox_controller.py:25`.
4. Add `import time` at the top of `pox_controller.py`.
5. Add `global set_timer` — or delete `set_timer` entirely.
6. Move the `Timer(...)` construction out of `handle_packet` to controller startup; collapse to one timer instance.
7. `setdefault(dpid, {})` at the top of `handle_arp`.
8. Move every attribute in `EntropyAnalyzer` into `__init__` (§2.8).
9. Add `LICENSE` (MIT default).
10. Add `.gitignore`.
11. Add `requirements.txt` (`scapy`, `pyyaml`, `pytest`, `numpy`, `scikit-learn`, `pandas`, `joblib`, plus POX install notes in a comment).
12. Rename the report PDF and move to `docs/SDN_DDoS_Report.pdf`; link from README under "Academic background."

**Done when:** controller starts, ARP works, no `NameError`s, no `KeyError`s, only one timer running, file names match behavior.

### Phase 1 — Make it honest (≈ 1 day)

1. Settle on entropy window = **256**; apply in code, README, tests.
2. `argparse` in both simulators; update README; remove the `Trafficlaunch.py` banner.
3. Replace `os.popen("ifconfig | awk ...")` with `psutil.net_if_addrs()`.
4. Replace `input()` in `udp_flood.py` with `--duration` flag.
5. Move every magic number from §3.1 into `config.yaml`.
6. Replace `print(self.dst_entropy)` with the JSON-line telemetry contract (§5.2).
7. Replace `self.ip_addresses.count(addr)` with `Counter(self.ip_addresses)`.
8. Switch `math.log(..., 10)` to `math.log2`. Update thresholds.
9. Resolve `_config.yml` (§2.10).
10. **Rewrite the README narrative.** Lead with network-security framing (§Portfolio positioning at top of this prompt). Add the "Real-world parallel" section (§4.13) and the "Engineering skills demonstrated" section (§4.14). Link to the report PDF and to the Dark Web companion repo.

**Done when:** every README example, run verbatim, produces what the README claims; the README leads with network-security language, not "machine learning."

### Phase 2 — Make it demoable (≈ 1–2 days)

1. Capture/extract two PCAPs into `samples/` (§4.3).
2. Ship `samples/cicddos2019_sample.csv` and `data/README.md` (§4.12).
3. Write `demo.py` per §5.2 — ML stubs in this phase (constant scores), real models in Phase 3.
4. `tests/test_entropy.py` (§4.6), `tests/test_pcap_replay.py` (§4.7).
5. `Makefile` with `demo`, `test`, `lint`.
6. `## Quickstart` section in README (§5.4).
7. **Retake screenshots** against fixed code (§2.11); embed under each demo step.

**Done when:** a clean macOS clone + `pip install -r requirements.txt` + `python demo.py` exits 0 in under 60 s.

### Phase 3 — Make it credible (≈ 3–5 days)

1. `notebooks/train_pca_and_rf.ipynb`: loads CICDDoS2019, fits PCA + RandomForest, writes `models/*.joblib`.
2. Wire `MLDetector` and `PCADetector` classes into the JSON-line telemetry contract. Update `demo.py` to print three-detector comparison.
3. **Fix the actual mitigation** — `ofp_flow_mod(command=OFPFC_ADD, match=..., actions=[], hard_timeout=30)` per §2.6. *This is the headline network-security deliverable of the entire project.*
4. `THREAT_MODEL.md` (§4.5).
5. `Dockerfile` + `docker-compose.yml` (§4.9).
6. `.github/workflows/ci.yml` Linux + macOS (§4.8).
7. `## Evaluation` section in README with the three-detector F1 table.

**Done when:** the README's Evaluation table shows entropy-only F1 vs PCA-gated F1 vs RF F1 with defensible numbers.

### Phase 4 — Make it shine (optional, ≈ 2–4 days)

1. Streamlit dashboard (§4.10).
2. Multi-feature detector: dst-IP + src-IP + packet-size entropy + per-flow pps.
3. Multi-controller distributed detection (§4.11).
4. Comparative evaluation across attack classes (UDP flood, SYN flood, slow-loris, NTP amplification).
5. Short blog post / write-up linked from README.

---

## §7 — Working agreement (for the implementation pass)

1. **No stubs, no `TODO`, no `pass # placeholder`.** Every shipped function is fully implemented and tested.
2. **One phase at a time.** Commit and `pytest -q` green at each phase boundary.
3. **Ask before assuming** these four decisions:
   - Source-tree layout (§2.0 — propose `src/detector/` + `src/generators/`, confirm)
   - Entropy window size (§3.1 — propose 256, confirm)
   - License (§2.9 — propose MIT, confirm)
   - Fate of `_config.yml` (§2.10 — propose populating `docs/index.md`, confirm)
4. **Tone and terminology for all writeups.** README, docstrings, commit messages, blog post: *network-security primary, cybersecurity secondary*. Lead sentences mention packets/flows/controllers/topologies; ML is a method, not the headline. No "leveraging AI," no "cutting-edge," no emoji unless asked.
5. **Citations in README.** Where the prompt asks for citations (NIST SP 800-94, MITRE D3FEND, Lakhina–Crovella–Diot, the companion PDF), include them as a Markdown reference list at the bottom of the README, not inline links scattered through the body.
6. **Every numeric claim in the Evaluation section points to a reproducible artifact** (the notebook, the test, or the demo log).
7. **The README must read first as a network-security project.** If, after Phase 1, the README's opening paragraph could be mistaken for a generic ML-on-cybersecurity-data project, rewrite it.

---

## Appendix A — File-and-line index of every claim

| Claim | Location |
|---|---|
| Two simulator files swapped | `attack_simulator.py`, `traffic_simulator.py` (whole files) |
| Broken `from .detection` import | `l3_pox_controller.py:25` |
| Missing `import time` | `l3_pox_controller.py:106` |
| `UnboundLocalError` on `set_timer` | `l3_pox_controller.py:36` |
| Timer re-creation on every breach | `l3_pox_controller.py:80` |
| ARP `KeyError` | `l3_pox_controller.py:93` |
| Empty `ofp_packet_out` instead of `ofp_flow_mod` drop | `l3_pox_controller.py:53` |
| Hardcoded entropy threshold `< 0.5` | `l3_pox_controller.py:78` |
| Hardcoded port count threshold `>= 50` | `l3_pox_controller.py:51` |
| Class-level mutable state in `EntropyAnalyzer` | `ddos_detection_trainer.py:6-11` |
| O(n²) `list.count` in inner loop | `ddos_detection_trainer.py:22` |
| `math.log(..., 10)` instead of `log2` | `ddos_detection_trainer.py:33` |
| Hardcoded window 50 / batch 80 | `ddos_detection_trainer.py:17, :38` |
| `popen('ifconfig \| awk ...')` (in benign generator) | `attack_simulator.py:42` |
| Hardcoded 1000-packet loop / 0.1 s gap | `attack_simulator.py:44, :48` |
| `getopt` without defaults / `UnboundLocalError` | `attack_simulator.py:29-40` |
| `input()` blocking attack duration | `traffic_simulator.py:60` |
| Wrong usage banner (`Trafficlaunch.py`) | `traffic_simulator.py:85` |
| Hardcoded interface / rate / packet size (in attacker) | `traffic_simulator.py:8-11` |
| Stub `monitor_attack` / `stop_attack` | `traffic_simulator.py:38-51` |
| README claims PCA / 250-packet window / `--f` flag | `README.md:21, :52, :43` |
| `_config.yml` cayman theme, unused | `_config.yml:1` |
| Report PDF filename contains spaces | `Report for Detection and Mitigation of DDOS attack using SDN.pdf` |
| 8 unreproducible screenshots, not embedded | `screenshot/*.png` |

---

## Appendix B — Portfolio narrative quick reference (for the README "About" section and any cover-letter language)

> *"Two-piece network-security portfolio plus one cybersecurity-tooling complement: (1) hands-on operation of an enterprise campus segment as a Graduate Teaching Assistant at the University of Maryland College of Information, under UMD IT-20 compliance — VLAN/ACL/storm-control on Cisco gear, MAC-registered NAC for IoT devices on EDU-Roam/UMD-IoT; (2) this repo — programmable network defense via an SDN controller, demonstrating the same defensive primitives (drop rules, flood detection, anomaly-driven mitigation) at the OpenFlow layer, with entropy + PCA + RandomForest detectors compared head-to-head; (3) the Dark Web Threat Intelligence Toolkit, a separate ~11k-LOC Python project for OSINT collection and IOC processing. Together: traditional + programmable + threat-intel — full-stack network and cybersecurity."*

---

*End of v3 review prompt. Implement Phases 0–2 first, commit, re-run this prompt as a checklist against the diff. Phases 3–4 are the differentiators.*
