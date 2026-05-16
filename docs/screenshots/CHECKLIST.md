# Screenshot capture checklist

The pre-rewrite screenshots in `legacy/` show output of code that no longer
runs (Phase 0 fixed import errors that this repo had since at least
2024-10-13). They are kept for git-history continuity, not as project
evidence.

This document is the capture plan for the **new** set of eight screenshots
that will replace them. The capture session has to happen on a Linux host
because POX, Mininet, and Open vSwitch are Linux-only. The expected
environment:

- Ubuntu 22.04 LTS or newer (VM is fine)
- POX cloned to `~/pox` (`git clone https://github.com/noxrepo/pox`)
- Mininet installed via `apt install mininet` (or built from source)
- This repo cloned and editable-installed: `pip install -e .`
- `config.yaml` left at its repo-root defaults

Each shot lands under `docs/screenshots/` with the filename listed below.
Embed them in `README.md`'s `## Real execution evidence` section in the order
listed here. Capture at native resolution; PNG, not JPEG.

---

## 01_pox_boot.png

Boot the POX controller with the entropy detector loaded.

```bash
cd ~/pox
PYTHONPATH=~/Detection-and-Mitigation-of-DDoS/src \
  ./pox.py log.level --DEBUG ddos_sdn.detector.pox_controller
```

Capture: the POX banner, the "DEBUG:core:POX 0.x.x" line, and the
"INFO:openflow.of_01:[None 1] connected" line when Mininet attaches.

---

## 02_mininet_topology_up.png

In a second terminal, bring up the tree topology.

```bash
sudo mn --switch ovsk \
        --topo tree,depth=2,fanout=8 \
        --controller=remote,ip=127.0.0.1,port=6633
```

Capture: the `*** Adding controller / hosts / switches / links` banner and
the `mininet>` prompt with all 64 hosts and 9 switches enumerated.

---

## 03_benign_entropy_baseline.png

From `mininet>`, open an xterm on host `h1`:

```
mininet> xterm h1
```

Inside that xterm:

```bash
python -m ddos_sdn.generators.benign_traffic -s 2 -e 64 --count 1000 --inter 0.05
```

Capture: the POX terminal showing several BENIGN JSON-line emissions.
Expected `entropy_dst` values are between 5.5 and 6.0 bits.

---

## 04_flood_entropy_collapse.png

From `mininet>`, open xterms on `h2`, `h3`, `h4`:

```
mininet> xterm h2 h3 h4
```

In each:

```bash
python -m ddos_sdn.generators.udp_flood 10.0.0.64 --duration 30 --rate 200
```

Capture: the POX terminal showing the JSON-line stream transition from
BENIGN to ATTACK, with `entropy_dst` dropping to 0.0 and `top_dst` ==
10.0.0.64. The `DDOS detected on Switch ...` log line should also be
visible.

---

## 05_random_dst_flood_evades_entropy.png

The headline "new-type DDoS" case from the report's chapter 6 case 3. Stop
the flood and restart with `random_dst_flood`:

```bash
python -m ddos_sdn.generators.random_dst_flood --source-ip 10.0.0.1 -s 2 -e 64 --duration 30 --rate 200
```

Capture: the POX terminal showing JSON-line emissions where
`entropy_dst` stays high (above the 1.66-bit threshold) and the verdict
remains BENIGN — demonstrating that destination-IP entropy *fails to
detect* this attack. This is the case the roadmap's PCA + RandomForest
detectors will catch.

---

## 06_controller_logs_attack_detected.png

Re-run the single-target flood from §04 and zoom in on the POX terminal.

Capture: the `INFO:ddos_sdn.detector.pox_controller:DDOS detected on
Switch X, Port Y. Dropping packets...` log line, with adjacent
`window closed: packets=250 entropy_bits=0.000 verdict=ATTACK
top_dst=10.0.0.64 top_src=10.0.0.2` records.

---

## 07_flow_table_state_pre_mitigation.png

From any host (or the Mininet host root namespace), dump the OpenFlow
flow table on the switch that's seeing the flood, *before* mitigation
fires:

```bash
sudo ovs-ofctl dump-flows s1
```

Capture: the flow table — should show only the default learning-switch
rules, no drop rules.

---

## 08_flow_table_state_post_mitigation.png

**Note:** this PNG is captured in a later session, after the Phase 3 work
ships the real `ofp_flow_mod` drop rule. The shot will show the same
`ovs-ofctl dump-flows s1` output but with an additional row matching
`nw_src=10.0.0.<attacker>` and `actions=drop`, `hard_timeout=30`.

Until that lands, leave this file absent. The README's screenshot
section should note that 08 is pending alongside the drop-rule
implementation.
