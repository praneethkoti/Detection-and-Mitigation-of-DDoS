# CICDDoS2019 dataset reference

The Phase 3 PCA + RandomForest detectors are trained on the **CICDDoS2019** dataset published by the Canadian Institute for Cybersecurity at the University of New Brunswick. Sharafaldin et al., *Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy*, IEEE CCST 2019. The dataset spans benign traffic and 12 distinct DDoS attack classes (UDP flood, SYN flood, NTP amplification, DNS amplification, etc.); each class ships as a per-attack-class CSV of bidirectional flow records with ~80 features and a `Label` column.

## Where to download

Official landing page: **https://www.unb.ca/cic/datasets/ddos-2019.html**

CIC requires acknowledging a click-through license before download, so this repo intentionally does not include an automated fetcher: provide your name and institution, accept the license, and download the `01-12` split (the more commonly used set; the `03-11` split is also published). The download yields a tree of per-attack-class CSVs; for the Phase 3 detectors the **`UDP.csv`** file is the recommended starting point because it matches the volumetric flood case the entropy detector targets.

## What ships in this repo

| Path | Status | Notes |
|---|---|---|
| `data/README.md` | shipped in Phase 2 | this file |
| `scripts/extract_sample.py` | shipped in Phase 2 | stratified-sample extraction with deterministic output |
| `samples/cicddos2019_sample.csv` | **not committed in Phase 2** | the user runs `scripts/extract_sample.py` against their own CICDDoS2019 download; the resulting sample lands in the Phase 3 commit alongside `notebooks/train_pca_and_rf.ipynb` |

## Producing the sample

```bash
python scripts/extract_sample.py path/to/CICDDoS2019.csv samples/cicddos2019_sample.csv
```

The script:

1. reads the full input CSV with pandas
2. requires a `Label` column (CICDDoS2019 uses `Label` with values like `BENIGN` and `DrDoS_UDP`); fails loudly with a clear message if missing
3. stratified-samples ~2000 rows preserving the benign/attack ratio of the source file
4. uses `numpy.random.default_rng(seed=42)` for the index draw, so the same input plus the same seed produces a byte-identical output across machines and OSes
5. prints the sha256 of both the input and the output file on completion, so the values below can be pasted in verbatim

## Expected sha256s (filled in after first extraction)

```
EXPECTED_SOURCE_SHA256 = synthetic, see ## Fallback (synth) below
EXPECTED_SAMPLE_SHA256 = synthetic, see ## Fallback (synth) below
```

The CSV that ships in this Phase 3 commit was produced via the documented synth-fallback path (see `## Fallback (synth)` near the bottom of this file). When the real CICDDoS2019 dataset becomes available, re-running `scripts/extract_sample.py` will overwrite `samples/cicddos2019_sample.csv` with real-data rows; at that point both placeholders should be replaced with the real `EXPECTED_SOURCE_SHA256` and `EXPECTED_SAMPLE_SHA256` values printed by the script, in this format:

```
extract_sample: read   <input_csv>   sha256=<...>   rows=<n_in>
extract_sample: wrote  <output_csv>  sha256=<...>   rows=<n_out>
```

## Citation (BibTeX)

```bibtex
@inproceedings{sharafaldin2019cicddos2019,
  title     = {Developing Realistic Distributed Denial of Service ({DDoS}) Attack
               Dataset and Taxonomy},
  author    = {Sharafaldin, Iman and Lashkari, Arash Habibi and
               Hakak, Saqib and Ghorbani, Ali A.},
  booktitle = {International Carnahan Conference on Security Technology (ICCST)},
  year      = {2019},
  publisher = {IEEE},
  doi       = {10.1109/CCST.2019.8888419},
}
```

## Scope note

`samples/cicddos2019_sample.csv` is sized for **demo and CI** only. At `--rows 2000` (the default in `scripts/extract_sample.py`) the committed CSV is roughly **5 MB**, large enough to fit a PCA + RandomForest training round in a few seconds. The full Phase 3 evaluation results reported in the README (precision / recall / F1 per attack class) would be computed against the **complete** CICDDoS2019 dataset, not the sample; the sample exists to give CI and offline demos a real-data path that doesn't depend on a 24 GB download.

---

## Fallback (synth)

The version of `samples/cicddos2019_sample.csv` committed in the Phase 3 commit was **not** produced from real CICDDoS2019 data. The UNB download was not available at execution time; the project's Phase 3 plan (§3.E) documents a synth-fallback path that produces a CSV with the **same column shape and Label conventions** the real-data path would produce, but with rows derived from the project's own three smoke generators scaled up.

**Why this path:** keeps Phase 3 unblocked on a single external dependency (UNB CICDDoS2019 access requires acknowledging a click-through license). All other Phase 3 deliverables (`PCADetector`, `MLDetector`, the real `ofp_flow_mod` drop rule, `THREAT_MODEL.md`, Docker, CI) are independent of where the training rows come from. The narrative arc (PCA flips the random-destination flood from BENIGN to ATTACK) is preserved because random_dst's *signature*, high `entropy_dst` with low `entropy_src`, is present in both synth and real CIC-reconstructed packet streams.

**What was generated (Phase 3):**
- Three traffic regimes from `tests/test_three_case_smoke.py`, scaled to ~10,000 packets per case.
- 250-packet windows produce 40 feature rows per case, so 120 total examples (40 BENIGN, 80 ATTACK).
- Each row has the 8-feature vector from PROJECT_IMPROVEMENT_PROMPT §3.B plus a `Label` column.
- `random_dst` rows are labeled `ATTACK` (ground truth: the flood is an attack) even though the entropy-only detector reports BENIGN on them. PCA learns to flip the verdict by gating on `entropy_src ~ 0` in combination with high `entropy_dst`.

---

### Phase 4c: four attack classes

Phase 4c §4c.A widens the builder from three regimes to six and the `Label` column from binary to five-way. 1200 rows: 200 BENIGN, 400 UDP_FLOOD (two variants), 200 each of SYN_FLOOD, SLOWLORIS, NTP_AMP.

**Difficulty discipline.** The first cut of this builder pinned each class to fixed parameter values (UDP_FLOOD always exactly one source, NTP_AMP always exactly 40 reflectors, SLOWLORIS always `pps = 500`). That produced five disjoint point-clouds and a multi-class RF scored macro F1 = 1.0000 on it, which measured the generator rather than the detector. Every class now draws its per-window parameters from a distribution, structurally similar classes deliberately overlap, and ~12% of windows per class are drawn as hard cases whose parameters push into a neighbouring class's territory.

For each class, what the generator produces at the packet level and which per-window features carry its signature:

**UDP_FLOOD** (400 rows, two variants)
- *Packets:* 1-5 attacker sources (skewed toward 1, with a tail reaching ~14). The single-target variant aims every packet at `10.0.0.64`; the random-destination variant sprays uniformly across `10.0.0.[2..64]`. Near-fixed 1024-byte payload with occasional MTU-driven jitter.
- *Discriminative features:* low `entropy_src`, low `unique_src_count`, high `top_src_frequency`. The source side collapses. `entropy_size` and `packet_size_std_dev` stay low from the near-fixed size.
- *Hard cases:* a botnet-shaped variant with 18-70 sources and amplification-shaped payloads, which lands inside NTP_AMP's territory on both of the features that normally separate them.
- *Why both variants share a label:* they differ only in destination spread, which is exactly the Phase 3 point. The random-destination variant keeps `entropy_dst` high, so entropy-only reports BENIGN, and RF must read the source and size collapse instead.

**SYN_FLOOD** (200 rows)
- *Packets:* single victim (~20% of windows spill onto one or two neighbouring hosts, so `unique_dst_count` is not a constant 1 for the class), sources spoofed from a per-window pool of 75-300, so most packets in a window carry a distinct source. 60-byte bare SYN; a quarter of ordinary windows carry some option jitter.
- *Discriminative features:* inverts UDP_FLOOD's source side. High `entropy_src`, `unique_src_count` ~ 38-178 (capped by the 250-packet window), low `top_src_frequency`, low `packet_size_std_dev`.
- *Hard cases:* a small spoof pool (35-90) plus full MSS/option jitter, which removes both of the features separating it from NTP_AMP at once.

**SLOWLORIS** (200 rows)
- *Packets:* single victim, 6-30 long-lived sources, rate-limited by design, small keep-alive writes of slightly varying length.
- *Discriminative features:* `pps` ~ 5-20 against a flood's ~1e5. `unique_src_count` ~ 6-30 and `packet_size_std_dev` ~ 15-30 back it up.
- *Hard cases:* a busier slow-loris (pps into the low thousands) that also spreads across a couple of vhosts and writes larger bodies, moving rate, destination entropy and size variance all toward a quiet BENIGN window.

**NTP_AMP** (200 rows)
- *Packets:* single victim, responses reflected off a pool of 12-110 servers, sizes drawn from monlist reply sizes. A quarter of ordinary windows are dominated by one or two reply sizes.
- *Discriminative features:* `unique_src_count` overlapping both SLOWLORIS below and SYN_FLOOD above; `packet_size_std_dev` ~ 180-400 is what actually carries the class.
- *Hard cases:* either a large open-resolver pool (90-160 sources, reaching into SYN_FLOOD's band) or a single dominant reply size that collapses the size variance toward a plain flood.

**BENIGN** (200 rows)
- *Packets:* source-pool size (8-254), destination spread (12-63 hosts), packet-size mix and rate all vary window to window, so the class spans a range of legitimate traffic shapes rather than sitting on one point. ~22% of windows are near-idle.
- *Hard cases:* a concentrated session (single destination, 4-25 clients, low rate, small uniform payloads), which is indistinguishable from slow-loris on `entropy_dst`, `unique_dst_count`, `top_dst_frequency`, `unique_src_count` and `pps` simultaneously.

**Designed overlaps.** These pairs are where the confusion-matrix off-diagonal mass lives:

| Pair | Overlap on | Separated by |
|---|---|---|
| UDP_FLOOD / NTP_AMP | `entropy_dst`, `pps`, `window_packets` | `packet_size_std_dev` (plain vs amplified), `unique_src_count` |
| SYN_FLOOD / NTP_AMP | `unique_src_count` (both many-source) | `packet_size_std_dev`, `entropy_size` |
| SLOWLORIS / BENIGN | `pps`, `unique_dst_count`, `entropy_dst` | packet-size mix only |

**Feature noise.** After the per-window features are computed, small Gaussian noise is added to `entropy_dst`, `entropy_src`, `entropy_size` and `packet_size_std_dev`. This models measurement jitter and stops the entropy features from being exact functions of the generator's parameters, which is what made the classes analytically separable before.

### Honest limitations

Three, in descending order of how much they should temper the README's numbers.

1. **This is synthetic data, and the macro F1 is a statement about this generator's difficulty.** The classes are no longer separable by construction, and `python scripts/probe_separability.py` is committed so that claim is checkable rather than asserted: within-class spread 2.77 z-units against a minimum inter-class centroid gap of 2.29; a depth-3 tree reaches 0.6854 against the forest's 0.9270; no single feature's removal moves macro F1 by more than 0.028; additive noise at 0.10 of each feature's own sigma costs 0.13 macro F1. But a parameterized generator still cannot reproduce how real classes overlap. Real CICDDoS2019, DARPA, or MAWI captures would replace it in a production evaluation.
2. **The PCA detector's numbers regressed sharply on this dataset, and that regression is informative.** Its previous 1.0000 depended on the old generator holding benign `pps` constant; see README §Evaluation "What the PCA row means". The training pipeline now standardizes before the PCA fit, but the 99th-percentile threshold is still calibrated for a much tighter benign cluster than this dataset has.
3. **No L4 protocol semantics.** Phase 4c chose coarse fidelity deliberately (plan Q1): the generator produces per-window *feature distributions* per class, not real TCP flags, NTP query/reply exchanges, or half-open connection state. `EntropyAnalyzer` only ever consumes source IP, destination IP, and packet size, so adding protocol realism would add lines without moving any number in the evaluation.

**How to reproduce:**

```bash
python scripts/build_synth_dataset.py --seed 42
```

Deterministic: the same seed produces a byte-identical CSV across machines and OSes. The script prints the output sha256 on completion:

```
# Phase 3 (8 features, before packet-size landing):
OUTPUT_SAMPLE_SHA256 = 418d5a9c726f44a40d598ca6c79d9bbf46b6551f9db10f9b3bfa1bdeb0712959

# Phase 4a (10 features: added entropy_size at column 3, packet_size_std_dev at column 10):
OUTPUT_SAMPLE_SHA256 = 0a6ad54d12fd97a3c68e94d319ec89e461f051042fde159bbcecd2b88217ff70

# Phase 4c (10 features, five-way Label: BENIGN + UDP_FLOOD + SYN_FLOOD + SLOWLORIS + NTP_AMP):
OUTPUT_SAMPLE_SHA256 = e6bfb3b2db54f136b3072c501598ef2061c94e61a200aee29437beddc449c31a

# Phase 4c redo (overlapping classes, 1200 rows at 200 windows/case):
OUTPUT_SAMPLE_SHA256 = 3f43e7208a7695a7911f9d72f2e0d04f2a137815f09c7c4c5832932e71e9d4f9
```

**Looking forward:** a later refresh may revisit with real CICDDoS2019 data once the UNB download completes. The migration is a single command: run `scripts/extract_sample.py` against the downloaded full CSV, paste the new `EXPECTED_SOURCE_SHA256` / `EXPECTED_SAMPLE_SHA256` values above, re-run `notebooks/train_pca_and_rf.py`, refresh the `models/*.joblib` artifacts, update the README §Evaluation table. No detector or test code needs to change: the training pipeline reads whichever `samples/cicddos2019_sample.csv` is on disk. Note that real data will not carry the five-way `Label` values this synth path emits, so the label mapping in `cell_2_to_windows` is where that migration starts.
