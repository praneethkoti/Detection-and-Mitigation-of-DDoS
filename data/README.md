# CICDDoS2019 dataset reference

The Phase 3 PCA + RandomForest detectors are trained on the **CICDDoS2019** dataset published by the Canadian Institute for Cybersecurity at the University of New Brunswick. Sharafaldin et al., *Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy*, IEEE CCST 2019. The dataset spans benign traffic and 12 distinct DDoS attack classes (UDP flood, SYN flood, NTP amplification, DNS amplification, etc.); each class ships as a per-attack-class CSV of bidirectional flow records with ~80 features and a `Label` column.

## Where to download

Official landing page: **https://www.unb.ca/cic/datasets/ddos-2019.html**

CIC requires acknowledging a click-through license before download, so this repo intentionally does not include an automated fetcher — provide your name and institution, accept the license, and download the `01-12` split (the more commonly used set; the `03-11` split is also published). The download yields a tree of per-attack-class CSVs; for the Phase 3 detectors the **`UDP.csv`** file is the recommended starting point because it matches the volumetric flood case the entropy detector targets.

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
4. uses `numpy.random.default_rng(seed=42)` for the index draw — same input + same seed produces a byte-identical output across machines and OSes
5. prints the sha256 of both the input and the output file on completion, so the values below can be pasted in verbatim

## Expected sha256s (filled in after first extraction)

```
EXPECTED_SOURCE_SHA256 = synthetic — see ## Fallback (synth) below
EXPECTED_SAMPLE_SHA256 = synthetic — see ## Fallback (synth) below
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

`samples/cicddos2019_sample.csv` is sized for **demo and CI** only — at `--rows 2000` (the default in `scripts/extract_sample.py`) the committed CSV is roughly **5 MB**, large enough to fit a PCA + RandomForest training round in a few seconds. The full Phase 3 evaluation results reported in the README (precision / recall / F1 per attack class) would be computed against the **complete** CICDDoS2019 dataset, not the sample; the sample exists to give CI and offline demos a real-data path that doesn't depend on a 24 GB download.

---

## Fallback (synth)

The version of `samples/cicddos2019_sample.csv` committed in the Phase 3 commit was **not** produced from real CICDDoS2019 data. The UNB download was not available at execution time; the project's Phase 3 plan (§3.E) documents a synth-fallback path that produces a CSV with the **same column shape and Label conventions** the real-data path would produce, but with rows derived from the project's own three smoke generators scaled up.

**Why this path:** keeps Phase 3 unblocked on a single external dependency (UNB CICDDoS2019 access requires acknowledging a click-through license). All other Phase 3 deliverables — `PCADetector`, `MLDetector`, the real `ofp_flow_mod` drop rule, `THREAT_MODEL.md`, Docker, CI — are independent of where the training rows come from. The narrative arc (PCA flips the random-destination flood from BENIGN to ATTACK) is preserved because random_dst's *signature* — high `entropy_dst`, low `entropy_src` — is present in both synth and real CIC-reconstructed packet streams.

**What was generated:**
- Three traffic regimes from `tests/test_three_case_smoke.py`, scaled to ~10,000 packets per case.
- 250-packet windows produce 40 feature rows per case → 120 total examples (40 BENIGN, 80 ATTACK).
- Each row has the 8-feature vector from PROJECT_IMPROVEMENT_PROMPT §3.B plus a `Label` column.
- `random_dst` rows are labeled `ATTACK` (ground truth — the flood is an attack) even though the entropy-only detector reports BENIGN on them. PCA learns to flip the verdict by gating on `entropy_src ≈ 0` in combination with high `entropy_dst`.

**How to reproduce:**

```bash
python scripts/build_synth_dataset.py --seed 42
```

Deterministic — same seed produces a byte-identical CSV across machines and OSes. The script prints the output sha256 on completion:

```
# Phase 3 (8 features, before packet-size landing):
OUTPUT_SAMPLE_SHA256 = 418d5a9c726f44a40d598ca6c79d9bbf46b6551f9db10f9b3bfa1bdeb0712959

# Phase 4a (10 features — added entropy_size at column 3, packet_size_std_dev at column 10):
OUTPUT_SAMPLE_SHA256 = 0a6ad54d12fd97a3c68e94d319ec89e461f051042fde159bbcecd2b88217ff70
```

**Looking forward:** Phase 4 (or any later refresh) may revisit with real CICDDoS2019 data once the UNB download completes. The migration is a single command: run `scripts/extract_sample.py` against the downloaded full CSV, paste the new `EXPECTED_SOURCE_SHA256` / `EXPECTED_SAMPLE_SHA256` values above, re-run `notebooks/train_pca_and_rf.ipynb`, refresh the `models/*.joblib` artifacts, update the README §Evaluation table. No detector or test code needs to change — the notebook reads whichever `samples/cicddos2019_sample.csv` is on disk.
