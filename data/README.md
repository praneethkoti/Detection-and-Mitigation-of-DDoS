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

## Expected sha256s (filled in by the candidate after first extraction)

```
EXPECTED_SOURCE_SHA256 = <computed by candidate>
EXPECTED_SAMPLE_SHA256 = <computed by candidate>
```

Once the first extraction has been performed, paste both values here so the Phase 3 review can reproduce the exact bytes the model was trained against. The script's output format is:

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

`samples/cicddos2019_sample.csv` is sized for **demo and CI** only — small enough to commit, large enough to fit a PCA + RandomForest training round in a few seconds. The full Phase 3 evaluation results reported in the README (precision / recall / F1 per attack class) are computed against the **complete** CICDDoS2019 dataset, not the sample. The sample exists to give CI and offline demos a real-data path that doesn't depend on a 24 GB download.
