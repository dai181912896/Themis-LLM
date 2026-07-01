# Datasets

Themis is evaluated on provenance-graph datasets from four public sources. This
document describes the converted, investigation-ready bundle and how to use it.

> The raw datasets total ~2.31 GB. They compress to a single **~146 MB** archive
> (`themis_datasets.zip`) distributed outside this repository — see
> [Distribution](#distribution). (146 MB exceeds GitHub's 100 MB per-file limit,
> so it is hosted on Releases rather than committed.)

## Sources

| Dataset | Scenarios | Provenance | Original source |
|---|---|---|---|
| ATLAS | `atlas_s1`, `atlas_s3` | CVE-based Windows attacks | ATLAS benchmark |
| SimulatedW10 | `nodlink_w10_apt29`, `nodlink_w10_fin6`, `nodlink_w10_sidewinder` | APT29 / FIN6 / Sidewinder on Windows 10 | Li et al., NodLink (NDSS 2024) |
| SimulatedWS12 | `nodlink_ws12` | Brute-force + lateral movement, Windows Server 2012 | Li et al., NodLink (NDSS 2024) |
| SimulatedUbuntu | `nodlink_ubuntu` | Multi-host attack on Ubuntu Linux | Li et al., NodLink (NDSS 2024) |

## Bundle layout

`themis_datasets.zip` contains:

```
themis_datasets/
├── README.md
├── MANIFEST.json                 # per-scenario file counts + sizes
├── converted/                    # full provenance graphs (Themis-ready)
│   ├── atlas_s1/                 #   triples.tsv, triples.jsonl, ground_truth.json, conversion_metadata.json
│   ├── atlas_s3/
│   ├── nodlink_w10_apt29/        #   edges.jsonl, nodes.json, gold_entities.json, seeds.json, conversion_metadata.json
│   ├── nodlink_w10_fin6/
│   ├── nodlink_w10_sidewinder/
│   ├── nodlink_ws12/
│   └── nodlink_ubuntu/
└── compressed/                   # hop2-compressed triples for fast investigation
    ├── nodlink_w10_apt29_hop2_8k/compressed_triples.tsv
    ├── nodlink_w10_fin6_hop2_8k/compressed_triples.tsv
    ├── nodlink_w10_fin6_hop2_8k_fb3/compressed_triples.tsv
    ├── nodlink_w10_sidewinder_hop2_8k/compressed_triples.tsv
    └── nodlink_ws12_hop2_5k/compressed_triples.tsv
```

### Ground-truth file naming

| Source | Ground-truth file(s) |
|---|---|
| ATLAS / Ubuntu | `ground_truth.json` (`{"malicious_entities": [{"value": ...}]}`) |
| SimulatedW10 / WS12 | `gold_entities.json` + `seeds.json` (NodLink native label format) |

## Usage

Feed a scenario's compressed triples + ground truth to the investigation launcher:

```bash
python supplementary/run_themis_investigation.py \
  --input themis_datasets/compressed/nodlink_w10_apt29_hop2_8k/compressed_triples.tsv \
  --ground-truth themis_datasets/converted/nodlink_w10_apt29/gold_entities.json \
  --collection attack_pattern_s1_s2s3s4 \
  --out results/apt29/ --alert certutil.exe
```

Then evaluate:

```bash
python supplementary/evaluate_fullgraph_event.py \
  --edges themis_datasets/converted/nodlink_w10_apt29/edges.jsonl \
  --ground-truth themis_datasets/converted/nodlink_w10_apt29/gold_entities.json \
  --prediction results/apt29/prediction.json \
  --out results/apt29/evaluation.json
```

## Distribution

Both archives are hosted outside this repository (the dataset archive exceeds
GitHub's 100 MB per-file limit). Host them on a release/share (e.g. GitHub
Releases — supports files up to 2 GB, Zenodo, or institutional storage):

| Archive | Contents | Size |
|---|---|---|
| `themis_datasets.zip` | Converted provenance graphs + ground truth + hop2-compressed inputs | ~146 MB |
| `provseek_code.zip` | ProVSeek baseline source code (sanitized: code only, no data, no secrets) | ~95 KB |

```
https://<your-release-url>/themis_datasets.zip
https://<your-release-url>/provseek_code.zip
```

Reproduction from raw sources is also possible with the original dataset zips
(ATLAS, NodLink SimulatedW10/WS12/Ubuntu) plus the conversion scripts.
