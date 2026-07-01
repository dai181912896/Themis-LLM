# Themis Configuration Guide

Themis is **fully environment-driven** — there are no hardcoded credentials and
no `config.py` / `LLM_config.py` to edit. All settings are read from the
environment (a `.env` file or your shell), centralized in
[`themis/config.py`](themis/config.py).

## Configure credentials

Copy the example env file and fill in your keys:

```bash
cp .env.example .env
# edit .env
```

| Variable | Purpose | Where to get it |
|---|---|---|
| `ARK_API_KEY` | LLM + embedding API key (Volcengine Ark) | Volcengine console → API Key |
| `ARK_BASE_URL` | Ark API base URL (default set in `themis/config.py`) | — |
| `ARK_MODEL` | Chat model (default `ark-code-latest`) | — |
| `ARK_EMBEDDING_MODEL` | Embedding model (default `doubao-embedding-vision`, 2048-dim) | — |
| `ZILLIZ_TOKEN` | Zilliz/Milvus Kill Chain KB token | https://cloud.zilliz.com/ |
| `ZILLIZ_URI` | Zilliz cluster URI (default set in `themis/config.py`) | — |

## Behavior flags (env-overridable)

These tune the investigation loop (see [`themis/config.py`](themis/config.py)):

| Flag | Default | Effect |
|---|---|---|
| `THEMIS_GRAPH_MODE` | `1` | Parse subject/object for adjacency (no substring) |
| `THEMIS_MATCH_MODE` | `relaxed` | basename / IP-no-port exact matching |
| `THEMIS_HUB_EXPANSION` | `1` | Surface dispatcher-hub sibling fork-children |
| `THEMIS_FILTER_SYSDLL` | `1` | Filter universal system-DLL-load noise |
| `THEMIS_CAP_SELFEXTRACT` | unset | Cap PyInstaller self-extraction artifacts |
| `THEMIS_HUB_CHILD_ACTIONS` | unset | Append sibling child-action evidence |
| `THEMIS_FILTER_NOISE` | unset | Filter noise entities during BFS |
| `THEMIS_MAX_EXPANSIONS` | `0` | BFS entity cap (0 = unlimited) |
| `THEMIS_SLEEP` | `2` | Seconds between LLM iterations |
| `THEMIS_DEDUP` | `1` | Drop duplicate log lines within each fetched chunk |
| `THEMIS_FILTER_CACHE_IO` | `1` | Drop benign cache-file read/write (browser cache, registry hives, NTFS, prefetch, `.tmp`) |
| `THEMIS_NOISE_ANALYZER` | `0` | Runtime parallel LLM analyzer that learns new noise patterns (extra token cost; off by default) |
| `THEMIS_NOISE_RULES` | `noise_rules.json` | Path to the persisted learned-rules file written by the analyzer, re-read each batch |

### Batch pre-filter & runtime noise analyzer

At each chunk fetch, `neighbor_scan` applies a pre-filter (`themis.prefilter`):
duplicate lines are dropped, then benign cache-file read/write is dropped via
the hardcoded `CACHE_IO_SEED` patterns, then any patterns the analyzer learned
into `rules.json`. Currently-detected entities (IoCs like `certutil`,
`mimikatz`) are **never** dropped — only dedup applies to them. An emptied chunk
is skipped entirely (no LLM call).

With `THEMIS_NOISE_ANALYZER=1`, a background thread (`themis.noise_analyzer`)
analyzes each raw chunk in parallel and appends generalized noise patterns to
`rules.json`; the main loop re-reads it each batch, so rules improve within a
run and persist across runs.

## Security notes

- **Never commit real API keys.** `.env` is git-ignored; `.env.example` carries only placeholders.
- Prefer environment variables; rotate keys regularly.

## Run

```bash
# 1. Build the Kill Chain knowledge base
python supplementary/kill_chain_annotator.py \
  --log data/attack_triples.txt --entities data/malicious_entities.json \
  --out data/kb/annotated_kb.json

# 2. Run investigation (Stage 2 + 3)
python supplementary/run_themis_investigation.py \
  --input data/compressed_triples.tsv --ground-truth data/ground_truth.json \
  --collection attack_pattern_s1_s2s3s4 --out results/ --alert certutil.exe

# 3. Generate the report (Stage 4)
python supplementary/story_generator.py \
  --cache results/reasoning_cache.jsonl --out results/investigation_report.md
```
