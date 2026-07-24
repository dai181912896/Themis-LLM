# THEMIS

THEMIS is an LLM-empowered attack investigation framework that reconstructs multi-phase attack scenarios from massive heterogeneous logs and generates coherent, analyst-ready investigation reports.

## Overview

THEMIS operates in two stages:

**Stage 1: Knowledge Base Construction** — Automatically processes public attack logs, aligns events with Cyber Kill Chain phases, and stores them as structured knowledge units with semantic embeddings for retrieval.

**Stage 2: Attack Investigation** — Starting from an IDS alert, THEMIS iteratively explores the provenance graph, retrieves relevant threat knowledge, performs causal reasoning, and generates a complete attack narrative.

## Architecture

```
Core library: themis/   (config, llm, embeddings, vector_db, logs, graph, prompts, investigation, kb, story)
Entry points: attack_Investigation_byLLM.py, supplementary/kill_chain_annotator.py, supplementary/story_generator.py
              (thin CLI shims that delegate to themis/ — kept for backward-compatible invocation)

Stage 1: Knowledge Base Construction
  ├── Kill-Chain Knowledge Base Annotation (themis/kb.py)
  └── Semantic Embedding & Index (themis/embeddings.py, themis/vector_db.py)

Stage 2: Attack Investigation
  ├── Adjacency-Prioritized Expansion (themis/graph.py, themis/logs.py)
  ├── Causal Reasoning with RAG (themis/prompts.py, themis/investigation.py)
  └── Story Generation (themis/story.py)

Evaluation:
  ├── Event-level TPR/FPR (supplementary/evaluate_fullgraph_event.py)
  ├── Node-level TPR/FPR (supplementary/evaluate_nodelevel.py)
  └── Graph Compression (supplementary/compress_connected_subgraph.py)

Baselines:
  ├── ProVSeek (baselines/provseek_eval.py)
  └── NodLink (baselines/nodlink_investigation.py)
```

## Quick Start

```bash
# 1. Configure API keys
cp .env.example .env
# Edit .env with your Ark API key + Zilliz token

# 2. Build Kill Chain Knowledge Base
python supplementary/kill_chain_annotator.py \
  --log data/attack_triples.txt \
  --entities data/malicious_entities.json \
  --out data/kb/annotated_kb.json

# 3. Run Investigation
python supplementary/run_themis_investigation.py \
  --input data/compressed_triples.tsv \
  --ground-truth data/ground_truth.json \
  --collection attack_pattern_s1_s2s3s4 \
  --out results/ \
  --alert certutil.exe

# 4. Generate Investigation Report
python supplementary/story_generator.py \
  --cache results/reasoning_cache.jsonl \
  --out results/investigation_report.md

# 5. Evaluate
python supplementary/evaluate_fullgraph_event.py \
  --edges data/full_edges.jsonl \
  --ground-truth data/ground_truth.json \
  --prediction results/prediction.json \
  --out results/evaluation.json
```

## Key Modules

| Module | File | Description |
|--------|------|-------------|
| Configuration | `themis/config.py` | Endpoints, Kill Chain phases, behavior flags (env-driven) |
| LLM call wrapper | `themis/llm.py` | Volcengine Ark client with retry/backoff |
| Embeddings | `themis/embeddings.py` | doubao-embedding-vision (Ark-first) |
| Vector DB client | `themis/vector_db.py` | Zilliz/Milvus KB client + insertion |
| Kill-Chain KB Annotation | `themis/kb.py` | Extracts malicious events, annotates with Kill Chain phases |
| Graph Expansion | `themis/graph.py` | Adjacency-prioritized neighbor exploration + hub/noise logic |
| Log utilities | `themis/logs.py` | Triple log loading, chunking, JSON parsing |
| Causal Reasoning prompts | `themis/prompts.py` | normal / backward / forward prompt builders |
| Investigation (main loop) | `themis/investigation.py` | Iterative BFS expansion + LLM causal reasoning |
| Batch Pre-Filter | `themis/prefilter.py` | Dedup + cache-I/O + learned-noise filtering per fetched chunk |
| Noise Rules Store | `themis/rules.py` | Thread-safe persisted learned noise patterns (`noise_rules.json`) |
| Runtime Noise Analyzer | `themis/noise_analyzer.py` | Optional parallel LLM thread that learns noise patterns |
| Story Generation | `themis/story.py` | Consolidates reasoning into analyst-ready report |
| Entity Normalization | `supplementary/normalize.py` | Basename/IP/normalized entity matching (canonical) |
| KB rebuild (Ark embeddings) | `supplementary/rebuild_kb_ark.py` | Re-embed KB into *_doubao collections |
| Event-level Evaluation | `supplementary/evaluate_fullgraph_event.py` | TPR/FPR over full provenance graph |
| Node-level Evaluation | `supplementary/evaluate_nodelevel.py` | Strict per-node TPR/FPR |
| Graph Compression | `supplementary/compress_connected_subgraph.py` | BFS-based subgraph compression |

## Requirements

- Python 3.10+
- openai (Ark API compatible)
- pymilvus (Zilliz/Milvus for KB)
- networkx (provenance graph)

## Datasets

THEMIS is evaluated on:
- **ATLAS** (S1-S4): CVE-based attack scenarios on Windows
- **SimulatedW10**: APT29 / FIN6 / Sidewinder on Windows 10 (1.88M events)
- **SimulatedWS12**: Brute-force + lateral movement on Windows Server 2012 (1.08M events)
- **SimulatedUbuntu**: Multi-host attack on Ubuntu Linux (19.1M events)

See `datasets/README.md` for preparation instructions.

**Download:** [Baidu Netdisk](https://pan.baidu.com/s/1E-UfGho3w7zMp9T0F08k5w?pwd=fezk) (extraction code: `fezk`).

## Notes

- All API keys are loaded from environment variables (`.env` file or system env).
- The framework is label-blind: investigation uses only the alert entity + graph structure, never ground-truth labels.
