# THEMIS

**THEMIS: Harnessing Large Language Models Augmented with Threat Knowledge for Automated Attack Investigation**

THEMIS is an LLM-empowered attack investigation framework that:
1. Constructs a Cyber Kill Chain-aligned threat knowledge base from public attack logs
2. Performs alert-driven iterative graph expansion with adjacency-prioritized exploration
3. Applies causal reasoning with RAG-retrieved threat knowledge
4. Generates coherent, analyst-ready investigation reports

## Architecture (Paper §4)

```
Stage 1: Knowledge Base Construction
  ├── Kill-Chain Knowledge Base Annotation (supplementary/kill_chain_annotator.py)
  ├── Semantic Embedding & Index (supplementary/rebuild_kb_ark.py, VDB_data_utils.py)
  
Stage 2: Attack Investigation  
  ├── Adjacency-Prioritized Expansion (utils.py, supplementary/graph_utils.py)
  ├── Causal Reasoning with RAG (attack_Investigation_byLLM.py, supplementary/normalize.py)
  ├── Story Generation (supplementary/story_generator.py)
  
Evaluation:
  ├── Event-level TPR/FPR (supplementary/evaluate_fullgraph_event.py)
  ├── Node-level TPR/FPR (supplementary/evaluate_nodelevel.py)
  └── Graph Compression (supplementary/compress_connected_subgraph.py)
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

| Module | File | Paper Section |
|--------|------|---------------|
| Kill-Chain KB Annotation | `supplementary/kill_chain_annotator.py` | §4.1 |
| KB Construction (embedding) | `supplementary/rebuild_kb_ark.py` | §4.1 |
| Investigation (main loop) | `attack_Investigation_byLLM.py` | §4.2-4.3 |
| Graph Expansion | `utils.py`, `supplementary/graph_utils.py` | §4.2 |
| Entity Normalization | `supplementary/normalize.py` | §4.2 |
| Story Generation | `supplementary/story_generator.py` | §4.4 |
| Event-level Evaluation | `supplementary/evaluate_fullgraph_event.py` | §5 |
| Graph Compression | `supplementary/compress_connected_subgraph.py` | §4.2 |

## Requirements

- Python 3.10+
- openai (Ark API compatible)
- pymilvus (Zilliz/Milvus for KB)
- networkx (provenance graph)
- pdfminer.six (optional, for KB from PDFs)

## Notes

- LLM prompts (`generate_backward_prompt`, `generate_forward_prompt` in `attack_Investigation_byLLM.py`) 
  are in Chinese as they were designed for Chinese-language threat intelligence scenarios.
- All API keys are loaded from environment variables (`.env` file or system env).
- The framework is label-blind: investigation uses only the alert entity + graph structure.
