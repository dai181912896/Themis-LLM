"""Themis — LLM-empowered attack investigation framework.

Package layout maps to the four pipeline stages:

  Stage 1 — Kill-Chain Knowledge Base   : themis.kb, themis.embeddings, themis.vector_db
  Stage 2 — Adjacency Expansion          : themis.graph, themis.logs
  Stage 3 — Causal Reasoning with RAG    : themis.prompts, themis.investigation
  Stage 4 — Story Generation             : themis.story

Shared infra: themis.config (endpoints + Kill Chain phases + env flags),
themis.llm (LLM call wrapper). Entity normalization lives in
``supplementary.normalize`` (canonical; the evaluators depend on it).
"""

__version__ = "1.0.0"
