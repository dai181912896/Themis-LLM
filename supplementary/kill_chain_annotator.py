"""Thin CLI shim — delegates to ``themis.kb`` (Kill-Chain KB annotation).

Preserved so existing invocations
(``python supplementary/kill_chain_annotator.py --log ... --entities ... --out ...``)
keep working. The real implementation lives in ``themis/kb.py``.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from themis.kb import build_kill_chain_kb

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Kill-Chain Knowledge Base Annotation")
    ap.add_argument("--log", required=True, help="Raw triples file (subject action object)")
    ap.add_argument("--entities", required=True, help="JSON with malicious entities")
    ap.add_argument("--out", required=True, help="Output KB JSON file")
    ap.add_argument("--chunk-size", type=int, default=20)
    a = ap.parse_args()
    build_kill_chain_kb(a.log, a.entities, a.out, a.chunk_size)
