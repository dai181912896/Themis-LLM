"""Run NodLink's INVESTIGATION step (only) on a NODLINK-format edges.jsonl.

NodLink's investigation engine (atlas_investigate.InvestigationEngine) is
STANDALONE (no VAE/FastText model needed) — it does bidirectional provenance
propagation from a seed alert node. This isolates the investigation step from
NodLink's detection step, for a fair investigation-only comparison vs Themis.

Builds a networkx DiGraph from edges.jsonl, seeds with the alert entity, runs
propagate(f_depth=5, b_depth=5), extracts discovered basenames -> prediction.json.
"""
import argparse
import json
import os
import sys

import networkx as nx

NODLINK_ETW = "D:/git_investigation/NODLINK/src/ETW"
if NODLINK_ETW not in sys.path:
    sys.path.insert(0, NODLINK_ETW)
from atlas_investigate import InvestigationEngine, find_seed_in_graph, extract_basenames  # noqa: E402


def build_graph_from_edges(edges_path):
    G = nx.DiGraph()
    node_attrs = {}
    with open(edges_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                e = json.loads(line)
            except Exception:
                continue
            s = e.get("source_attr") or e.get("subject") or ""
            d = e.get("dest_attr") or e.get("object") or ""
            if not s or not d:
                continue
            G.add_edge(s, d)
            if s not in node_attrs:
                node_attrs[s] = {"label": s, "type": (e.get("source_type") or "process").lower(), "score": 0}
            if d not in node_attrs:
                node_attrs[d] = {"label": d, "type": (e.get("dest_type") or "file").lower(), "score": 0}
    return G, node_attrs


def run(edges_path, alert, out, f_depth=5, b_depth=5):
    G, node_attrs = build_graph_from_edges(edges_path)
    seed = find_seed_in_graph(G, node_attrs, alert)
    if not seed:
        print(f"[nodlink-inv] seed '{alert}' NOT FOUND in graph ({len(G)} nodes)")
        return None
    engine = InvestigationEngine(G, node_attrs)
    discovered = engine.propagate({seed}, f_depth=f_depth, b_depth=b_depth)
    discovered.add(seed)
    basenames = sorted(extract_basenames(discovered, node_attrs))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"method": "NodLink(investigation)", "alert": alert,
               "predicted_entities": basenames, "n_predicted": len(basenames),
               "f_depth": f_depth, "b_depth": b_depth},
              open(out, "w"), indent=2, ensure_ascii=False)
    print(f"[nodlink-inv] alert={alert} seed={seed} discovered_nodes={len(discovered)} "
          f"basenames={len(basenames)} -> {out}")
    return basenames


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--edges", required=True)
    ap.add_argument("--alert", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--f-depth", type=int, default=5)
    ap.add_argument("--b-depth", type=int, default=5)
    a = ap.parse_args()
    run(a.edges, a.alert, a.out, a.f_depth, a.b_depth)
