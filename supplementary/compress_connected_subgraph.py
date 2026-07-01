import argparse
import json
import os
import sys
from collections import defaultdict, deque

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXP = os.path.abspath(os.path.join(_HERE, ".."))
if _EXP not in sys.path:
    sys.path.insert(0, _EXP)

from supplementary.normalize import normalize_entity, _basename, _ip_no_port, _is_ip

PRIORITY = {"fork": 5, "execute": 5, "start": 5,
            "write": 4, "delete": 4, "connect": 4, "sock_send": 4,
            "recv": 3, "load": 2, "read": 1}


def _matches_ioc(attr, ioc_sets):
    if not attr:
        return False
    n = normalize_entity(attr)
    if n in ioc_sets["norm"]:
        return True
    if _basename(attr) in ioc_sets["base"]:
        return True
    if _is_ip(n) and _ip_no_port(attr) in ioc_sets["ip"]:
        return True
    return False


def _ioc_sets(iocs):
    return {"norm": {normalize_entity(x) for x in iocs if x},
            "base": {_basename(x) for x in iocs if x},
            "ip": {_ip_no_port(x) for x in iocs if _is_ip(normalize_entity(x))}}


def compress(edges_path, seeds_path, gold_path, out_dir, hop=2, max_edges=5000,
             time_window_sec=0, dedup="first_last"):
    os.makedirs(out_dir, exist_ok=True)
    seeds = json.load(open(seeds_path, encoding="utf-8"))
    gold = json.load(open(gold_path, encoding="utf-8"))
    iocs = gold["iocs"]
    seed_attrs = {normalize_entity(s["attr"]) for s in seeds["seed_nodes"]}

    edges, adj = [], defaultdict(set)
    seed_first_ts = None
    with open(edges_path, "r", encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            s = normalize_entity(e["source_attr"])
            d = normalize_entity(e["dest_attr"])
            eid = e["edge_id"]
            edges.append({"s": s, "a": e["action"], "d": d,
                          "t": float(e["timestamp"]), "id": eid,
                          "label": e.get("label", "benign")})
            adj[s].add(d); adj[d].add(s)
            if s in seed_attrs or d in seed_attrs:
                ts = float(e["timestamp"])
                seed_first_ts = ts if seed_first_ts is None else min(seed_first_ts, ts)
    raw_edges = len(edges)

    front = deque((s, 0) for s in seed_attrs if s in adj)
    reached = set(seed_attrs)
    while front:
        n, h = front.popleft()
        if h >= hop:
            continue
        for m in sorted(adj.get(n, ())):
            if m not in reached:
                reached.add(m)
                front.append((m, h + 1))

    cand = [e for e in edges if e["s"] in reached and e["d"] in reached]

    frontier_k = int(os.environ.get("THEMIS_FRONTIER_K", "0"))
    if frontier_k > 0:
        by_src = defaultdict(list)
        for e in edges:
            if e["s"] in reached and e["d"] not in reached and PRIORITY.get(e["a"], 0) >= 4:
                by_src[e["s"]].append(e)
        for s, es in by_src.items():
            es.sort(key=lambda x: (-PRIORITY.get(x["a"], 0), x["id"]))
            cand.extend(es[:frontier_k])

    if time_window_sec and time_window_sec > 0 and seed_first_ts is not None:
        lo, hi = seed_first_ts - time_window_sec, seed_first_ts + time_window_sec
        cand = [e for e in cand if lo <= e["t"] <= hi]

    groups = defaultdict(list)
    for e in cand:
        groups[(e["s"], e["a"], e["d"])].append(e)
    deduped = []
    for k, es in groups.items():
        es.sort(key=lambda x: (x["t"], x["id"]))
        keep = [es[0]] if len(es) == 1 else [es[0], es[-1]]
        deduped.extend(keep)

    if len(deduped) > max_edges:
        deduped.sort(key=lambda x: (-PRIORITY.get(x["a"], 0), x["id"]))
        deduped = deduped[:max_edges]
    deduped.sort(key=lambda x: (x["t"], x["id"]))

    nodes_out = {}
    with open(os.path.join(out_dir, "compressed_triples.tsv"), "w", encoding="utf-8") as f:
        for e in deduped:
            f.write(f"{e['s']}\t{e['a']}\t{e['d']}\t{e['t']}\t{e['id']}\n")
            nodes_out[e["s"]] = True; nodes_out[e["d"]] = True
    with open(os.path.join(out_dir, "compressed_nodes.json"), "w", encoding="utf-8") as f:
        json.dump(list(nodes_out.keys()), f)
    with open(os.path.join(out_dir, "ground_truth.json"), "w", encoding="utf-8") as f:
        json.dump({"iocs": iocs, "label_source": "weak_entity_projection"}, f, indent=2)

    covered, missing = [], []
    for ioc in iocs:
        s_ioc = _ioc_sets([ioc])
        if any(_matches_ioc(e["s"], s_ioc) or _matches_ioc(e["d"], s_ioc) for e in deduped):
            covered.append(ioc)
        else:
            missing.append(ioc)
    n_mal_kept = sum(1 for e in deduped if e["label"] == "malicious")

    parent = {}
    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for e in deduped:
        rs, rd = find(e["s"]), find(e["d"])
        if rs != rd:
            parent[rs] = rd
    roots = {find(n) for n in nodes_out}
    connected = len(roots) <= 1

    meta = {
        "raw_edges": raw_edges, "raw_nodes_reached": len(reached),
        "candidate_edges_after_bfs": len(cand),
        "compressed_edges": len(deduped), "compressed_nodes": len(nodes_out),
        "compression_ratio_edges": round(raw_edges / max(1, len(deduped)), 2),
        "connected": connected, "hop": hop, "max_edges": max_edges,
        "time_window_sec": time_window_sec, "dedup_policy": dedup,
        "config_role": "primary", "seed_entities": list(seed_attrs),
        "matched_seed_nodes": len(seeds["seed_nodes"]),
        "gold_entity_coverage": {"covered": covered, "total": iocs,
                                 "recall": round(len(covered) / max(1, len(iocs)), 4),
                                 "missing": missing},
        "gold_coverage_pre_expansion": {"recall": round(len(covered) / max(1, len(iocs)), 4),
                                        "expansion_fired": False},
        "malicious_edges_kept": n_mal_kept,
        "bfs_tiebreak": "sorted_adjacency_time_sorted_output",
        "note": "label-blind: trim uses action priority + edge_id only, never `label`",
    }
    with open(os.path.join(out_dir, "compression_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"[compress] raw={raw_edges} bfs_cand={len(cand)} -> compressed={len(deduped)} "
          f"(ratio {meta['compression_ratio_edges']}x) connected={connected} "
          f"gold_cov={len(covered)}/{len(iocs)} mal_kept={n_mal_kept} -> {out_dir}")
    return meta


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--edges", required=True)
    ap.add_argument("--seeds", required=True)
    ap.add_argument("--gold", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--hop", type=int, default=2)
    ap.add_argument("--max-edges", type=int, default=5000)
    ap.add_argument("--time-window-sec", type=float, default=0)
    ap.add_argument("--dedup", default="first_last")
    a = ap.parse_args()
    compress(a.edges, a.seeds, a.gold, a.out, a.hop, a.max_edges, a.time_window_sec, a.dedup)
