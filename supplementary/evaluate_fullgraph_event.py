import argparse
import collections
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXP = os.path.abspath(os.path.join(_HERE, ".."))
if _EXP not in sys.path:
    sys.path.insert(0, _EXP)

from supplementary.normalize import normalize_entity, _basename, _ip_no_port, _is_ip


def _keys(entities):
    return {"norm": {normalize_entity(x) for x in entities if x},
            "base": {_basename(x) for x in entities if x},
            "ip": {_ip_no_port(x) for x in entities if _is_ip(normalize_entity(x))}}


def _hit(attr, keys):
    if not attr:
        return False
    n = normalize_entity(attr)
    if n in keys["norm"]:
        return True
    if _basename(attr) in keys["base"]:
        return True
    if _is_ip(n) and _ip_no_port(attr) in keys["ip"]:
        return True
    return False


def _build_reverse_map(gold):
    norm2ioc = collections.defaultdict(set)
    base2ioc = collections.defaultdict(set)
    ip2ioc = collections.defaultdict(set)
    for i, ioc in enumerate(gold):
        if not ioc:
            continue
        norm2ioc[normalize_entity(ioc)].add(i)
        base2ioc[_basename(ioc)].add(i)
        if _is_ip(normalize_entity(ioc)):
            ip2ioc[_ip_no_port(ioc)].add(i)
    return norm2ioc, base2ioc, ip2ioc


def _gold_hit_set(attr, norm2ioc, base2ioc, ip2ioc):
    hit = set()
    if not attr:
        return hit
    n = normalize_entity(attr)
    if n in norm2ioc:
        hit |= norm2ioc[n]
    b = _basename(attr)
    if b in base2ioc:
        hit |= base2ioc[b]
    if _is_ip(n):
        ipa = _ip_no_port(attr)
        if ipa in ip2ioc:
            hit |= ip2ioc[ipa]
    return hit


def _iter_endpoints(edges_path):
    if edges_path.endswith(".jsonl"):
        for l in open(edges_path, encoding="utf-8", errors="replace"):
            try:
                e = json.loads(l)
                s = e.get("source_attr") or e.get("subject") or ""
                o = e.get("dest_attr") or e.get("object") or ""
                if s or o:
                    yield s, o
            except Exception:
                continue
    else:
        for l in open(edges_path, encoding="utf-8", errors="replace"):
            p = l.split("\t") if "\t" in l else l.split()
            if len(p) >= 3:
                yield p[0], p[2]


def evaluate(edges_path, ground_truth, prediction_path, out):
    gt = json.load(open(ground_truth, encoding="utf-8"))
    gold = gt.get("iocs") or [e["value"] for e in gt.get("malicious_entities", [])] or gt.get("seeds", [])
    pred_obj = json.load(open(prediction_path, encoding="utf-8"))
    pred = pred_obj.get("predicted_entities", [])
    pk = _keys(pred)
    norm2ioc, base2ioc, ip2ioc = _build_reverse_map(gold)
    pred_norm2, pred_base2, pred_ip2 = _build_reverse_map(pred)

    tp = fp = tn = fn = 0
    n_events = 0
    ioc_ev = [0] * len(gold)
    pred_ev = [0] * len(pred)

    for s, o in _iter_endpoints(edges_path):
        n_events += 1
        gold_hit = _gold_hit_set(s, norm2ioc, base2ioc, ip2ioc) | \
                   _gold_hit_set(o, norm2ioc, base2ioc, ip2ioc)
        gt_mal = bool(gold_hit)
        for i in gold_hit:
            ioc_ev[i] += 1
        pred_hit = (_gold_hit_set(s, pred_norm2, pred_base2, pred_ip2) |
                    _gold_hit_set(o, pred_norm2, pred_base2, pred_ip2))
        pr_mal = bool(pred_hit)
        for i in pred_hit:
            pred_ev[i] += 1
        if gt_mal and pr_mal:
            tp += 1
        elif gt_mal and not pr_mal:
            fn += 1
        elif (not gt_mal) and pr_mal:
            fp += 1
        else:
            tn += 1

    gold_events = tp + fn
    ioc_breakdown = []
    for i, ioc in enumerate(gold):
        ioc_breakdown.append({
            "ioc": ioc,
            "events": ioc_ev[i],
            "share_of_gold_events": round(ioc_ev[i] / gold_events, 4) if gold_events else 0.0,
        })
    ioc_breakdown.sort(key=lambda r: r["events"], reverse=True)

    pred_breakdown = []
    for i, e in enumerate(pred):
        pred_breakdown.append({
            "predicted_entity": e,
            "events": pred_ev[i],
        })
    pred_breakdown.sort(key=lambda r: r["events"], reverse=True)

    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    res = {
        "method": pred_obj.get("method"),
        "universe_type": "full_graph_events",
        "universe_n_events": n_events,
        "gold_events": gold_events,
        "predicted_entities": pred,
        "n_predicted_entities": len(pred),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "TPR": round(tpr, 4), "FPR": round(fpr, 5),
        "Precision": round(prec, 4),
        "F1": round(2 * prec * tpr / (prec + tpr), 4) if (prec + tpr) else 0.0,
        "per_ioc_event_density": ioc_breakdown,
        "per_predicted_event_density": pred_breakdown,
        "event_label_source": "weak_entity_projection",
        "match_mode": "relaxed (basename/ip/domain)",
        "note": "share_of_gold_events may sum >1: an edge touching multiple IoCs counts for each (density, not a partition).",
    }
    json.dump(res, open(out, "w"), indent=2, ensure_ascii=False)
    print(f"[fullgraph {res['method']}] events={n_events} gold_events={gold_events} "
          f"TPR={tpr:.4f} FPR={fpr:.5f} P={prec:.4f} -> {out}")
    print("  per-IoC gold event density (top):")
    for r in ioc_breakdown[:8]:
        print(f"    {r['events']:6d}  {r['share_of_gold_events']*100:5.1f}%  {r['ioc']}")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--edges", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--prediction", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    evaluate(a.edges, a.ground_truth, a.prediction, a.out)
