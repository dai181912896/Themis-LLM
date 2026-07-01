import argparse
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


def _iter_node_basenames(edges_path):
    seen = set()
    for l in open(edges_path, encoding="utf-8", errors="replace"):
        try:
            e = json.loads(l)
            s = e.get("source_attr") or e.get("subject") or ""
            o = e.get("dest_attr") or e.get("object") or ""
            for a in (s, o):
                if a:
                    seen.add(a)
        except Exception:
            continue
    return seen


def evaluate(edges_path, ground_truth, prediction_path, out):
    gt = json.load(open(ground_truth, encoding="utf-8"))
    gold = gt.get("iocs") or [e["value"] for e in gt.get("malicious_entities", [])] or gt.get("seeds", [])
    pred_obj = json.load(open(prediction_path, encoding="utf-8"))
    pred = pred_obj.get("predicted_entities", [])
    gk, pk = _keys(gold), _keys(pred)

    nodes = _iter_node_basenames(edges_path)
    universe = len(nodes)
    tp = fp = fn = tn = 0
    gold_nodes = set()
    pred_nodes = set()
    for a in nodes:
        is_gold = _hit(a, gk)
        is_pred = _hit(a, pk)
        if is_gold:
            gold_nodes.add(a)
        if is_pred:
            pred_nodes.add(a)
        if is_pred and is_gold:
            tp += 1
        elif is_pred and not is_gold:
            fp += 1
        elif (not is_pred) and is_gold:
            fn += 1
        else:
            tn += 1

    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    res = {
        "method": pred_obj.get("method"),
        "universe_type": "nodes",
        "universe_nodes": universe,
        "gold_nodes": len(gold_nodes),
        "predicted_entities": pred,
        "n_predicted": len(pred),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "TPR": round(tpr, 4), "FPR": round(fpr, 5),
        "Precision": round(prec, 4),
        "note": "strict per-node; GT=gold IoC basename; no 2-hop relaxation",
    }
    json.dump(res, open(out, "w"), indent=2, ensure_ascii=False)
    print(f"[nodelevel {res['method']}] universe={universe} gold={len(gold_nodes)} "
          f"pred={len(pred)} TP={tp} FP={fp} FN={fn} TN={tn} "
          f"TPR={tpr:.4f} FPR={fpr:.5f} P={prec:.4f} -> {out}")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--edges", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--prediction", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    evaluate(a.edges, a.ground_truth, a.prediction, a.out)
