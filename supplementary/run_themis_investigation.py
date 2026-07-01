import argparse
import ast
import json
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXP = os.path.abspath(os.path.join(_HERE, ".."))
PY = os.environ.get("THEMIS_PY", sys.executable)

PLACEHOLDERS = {"other_entity", "无", "none", "n/a", "null", "xxx", "...", "example.exe"}

DEFAULT_ENV = {
    "ARK_API_KEY": os.environ.get("ARK_API_KEY", ""),
    "ARK_BASE_URL": "https://ark.cn-beijing.volces.com/api/coding/v3",
    "ARK_MODEL": "ark-code-latest",
    "ARK_EMBEDDING_MODEL": "doubao-embedding-vision",
    "ZILLIZ_TOKEN": os.environ.get("ZILLIZ_TOKEN", ""),
    "THEMIS_GRAPH_MODE": "1",
    "THEMIS_MATCH_MODE": "relaxed",
    "THEMIS_HUB_EXPANSION": "1",
    "THEMIS_FILTER_SYSDLL": "1",
    "THEMIS_SLEEP": os.environ.get("THEMIS_SLEEP", "3"),
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
}


def build_input(triples_tsv, iocs, out_path):
    lines = [l for l in open(triples_tsv, encoding="utf-8").read().splitlines() if l.strip()]
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("[" + ",".join(iocs) + "]\n# themis input\n")
        for l in lines:
            f.write(l + "\n")


def parse_output(out_path):
    raw = [l.rstrip("\n") for l in open(out_path, encoding="utf-8", errors="replace")]
    lines = [l for l in raw if l.strip()]
    cost, results, entities = {}, [], []
    if lines:
        try:
            cost = ast.literal_eval(lines[-1]) or {}
        except Exception:
            cost = {}
    body = lines[:-1]
    while body and "{" not in body[-1] and body[-1].rstrip().endswith(","):
        entities.append(body.pop().rstrip().rstrip(",").strip())
    for l in body:
        try:
            results.append(ast.literal_eval(l))
        except Exception:
            pass
    seen, pred = set(), []
    for e in reversed(entities):
        e = e.strip().strip("'\"")
        if not e or e.lower() in PLACEHOLDERS:
            continue
        if e not in seen:
            seen.add(e); pred.append(e)
    return list(reversed(pred)), results, cost


def run(triples_tsv, ground_truth, collection, out, alert=None, dataset="?", scenario="?"):
    os.makedirs(out, exist_ok=True)
    gt = json.load(open(ground_truth, encoding="utf-8"))
    iocs = [e["value"] for e in gt.get("malicious_entities", [])] or gt.get("seeds", []) or gt.get("iocs", [])
    alert = alert or gt.get("alert") or (iocs[0] if iocs else "")
    themis_in = os.path.join(out, "themis_input.txt")
    build_input(triples_tsv, iocs, themis_in)

    trace = os.path.join(out, "adjacency_trace.jsonl")
    if os.path.exists(trace):
        os.remove(trace)
    raw_out = os.path.join(out, "raw_output.txt")

    env = dict(os.environ)
    env.update(DEFAULT_ENV)
    env["THEMIS_TRACE_PATH"] = trace

    cmd = [PY, os.path.join(_EXP, "attack_Investigation_byLLM.py"),
           "--log_file", themis_in, "--alert", alert,
           "--collection", collection, "--output", raw_out]
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=_EXP, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    wall = time.time() - t0
    with open(os.path.join(out, "run.log"), "w", encoding="utf-8") as f:
        f.write(proc.stdout[-8000:] + "\n--- STDERR ---\n" + proc.stderr[-4000:])

    pred, results, cost = parse_output(raw_out)
    cost_out = {
        "wall_time_sec": round(wall, 1),
        "prompt_tokens": cost.get("total_prompt_tokens", 0),
        "completion_tokens": cost.get("total_completion_tokens", 0),
        "reasoning_tokens": cost.get("total_reasoning_tokens", 0),
        "total_tokens": cost.get("total_all_tokens", 0),
    }
    json.dump({"method": "Themis", "dataset": dataset, "scenario": scenario,
               "alert": alert, "predicted_entities": pred,
               "n_predicted": len(pred)}, open(os.path.join(out, "prediction.json"), "w"), indent=2)
    json.dump(cost_out, open(os.path.join(out, "cost.json"), "w"), indent=2)
    with open(os.path.join(out, "reasoning_cache.jsonl"), "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"[Themis/{scenario}] alert={alert} predicted={len(pred)} "
          f"tokens={cost_out['total_tokens']} wall={cost_out['wall_time_sec']}s -> {out}")
    return pred, cost_out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--collection", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--alert", default=None)
    ap.add_argument("--dataset", default="?")
    ap.add_argument("--scenario", default="?")
    a = ap.parse_args()
    run(a.input, a.ground_truth, a.collection, a.out, a.alert, a.dataset, a.scenario)
