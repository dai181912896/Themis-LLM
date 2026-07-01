import os, json, re, time, sys
from pathlib import Path
from collections import defaultdict
from dotenv import load_dotenv
load_dotenv()

DATASET = sys.argv[1] if len(sys.argv) > 1 else "ws12"
THEMIS_EXP = Path("D:/git_investigation/Themis/exp")

DATA_MAP = {
    "ws12": {
        "triples": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_ws12_hop2_5k/compressed_triples.tsv"),
        "ground_truth": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_ws12_hop2_5k/ground_truth.json"),
        "edges": str(THEMIS_EXP / "data/supplementary/converted/nodlink_ws12/edges.jsonl"),
        "alert": "WinBrute.exe",
        "scenario": "Windows Server 2012 brute-force + lateral movement",
    },
    "apt29": {
        "triples": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_w10_apt29_hop2_8k/compressed_triples.tsv"),
        "ground_truth": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_w10_apt29_hop2_8k/ground_truth.json"),
        "edges": str(THEMIS_EXP / "data/supplementary/converted/nodlink_w10_apt29/edges.jsonl"),
        "alert": "certutil.exe",
        "scenario": "APT29 credential dumping via mimikatz + Invoke-Mimikatz",
    },
    "fin6": {
        "triples": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_w10_fin6_hop2_8k/compressed_triples.tsv"),
        "ground_truth": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_w10_fin6_hop2_8k/ground_truth.json"),
        "edges": str(THEMIS_EXP / "data/supplementary/converted/nodlink_w10_fin6/edges.jsonl"),
        "alert": "lazagne1.exe",
        "scenario": "FIN6 credential theft via lazagne + procdump",
    },
    "sidewinder": {
        "triples": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_w10_sidewinder_hop2_8k/compressed_triples.tsv"),
        "ground_truth": str(THEMIS_EXP / "data/supplementary/compressed/nodlink_w10_sidewinder_hop2_8k/ground_truth.json"),
        "edges": str(THEMIS_EXP / "data/supplementary/converted/nodlink_w10_sidewinder/edges.jsonl"),
        "alert": "certutil.exe",
        "scenario": "Sidewinder HTA download via certutil + mshta execution",
    },
}

CFG = DATA_MAP[DATASET]
REPORT_PATH = Path(f"D:/git_investigation/ProVSeek/provseek_{DATASET}_report.json")

import rich.console
_o = rich.console.Console.render_str
def _s(self, t, *a, **kw):
    try: return _o(self, t, *a, **kw)
    except:
        from rich.text import Text
        return Text(str(t).replace("\\[","[").replace("\\]","]"))
rich.console.Console.render_str = _s

from smolagents import LiteLLMModel, CodeAgent, tool
from rich.markup import escape

print(f"[{DATASET}] Loading compressed triples: {CFG['triples']}")
events = []
with open(CFG["triples"], encoding="utf-8", errors="replace") as f:
    for i, line in enumerate(f):
        parts = line.strip().split("\t") if "\t" in line else line.strip().split()
        if len(parts) >= 3:
            events.append({"idx": i, "subject": parts[0], "action": parts[1],
                           "object": " ".join(parts[2:5])})

gt = json.load(open(CFG["ground_truth"], encoding="utf-8"))
gold_iocs = gt.get("iocs", [])
mal_labels = set()
for ioc in gold_iocs:
    b = ioc
    for sep in ["/", "\\", ":"]:
        b = b.split(sep)[-1]
    mal_labels.add(b.lower().replace(".exe", "").replace(".dll", ""))

print(f"[{DATASET}] {len(events)} events, {len(mal_labels)} gold IoCs: {gold_iocs[:8]}")

entity_events = defaultdict(list)
for e in events:
    entity_events[e["subject"]].append(e)
    entity_events[e["object"]].append(e)

reasoning_model_id = os.getenv("REASONING_MODEL_ID", "openai/ark-code-latest")
tool_model_id = os.getenv("TOOL_MODEL_ID", "openai/ark-code-latest")
openai_api_key = os.getenv("OPENAI_API_KEY", "")
openai_base = os.getenv("OPENAI_API_BASE", "https://ark.cn-beijing.volces.com/api/plan/v3")

def get_model(mid):
    return LiteLLMModel(
        model_id=mid, api_key=openai_api_key, api_base=openai_base,
        additional_drop_params=["stop"],
    )

reasoner = CodeAgent(tools=[], model=get_model(reasoning_model_id), add_base_tools=False, max_steps=10)

@tool
def search_events(entity_name: str) -> str:
    nl = entity_name.lower().strip()
    matched = {n for n in entity_events if nl in n.lower()}
    if not matched:
        return f"No entities matching '{entity_name}' found."
    seen, relevant = set(), []
    for ent in matched:
        for e in entity_events[ent]:
            k = (e["subject"], e["action"], e["object"])
            if k not in seen:
                seen.add(k); relevant.append(e)
    if len(relevant) > 30: relevant = relevant[:30]
    all_ents = {e["subject"] for e in relevant} | {e["object"] for e in relevant}
    lines = [f"Found {len(matched)} entities, {len(relevant)} events:"]
    lines.append(f"Matched: {sorted(matched)[:15]}")
    lines.append(f"Related: {sorted(all_ents - matched)[:15]}")
    lines.append("---")
    for e in relevant:
        lines.append(f"  {e['subject']} {e['action']} {e['object']}")
    return "\n".join(lines)

@tool
def list_entities() -> str:
    subjects = sorted(set(e["subject"] for e in events))
    lines = [f"Total events: {len(events)}, Unique subjects: {len(subjects)}"]
    for s in subjects[:30]:
        lines.append(f"  subj: {s} (x{len(entity_events[s])})")
    return "\n".join(lines)

agent = CodeAgent(tools=[search_events, list_entities],
                  model=get_model(tool_model_id),
                  additional_authorized_imports=["json", "re", "os"], max_steps=15)

def _extract_list(text, prefix):
    items = set()
    for m in re.findall(rf'{prefix}\s*:\s*\[([^\]]+)\]', text, re.IGNORECASE):
        for x in m.split(","):
            x = x.strip().strip("'\"")
            if x and x.lower() not in ("none", "n/a", ""): items.add(x)
    if not items:
        for m in re.findall(rf'{prefix}\s*:\s*(.+?)(?:\n|$)', text, re.IGNORECASE):
            for x in m.split(","):
                x = x.strip().strip("'\"")
                if x and x.lower() not in ("none", "n/a", ""): items.add(x)
    return items

def extract_iocs(text):
    return {"process": sorted(_extract_list(text, r'Processes?')),
            "file": sorted(_extract_list(text, r'Files?')),
            "ip": sorted(_extract_list(text, r'IP\s*Address'))}

query = f"""Investigate the following threat scenario in the provenance data.
Alert entity: {CFG['alert']}
Scenario: {CFG['scenario']}

Steps:
1. Search for '{CFG['alert']}' to find its related events.
2. Search for related processes, files, and IPs that appear in the alert's neighborhood.
3. Identify ALL malicious entities (processes, files, IPs) involved in this attack.
4. Provide your findings in this exact format:
   Processes: [process1, process2, ...]
   Files: [file1, file2, ...]
   IP Address: [ip1, ip2, ...]
"""

print(f"\n[{DATASET}] Running ProVSeek agent...")
t0 = time.time()
try:
    result = agent.run(query)
    elapsed = time.time() - t0
    print(f"\n[RESULT] {len(str(result))} chars, {elapsed:.1f}s")
except Exception as e:
    import traceback; traceback.print_exc()
    result = str(e)
    elapsed = time.time() - t0

total_tokens = 0
try:
    for log_entry in agent.logs:
        if hasattr(log_entry, 'token_usage') and log_entry.token_usage:
            total_tokens += log_entry.token_usage
except: pass

iocs = extract_iocs(str(result))
all_detected = set()
for v in iocs.values(): all_detected.update(v)

gold_norm = set()
for ioc in gold_iocs:
    b = ioc.lower().replace(".exe", "").replace(".dll", "")
    for sep in ["/", "\\", ":"]: b = b.split(sep)[-1]
    gold_norm.add(b)
det_norm = set()
for d in all_detected:
    b = str(d).lower().replace(".exe", "").replace(".dll", "")
    for sep in ["/", "\\", ":"]: b = b.split(sep)[-1]
    det_norm.add(b)

tp = gold_norm & det_norm
fp = det_norm - gold_norm
fn = gold_norm - det_norm
prec = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 0
rec = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 0
f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

sys.path.insert(0, str(THEMIS_EXP / "supplementary"))
from evaluate_nodelevel import _keys, _hit
pk = _keys(list(all_detected))
gk = _keys(gold_iocs)
tp_ev = fp_ev = fn_ev = tn_ev = 0
with open(CFG["edges"], encoding="utf-8", errors="replace") as f:
    for line in f:
        try: e = json.loads(line)
        except: continue
        s = e.get("source_attr", ""); d = e.get("dest_attr", "")
        gm = _hit(s, gk) or _hit(d, gk)
        pm = _hit(s, pk) or _hit(d, pk)
        if gm and pm: tp_ev += 1
        elif gm and not pm: fn_ev += 1
        elif not gm and pm: fp_ev += 1
        else: tn_ev += 1

ev_tpr = tp_ev / (tp_ev + fn_ev) if (tp_ev + fn_ev) else 0
ev_fpr = fp_ev / (fp_ev + tn_ev) if (fp_ev + tn_ev) else 0

report = {
    "method": "ProVSeek_Agent",
    "dataset": f"NODLINK_{DATASET.upper()}",
    "alert": CFG["alert"],
    "gold_iocs": gold_iocs,
    "detected_iocs": iocs,
    "entity_metrics": {"TP": len(tp), "FP": len(fp), "FN": len(fn),
        "Precision": round(prec,4), "Recall": round(rec,4), "F1": round(f1,4),
        "tp_list": sorted(tp), "fp_list": sorted(fp)[:20], "fn_list": sorted(fn)},
    "event_metrics": {"TP": tp_ev, "FP": fp_ev, "FN": fn_ev, "TN": tn_ev,
        "TPR": round(ev_tpr,4), "FPR": round(ev_fpr,5),
        "total_events": tp_ev+fp_ev+fn_ev+tn_ev, "total_malicious": tp_ev+fn_ev},
    "time_seconds": round(elapsed, 1),
    "total_tokens": total_tokens,
    "result_text": str(result)[:2000],
}
with open(REPORT_PATH, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f"\n{'='*60}")
print(f"ProVSeek on {DATASET.upper()}")
print(f"  Entity: TP={len(tp)} FP={len(fp)} FN={len(fn)} P={prec:.4f} R={rec:.4f} F1={f1:.4f}")
print(f"  Event:  TP={tp_ev} FP={fp_ev} FN={fn_ev} TPR={ev_tpr:.4f} FPR={ev_fpr:.5f}")
print(f"  Time: {elapsed:.1f}s  Tokens: {total_tokens}")
print(f"  TP: {sorted(tp)}")
print(f"  FP: {sorted(fp)[:10]}")
print(f"  FN: {sorted(fn)}")
print(f"  -> {REPORT_PATH}")
