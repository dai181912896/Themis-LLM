"""Kill-Chain Knowledge Base Annotation Module (Paper §4.1b).

Implements the phase-aware Kill Chain annotation described in the paper:
  1. Malicious Events Extraction: filter raw logs by rel(l, Emal)
  2. Phase-Aware Kill Chain Annotation: LLM(Pkill) annotates each event
     segment with phase/behavior/entities/neighbors metadata
  3. Output: annotated sequences ready for embedding + KB insertion

Usage:
  python kill_chain_annotator.py --log <triples_file> --entities <emal.json> --out <kb.json>
"""
import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXP = os.path.abspath(os.path.join(_HERE, ".."))
if _EXP not in sys.path:
    sys.path.insert(0, _EXP)

KILL_CHAIN_PHASES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command and Control (C2)", "Actions on Objectives"
]

PKILL_PROMPT = """You are a cybersecurity threat intelligence expert specializing in the Cyber Kill Chain framework.
You are given a sequence of system audit events from a known attack scenario. Your task is to:

1. Identify which Kill Chain phase this event sequence belongs to. Choose from:
   {phases}

2. Generate structured metadata for this sequence in the following JSON format:
   {{
     "phase": "<Kill Chain phase name>",
     "behavior": "<concise natural-language summary of the attack behavior in this phase>",
     "entities": ["<malicious entity 1>", "<malicious entity 2>", ...],
     "benign_entities": ["<benign entity involved but not malicious>", ...],
     "neighbors_prior": "<brief description of what likely happened in the PRECEDING phase, or 'Initial phase' if this is the first>",
     "neighbors_next": "<brief prediction of what likely happens in the SUBSEQUENT phase, or 'Final phase' if this is the last>"
   }}

Guidelines:
- Phase: infer from the attack behavior (e.g., process execution -> Exploitation; C2 connection -> Command and Control).
- Behavior: describe WHAT the attacker is doing in human-readable form.
- Entities: list ALL malicious entities in this sequence (processes, files, IPs, domains).
- Benign entities: list system processes/files that are involved but NOT malicious.
- Neighbors: link to adjacent phases to maintain causal continuity across the attack chain.

Malicious entities (Emal) for this scenario: {emal}

Event sequence (temporally ordered):
{sequence}

Output ONLY the JSON object, no other text."""


def extract_malicious_events(logs, emal_set):
    """T = {l in L | rel(l, Emal) = 1}. Keep events related to malicious entities."""
    trace = []
    for line in logs:
        parts = line.strip().split("\t") if "\t" in line else line.strip().split()
        if len(parts) < 3:
            continue
        subj, action, obj = parts[0], parts[1], " ".join(parts[2:])
        sl, ol = subj.lower(), obj.lower()
        is_relevant = any(
            me.lower() in sl or me.lower() in ol
            or sl in me.lower() or ol in me.lower()
            for me in emal_set
        )
        if is_relevant:
            trace.append({"subject": subj, "action": action, "object": obj})
    return trace


def segment_events(trace, chunk_size=20):
    """Split malicious trace into subsequences of <=N events (paper §4.1 N=20)."""
    return [trace[i:i + chunk_size] for i in range(0, len(trace), chunk_size)]


def annotate_segment(segment, emal_list, get_answer_fn):
    """Call LLM with Pkill prompt to annotate one event segment."""
    seq_text = "\n".join(
        f"  [{i+1}] {e['subject']} {e['action']} {e['object']}"
        for i, e in enumerate(segment)
    )
    prompt = PKILL_PROMPT.format(
        phases="\n   ".join(KILL_CHAIN_PHASES),
        emal=", ".join(emal_list),
        sequence=seq_text,
    )
    reasoning, answer, stats = get_answer_fn(prompt, "deepseek-ai/DeepSeek-R1")
    try:
        m = re.search(r'\{[^{}]+\}', answer, re.DOTALL)
        annotation = json.loads(m.group()) if m else {
            "phase": "Unknown", "behavior": answer[:200],
            "entities": [], "benign_entities": [],
            "neighbors_prior": "", "neighbors_next": ""}
    except json.JSONDecodeError:
        annotation = {"phase": "Unknown", "behavior": answer[:200],
                      "entities": [], "benign_entities": [],
                      "neighbors_prior": "", "neighbors_next": ""}
    annotation["sequence"] = segment
    annotation["evidence_set"] = ", ".join(
        f"{e['subject']} {e['action']} {e['object']}" for e in segment[:10])
    annotation["core_entities"] = ", ".join(annotation.get("entities", []))
    annotation["phase_type"] = annotation.get("phase", "Unknown")
    annotation["phase_description"] = annotation.get("behavior", "")
    return annotation, stats


def build_kill_chain_kb(log_file, emal_file, output_file, chunk_size=20):
    """Full pipeline: extract -> segment -> annotate -> output KB."""
    os.environ.setdefault("ARK_API_KEY", "os.getenv("ARK_API_KEY", "")")
    os.environ.setdefault("ARK_BASE_URL", "https://ark.cn-beijing.volces.com/api/coding/v3")
    os.environ.setdefault("ARK_MODEL", "ark-code-latest")

    from wrap_tencent_LLM_API import get_answer

    print(f"[KillChain-KB] Loading logs: {log_file}")
    with open(log_file, encoding="utf-8", errors="replace") as f:
        logs = [l.strip() for l in f if l.strip()]
    if logs and logs[0].startswith("["):
        logs = logs[2:]  # skip NODLINK header

    with open(emal_file, encoding="utf-8") as f:
        emal_data = json.load(f)
    emal_list = emal_data.get("malicious_entities", emal_data.get("iocs", []))

    print(f"[KillChain-KB] {len(logs)} logs, {len(emal_list)} malicious entities")

    trace = extract_malicious_events(logs, set(emal_list))
    print(f"[KillChain-KB] Extracted {len(trace)} malicious events")

    segments = segment_events(trace, chunk_size)
    print(f"[KillChain-KB] {len(segments)} segments (max {chunk_size} events each)")

    kb_units, total_tokens = [], 0
    for i, seg in enumerate(segments):
        print(f"  [{i+1}/{len(segments)}] Annotating {len(seg)} events...")
        ann, stats = annotate_segment(seg, emal_list, get_answer)
        kb_units.append(ann)
        total_tokens += stats.get("tokens", {}).get("total", 0)

    output = {
        "method": "Themis_KillChain_KB_Annotation",
        "source_log": log_file,
        "malicious_entities": emal_list,
        "total_logs": len(logs),
        "total_malicious_events": len(trace),
        "total_segments": len(segments),
        "total_tokens": total_tokens,
        "knowledge_units": kb_units,
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    phase_dist = {}
    for u in kb_units:
        p = u.get("phase", "Unknown")
        phase_dist[p] = phase_dist.get(p, 0) + 1
    print(f"\n[KillChain-KB] Done: {len(kb_units)} units, {total_tokens} tokens")
    print(f"  Phase distribution: {phase_dist}")
    print(f"  -> {output_file}")

    # Also export NDJSON for VDB_data_utils::process_and_insert (Paper §4.1 step 3 wiring)
    ndjson_file = output_file.rsplit(".", 1)[0] + ".ndjson"
    with open(ndjson_file, "w", encoding="utf-8") as f:
        for i, u in enumerate(kb_units):
            entry = {"attack_timeline": [{
                "phase_type": u.get("phase_type", u.get("phase", "")),
                "core_entities": u.get("core_entities", ""),
                "evidence_set": u.get("evidence_set", ""),
                "phase_description": u.get("phase_description", u.get("behavior", "")),
                "entity_actions": "",
                "neighbors_prior": u.get("neighbors_prior", ""),
                "neighbors_next": u.get("neighbors_next", ""),
                "chunk_index": str(i),
            }], "attack_sc": "auto"}
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"  -> {ndjson_file} (NDJSON for VDB_data_utils)")
    return output


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Kill-Chain Knowledge Base Annotation")
    ap.add_argument("--log", required=True, help="Raw triples file (subject action object)")
    ap.add_argument("--entities", required=True, help="JSON with malicious entities")
    ap.add_argument("--out", required=True, help="Output KB JSON file")
    ap.add_argument("--chunk-size", type=int, default=20)
    a = ap.parse_args()
    build_kill_chain_kb(a.log, a.entities, a.out, a.chunk_size)
