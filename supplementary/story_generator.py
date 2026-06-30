"""Attack Story Generation Module (Paper §4.4).

Transforms per-iteration reasoning outputs [A(1),...,A(T)] from the reasoning
cache into a coherent, analyst-ready investigation report using the Pgen prompt.

G = LLM([A(1),...,A(T)], H(T), Pgen)

Usage:
  python story_generator.py --cache <reasoning_cache.jsonl> --out <report.md>
  python story_generator.py --cache <reasoning_cache.jsonl> --out <report.md> --kill-chain <kb.json>
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

PGEN_PROMPT = """You are a senior security analyst writing a formal attack investigation report.

You are given a series of reasoning steps from an automated attack investigation system.
Each step contains detected malicious entities, attack behaviors, and evidence from system logs.
Your task is to synthesize ALL steps into a SINGLE coherent, analyst-ready investigation report.

Requirements:
1. Chronological Ordering: Present events in temporal/causal order, from initial access to final objectives.
2. Causal Linking: Explicitly connect each step to the next (e.g., "This led to..." "Following the initial compromise...").
3. Kill Chain Alignment: Label each major phase with its Kill Chain stage (Reconnaissance, Delivery, Exploitation, Installation, C2, Actions on Objectives).
4. Analyst-Readable: Use clear, professional language. Avoid raw log dumps. Summarize behavior, cite key entities.
5. Completeness: Include ALL detected entities (processes, files, IPs) and ALL attack behaviors from the reasoning steps.

Output format:
```
# Attack Investigation Report

## Executive Summary
<2-3 sentence overview of the attack>

## Kill Chain Reconstruction

### Phase 1: <Kill Chain Phase Name>
**Timeline**: <approximate>
**Key Entities**: <list>
**Behavior**: <detailed description>
**Evidence**: <key log evidence>

### Phase 2: ...

## Detected Malicious Entities
| Type | Entity | Phase | Evidence |
|------|--------|-------|----------|
| Process | ... | ... | ... |
| File | ... | ... | ... |
| IP | ... | ... | ... |

## Attack Chain Summary
<1 paragraph narrative connecting all phases>
```

--- REASONING STEPS ---

{reasoning_steps}

--- LATEST SUMMARY (H(T)) ---
{latest_summary}

{kill_chain_context}

Generate the complete report now."""


def load_reasoning_cache(cache_path):
    """Load reasoning_cache.jsonl into a list of per-iteration outputs."""
    entries = []
    with open(cache_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def format_reasoning_steps(entries):
    """Format reasoning cache entries into readable text for the Pgen prompt."""
    blocks = []
    for i, entry in enumerate(entries):
        entities = entry.get("detected_suspicious_entities", [])
        attack_process = entry.get("attack_process", [])
        summary = entry.get("summary", "")
        lines = [f"### Step {i+1}"]
        if entities:
            lines.append(f"Detected Entities: {', '.join(entities)}")
        if summary:
            lines.append(f"Summary: {summary}")
        for j, step in enumerate(attack_process):
            action = step.get("action", "")
            desc = step.get("description", "")
            seq = step.get("sequences", "")
            lines.append(f"  [{j+1}] {action}")
            if desc:
                lines.append(f"      Behavior: {desc}")
            if seq:
                lines.append(f"      Evidence: {seq[:200]}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def load_kill_chain_context(kb_path):
    """Load Kill Chain KB and format phase descriptions for the prompt."""
    if not kb_path or not os.path.exists(kb_path):
        return ""
    try:
        kb = json.load(open(kb_path, encoding="utf-8"))
        units = kb.get("knowledge_units", kb) if isinstance(kb, dict) else kb
        phases = []
        for u in units[:10]:
            phase = u.get("phase", u.get("phase_type", ""))
            behavior = u.get("behavior", u.get("phase_description", ""))
            entities = u.get("entities", u.get("core_entities", ""))
            if isinstance(entities, list):
                entities = ", ".join(entities)
            phases.append(f"- {phase}: {behavior} (Entities: {entities})")
        if phases:
            return "--- KILL CHAIN KNOWLEDGE BASE CONTEXT ---\n" + "\n".join(phases)
    except Exception:
        pass
    return ""


def generate_story(cache_path, output_path, kb_path=None):
    """Full pipeline: load cache -> format -> LLM(Pgen) -> output report."""
    os.environ.setdefault("ARK_API_KEY", "os.getenv("ARK_API_KEY", "")")
    os.environ.setdefault("ARK_BASE_URL", "https://ark.cn-beijing.volces.com/api/coding/v3")
    os.environ.setdefault("ARK_MODEL", "ark-code-latest")

    from wrap_tencent_LLM_API import get_answer

    print(f"[StoryGen] Loading reasoning cache: {cache_path}")
    entries = load_reasoning_cache(cache_path)
    print(f"[StoryGen] {len(entries)} reasoning steps loaded")

    if not entries:
        entries = [{"detected_suspicious_entities": [], "attack_process": [],
                     "summary": "No investigation data available."}]

    reasoning_text = format_reasoning_steps(entries)
    latest_summary = entries[-1].get("summary", "") if entries else ""
    kc_context = load_kill_chain_context(kb_path)

    prompt = PGEN_PROMPT.format(
        reasoning_steps=reasoning_text,
        latest_summary=latest_summary,
        kill_chain_context=kc_context,
    )

    print(f"[StoryGen] Calling LLM with Pgen prompt ({len(prompt)} chars)...")
    reasoning, answer, stats = get_answer(prompt, "deepseek-ai/DeepSeek-R1")
    tokens = stats.get("tokens", {}).get("total", 0)

    if not answer.strip().startswith("#"):
        answer = f"# Attack Investigation Report\n\n{answer}"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(answer)

    all_entities = set()
    for entry in entries:
        all_entities.update(entry.get("detected_suspicious_entities", []))

    meta = {
        "method": "Themis_Story_Generation",
        "input_cache": cache_path,
        "steps": len(entries),
        "all_detected_entities": sorted(all_entities),
        "total_tokens": tokens,
        "output_file": output_path,
    }
    meta_path = output_path.rsplit(".", 1)[0] + "_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"\n[StoryGen] Report generated: {len(answer)} chars, {tokens} tokens")
    print(f"  {len(all_entities)} unique entities across {len(entries)} steps")
    print(f"  -> {output_path}")
    print(f"  -> {meta_path}")
    return answer


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Attack Story Generation (Paper §4.4)")
    ap.add_argument("--cache", required=True, help="reasoning_cache.jsonl from investigation")
    ap.add_argument("--out", required=True, help="Output report file (.md)")
    ap.add_argument("--kill-chain", default=None, help="Optional Kill Chain KB JSON for context")
    a = ap.parse_args()
    generate_story(a.cache, a.out, a.kill_chain)
