"""Provenance graph: triple parsing, adjacency, and adjacency-prioritized
neighbor expansion (Stage 2 of the pipeline).

NO substring matching — adjacency is always on parsed subject/object via
``supplementary.normalize.entity_match``. Hub-aware expansion surfaces a
dispatcher's sibling fork-children so the investigator can reach payloads
behind cmd/powershell, and self-extraction noise is capped so attack signal
isn't crowded out.

Imports ``chunk_list`` from ``themis.logs``; ``themis.logs.line_mentions_entity``
imports this module lazily, so there is no import-time cycle.
"""
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, List, Optional

from supplementary.normalize import entity_match, normalize_entity, _basename

from .logs import chunk_list


# --------------------------------------------------------------------------
# Triple parsing + adjacency (was supplementary/graph_utils.py)
# --------------------------------------------------------------------------
@dataclass
class Triple:
    subject: str = ""
    action: str = ""
    object: str = ""
    raw: str = ""
    edge_id: str = ""
    timestamp: str = ""


def parse_triple(line: str) -> Triple:
    """Parse one log line into a Triple. Returns empty Triple for headers/garbage.

    Supports both:
      - ATLAS space format:  "subj action obj"
      - NODLINK TSV format:  "subj\\taction\\tobj\\tts\\tedge_id"
    """
    s = "" if line is None else str(line).strip()
    if not s:
        return Triple()
    if s.startswith("[") or s.startswith("#"):
        return Triple(raw=s)

    if "\t" in s:
        cols = [c for c in s.split("\t") if c != ""]
        if len(cols) < 3:
            return Triple(raw=s)
        t = Triple(subject=cols[0], action=cols[1], object=cols[2], raw=s)
        if len(cols) > 3:
            t.timestamp = cols[3]
        if len(cols) > 4:
            t.edge_id = cols[4]
        return t

    parts = s.split()
    if len(parts) < 3:
        return Triple(raw=s)
    return Triple(subject=parts[0], action=parts[1],
                  object=" ".join(parts[2:]), raw=s)


def build_adjacency(triples: Iterable[Triple]) -> dict:
    """normalized(entity) -> list[Triple] incident (as subject or object)."""
    idx = defaultdict(list)
    for t in triples:
        if t.subject:
            idx[normalize_entity(t.subject)].append(t)
        if t.object:
            idx[normalize_entity(t.object)].append(t)
    return dict(idx)


def get_incident_edges(entity: str, triples: List[Triple], mode: str = "relaxed") -> List[Triple]:
    """All triples whose subject OR object matches entity (no substring)."""
    out = []
    for t in triples:
        if (t.subject and entity_match(entity, t.subject, mode).matched) or \
           (t.object and entity_match(entity, t.object, mode).matched):
            out.append(t)
    return out


def is_connected_subgraph(triples: Iterable[Triple]) -> bool:
    """True iff endpoints of these triples form a single connected component."""
    edges = [t for t in triples if t.subject and t.object]
    if not edges:
        return True
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    nodes = set()
    for t in edges:
        s, o = normalize_entity(t.subject), normalize_entity(t.object)
        nodes.add(s); nodes.add(o)
        union(s, o)
    return len({find(n) for n in nodes}) == 1


def get_neighbor_lines(entity: str, lines: Iterable[str], mode: str = "relaxed",
                       trace_path: Optional[str] = None, round_no: Optional[int] = None) -> List[str]:
    """Graph-mode neighbor extraction: keep lines whose parsed subject/object matches entity.

    Appends one JSON record per kept line to trace_path (if set), for audit.
    """
    kept: List[str] = []
    trace: List[dict] = []
    for line in lines:
        t = parse_triple(line)
        if not t.subject and not t.object:
            continue
        mr_s = entity_match(entity, t.subject, mode) if t.subject else None
        mr_o = entity_match(entity, t.object, mode) if t.object else None
        if (mr_s and mr_s.matched) or (mr_o and mr_o.matched):
            kept.append(line if line.endswith("\n") else line + "\n")
            side, mr = ("subject", mr_s) if (mr_s and mr_s.matched) else ("object", mr_o)
            trace.append({
                "round": round_no,
                "query_entity": entity,
                "subject": t.subject,
                "action": t.action,
                "object": t.object,
                "match_side": side,
                "match_policy": mr.policy,
                "match_reason": mr.reason,
                "edge_id": t.edge_id,
            })
    if trace_path and trace:
        with open(trace_path, "a", encoding="utf-8") as f:
            for rec in trace:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return kept


# --------------------------------------------------------------------------
# Expansion: hub-aware neighbor discovery + noise filtering (was utils.py)
# --------------------------------------------------------------------------
_HUBS = {"cmd", "powershell", "wscript", "cscript", "mshta", "wmic",
         "rundll32", "explorer", "powershell_ise"}
_HUB_GENERIC = {"wordpad", "conhost", "calc", "dwellm", "searchindexer",
                "searchfilterhost", "searchprotocolhost", "runtimebroker",
                "sihost", "taskhost", "taskhostw", "csrss", "lsass", "wininit",
                "winlogon", "smss", "services", "spoolsv", "audiodg", "dwm",
                "fontdrvhost", "dllhost", "system", "idle"}


def _is_noise_entity(entity):
    """Stub — noise filtering is done POST-HOC during evaluation, not during BFS.
    This exists so the FILTER_NOISE block and the investigation loop import cleanly."""
    return False


def _is_noise_edge(line):
    """Filter universal startup noise: system DLL/image loads, prefetch.
    (action=load of system32/syswow64 .dll/.pyd/.sys — every process does this.)"""
    t = parse_triple(line)
    if t.action == "load":
        o = t.object.lower()
        if ("system32" in o or "syswow64" in o or "/windows/" in o) and \
           o.endswith((".dll", ".pyd", ".sys", ".cpl", ".tsp", ".drv")):
            return True
        if "prefetch" in o:
            return True
    return False


_SELFEXTRACT_RE = re.compile(
    r"_mei\d+[/\\]"                                       # PyInstaller self-extract
    r"|appdata/local/temp/[^/\s]*\.(pyd|dll)\b"           # temp pyd/dll
    r"|__psscriptpolicytest_[^/\s]*\.(ps1|psm1)\b"        # PowerShell policy-test noise (NOT real payloads like invoke-mimikatz.ps1 which live in desktop/shell/)
    r"|appdata/local/temp/[^/\s]*\.(cs|cmdline|out)\b",   # .NET/PowerShell compiled temp artifacts
    re.IGNORECASE)


def _cap_selfextract(lines, max_keep=8):
    """Cap PyInstaller self-extraction artifacts (_mei<N>/* temp .pyd/.dll) so
    they don't crowd out sibling-tool discovery. Keeps ALL non-self-extract lines
    + up to max_keep self-extract lines. lazagne1 itself is still detected, so its
    (legitimate-TP) PyInstaller events still count — this only limits how many
    such lines the LLM sees per expansion."""
    keep, se = [], []
    for k in lines:
        if _SELFEXTRACT_RE.search(k):
            se.append(k)
        else:
            keep.append(k)
    return keep + se[:max_keep]


def _hub_children_lines(entity, logs, mode="relaxed", cap=30):
    """Hub-aware expansion: if `entity` is a CHILD of a dispatcher hub
    (cmd/powershell/...), return the hub's OTHER fork-children lines so the
    investigator sees sibling tools (e.g. certutil <- cmd -> mimikatz2).
    Uses graph structure only (no labels); generic-benign children filtered.
    """
    hubs = set()
    for line in logs:
        t = parse_triple(line)
        if t.action in ("fork", "execute", "create", "start") and \
           entity_match(entity, t.object, mode).matched and _basename(t.subject) in _HUBS:
            hubs.add(t.subject)
    if not hubs:
        return []
    out, seen, children = [], set(), set()
    for line in logs:
        t = parse_triple(line)
        if t.action in ("fork", "execute", "create", "start") and t.subject in hubs:
            cb = _basename(t.object)
            if cb in _HUB_GENERIC or cb in seen or len(seen) >= cap:
                continue
            seen.add(cb)
            children.add(t.object)
            out.append(line.rstrip("\n"))
    # Child-action evidence: also append each sibling's top-K action edges
    # (execute/read/write/connect, system-noise filtered) so the LLM sees WHAT
    # each sibling does (e.g. 'powershell read invoke-mimikatz.ps1', 'calc
    # write X') and can emit it -> iterative expansion reaches the payload.
    # Targeted (only hub siblings' actions), not broad.
    if os.environ.get("THEMIS_HUB_CHILD_ACTIONS") == "1":
        _prio = {"fork": 5, "execute": 5, "start": 5, "connect": 4,
                 "write": 4, "read": 1, "load": 2}
        for child in children:
            cand = []
            for line in logs:
                t = parse_triple(line)
                if t.subject == child and t.action in ("execute", "read", "write", "connect"):
                    if _is_noise_edge(line):
                        continue
                    cand.append((_prio.get(t.action, 0), line.rstrip("\n")))
            cand.sort(key=lambda x: -x[0])
            for _, l in cand[:3]:
                if l not in out:
                    out.append(l)
    return out


def get_neighbor_entity_sequences(entity, logs):
    """Neighbor extraction.

    Graph mode (THEMIS_GRAPH_MODE=1) matches PARSED subject/object — NEVER
    substring. Also applies hub-aware expansion, system-DLL-load filtering,
    and self-extraction capping when the corresponding env flags are set.
    Legacy substring path kept so previously reported numbers stay reproducible.
    """
    if os.environ.get("THEMIS_GRAPH_MODE") == "1":
        try:
            mode = os.environ.get("THEMIS_MATCH_MODE", "relaxed")
            trace_path = os.environ.get("THEMIS_TRACE_PATH") or None
            kept = [k.rstrip("\n") for k in get_neighbor_lines(entity, logs, mode=mode, trace_path=trace_path)]
            # Hub-aware expansion: if entity is a child of a dispatcher hub,
            # also pull the hub's other children (sibling attack tools).
            if os.environ.get("THEMIS_HUB_EXPANSION") == "1":
                kept += _hub_children_lines(entity, logs, mode)
            # Filter universal system-DLL-load noise so attack signal is visible.
            if os.environ.get("THEMIS_FILTER_SYSDLL") == "1":
                kept = [k for k in kept if not _is_noise_edge(k)]
            # Cap PyInstaller self-extraction artifacts so sibling tools get budget.
            if os.environ.get("THEMIS_CAP_SELFEXTRACT") == "1":
                kept = _cap_selfextract(kept)
            # Filter noise entities (.NET temp dirs, random temp files, system profiles)
            # to keep LLM context tight. Does NOT filter ground-truth IoCs (certutil,
            # mimikatz, calc, procdump etc. don't match noise patterns).
            if os.environ.get("THEMIS_FILTER_NOISE") == "1":
                kept = [k for k in kept
                        if not (_is_noise_entity(parse_triple(k).subject) and
                                _is_noise_entity(parse_triple(k).object))]
            return chunk_list(kept)
        except Exception as e:
            print("[graph_mode] fallback to legacy:", e)
    results_sequences = []
    for line in logs:
        if entity.lower() in line.lower().strip():
            results_sequences.append(line)
    return chunk_list(results_sequences)
