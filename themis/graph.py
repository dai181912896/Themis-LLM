import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, List, Optional

from supplementary.normalize import entity_match, normalize_entity, _basename

from .logs import chunk_list


@dataclass
class Triple:
    subject: str = ""
    action: str = ""
    object: str = ""
    raw: str = ""
    edge_id: str = ""
    timestamp: str = ""


def parse_triple(line: str) -> Triple:
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
    idx = defaultdict(list)
    for t in triples:
        if t.subject:
            idx[normalize_entity(t.subject)].append(t)
        if t.object:
            idx[normalize_entity(t.object)].append(t)
    return dict(idx)


def get_incident_edges(entity: str, triples: List[Triple], mode: str = "relaxed") -> List[Triple]:
    out = []
    for t in triples:
        if (t.subject and entity_match(entity, t.subject, mode).matched) or \
           (t.object and entity_match(entity, t.object, mode).matched):
            out.append(t)
    return out


def is_connected_subgraph(triples: Iterable[Triple]) -> bool:
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


_HUBS = {"cmd", "powershell", "wscript", "cscript", "mshta", "wmic",
         "rundll32", "explorer", "powershell_ise"}
_HUB_GENERIC = {"wordpad", "conhost", "calc", "dwellm", "searchindexer",
                "searchfilterhost", "searchprotocolhost", "runtimebroker",
                "sihost", "taskhost", "taskhostw", "csrss", "lsass", "wininit",
                "winlogon", "smss", "services", "spoolsv", "audiodg", "dwm",
                "fontdrvhost", "dllhost", "system", "idle"}


def _is_noise_entity(entity):
    return False


def _is_noise_edge(line):
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
    r"_mei\d+[/\\]"
    r"|appdata/local/temp/[^/\s]*\.(pyd|dll)\b"
    r"|__psscriptpolicytest_[^/\s]*\.(ps1|psm1)\b"
    r"|appdata/local/temp/[^/\s]*\.(cs|cmdline|out)\b",
    re.IGNORECASE)


def _cap_selfextract(lines, max_keep=8):
    keep, se = [], []
    for k in lines:
        if _SELFEXTRACT_RE.search(k):
            se.append(k)
        else:
            keep.append(k)
    return keep + se[:max_keep]


def _hub_children_lines(entity, logs, mode="relaxed", cap=30):
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
    if os.environ.get("THEMIS_GRAPH_MODE") == "1":
        try:
            mode = os.environ.get("THEMIS_MATCH_MODE", "relaxed")
            trace_path = os.environ.get("THEMIS_TRACE_PATH") or None
            kept = [k.rstrip("\n") for k in get_neighbor_lines(entity, logs, mode=mode, trace_path=trace_path)]
            if os.environ.get("THEMIS_HUB_EXPANSION") == "1":
                kept += _hub_children_lines(entity, logs, mode)
            if os.environ.get("THEMIS_FILTER_SYSDLL") == "1":
                kept = [k for k in kept if not _is_noise_edge(k)]
            if os.environ.get("THEMIS_CAP_SELFEXTRACT") == "1":
                kept = _cap_selfextract(kept)
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
