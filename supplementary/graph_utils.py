"""Triple parsing + provenance adjacency (graph mode). NO substring.

parse_triple supports both:
  - ATLAS space format:  "subj action obj"
  - NODLINK TSV format:  "subj\taction\tobj\tts\tedge_id"
"""
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, List, Optional

from .normalize import entity_match, normalize_entity


@dataclass
class Triple:
    subject: str = ""
    action: str = ""
    object: str = ""
    raw: str = ""
    edge_id: str = ""
    timestamp: str = ""


def parse_triple(line: str) -> Triple:
    """Parse one log line into a Triple. Returns empty Triple for headers/garbage."""
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
