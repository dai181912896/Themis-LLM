import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

_LOCK = threading.Lock()
_COMPILED_CACHE = {}


@dataclass
class Pattern:
    regex: str
    action: str
    reason: str = ""
    source: str = "analyzer"
    compiled: re.Pattern = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path, data):
    d = os.path.dirname(os.path.abspath(path)) or "."
    tmp = os.path.join(d, f".{os.path.basename(path)}.{threading.get_ident()}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _actions(spec: str) -> set:
    if not spec or spec == "*":
        return {"*"}
    return {a.strip() for a in spec.split("|") if a.strip()}


def load_rules(path):
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return []
    cached = _COMPILED_CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for p in data.get("patterns", []):
        rx = p.get("regex")
        if not rx:
            continue
        try:
            compiled = re.compile(rx, re.IGNORECASE)
        except re.error:
            continue
        out.append(Pattern(
            regex=rx,
            action=p.get("action", "*"),
            reason=p.get("reason", ""),
            source=p.get("source", "analyzer"),
            compiled=compiled,
        ))
    _COMPILED_CACHE[path] = (mtime, out)
    return out


def add_patterns(path, patterns, source="analyzer"):
    with _LOCK:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            data = {"version": 1, "patterns": [], "stats": {}}
        existing = {p["regex"] for p in data.get("patterns", [])}
        now = _now()
        added = 0
        for p in patterns:
            rx = p.get("regex")
            if not rx or rx in existing:
                continue
            existing.add(rx)
            data.setdefault("patterns", []).append({
                "regex": rx,
                "action": p.get("action", "*"),
                "reason": p.get("reason", ""),
                "source": source,
                "added_utc": now,
            })
            added += 1
        if added:
            data["updated_utc"] = now
            stats = data.setdefault("stats", {})
            stats["learned"] = stats.get("learned", 0) + added
            _atomic_write(path, data)
            _COMPILED_CACHE.pop(path, None)
        return added


def pattern_matches(pattern: Pattern, action: str, norm_object: str) -> bool:
    if not pattern.compiled or not norm_object:
        return False
    if "*" not in _actions(pattern.action) and action not in _actions(pattern.action):
        return False
    return bool(pattern.compiled.search(norm_object))
