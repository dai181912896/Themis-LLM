"""Persisted noise-rule store (learned by the runtime analyzer).

``rules.json`` holds patterns the parallel noise analyzer discovers during an
investigation and persists across runs. The pre-filter (``themis.prefilter``)
reads this file each batch; the analyzer (``themis.noise_analyzer``) appends to
it. Writes are thread-safe and atomic (temp + ``os.replace``) so a concurrent
reader never sees a partial file.

Schema::

    {
      "version": 1,
      "updated_utc": "2026-07-01T12:00:00+00:00",
      "patterns": [
        {"regex": "appdata/local/[^/]+/cache", "action": "read",
         "reason": "browser cache hit", "source": "analyzer",
         "added_utc": "..."}
      ],
      "stats": {"learned": 3}
    }

A missing or corrupt file is treated as no rules (``[]``) — never raises.
"""
import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

_LOCK = threading.Lock()
_COMPILED_CACHE = {}  # path -> (mtime, [Pattern])


@dataclass
class Pattern:
    regex: str
    action: str            # "read" | "write" | "load" | "connect" | "*" (or "read|write")
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
    """Expand an action spec like 'read|write' or '*' into a set of actions."""
    if not spec or spec == "*":
        return {"*"}
    return {a.strip() for a in spec.split("|") if a.strip()}


def load_rules(path):
    """Return list[Pattern] (compiled), cached by file mtime. [] if missing/corrupt."""
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
    """Append new patterns (dedup by regex), atomic write. Returns count added.

    ``patterns`` is an iterable of dicts with keys ``regex`` (required),
    ``action`` (default "*"), ``reason`` (default ""). Thread-safe.
    """
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
            _COMPILED_CACHE.pop(path, None)  # invalidate so next load recompiles
        return added


def pattern_matches(pattern: Pattern, action: str, norm_object: str) -> bool:
    """True if ``pattern`` applies to a triple with the given action + object."""
    if not pattern.compiled or not norm_object:
        return False
    if "*" not in _actions(pattern.action) and action not in _actions(pattern.action):
        return False
    return bool(pattern.compiled.search(norm_object))
