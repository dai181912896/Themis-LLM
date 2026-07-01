"""Batch pre-filter applied to each chunk at fetch time (Stage 2 optimization).

Drops redundant/benign lines before they reach the LLM:

  1. ``dedup_chunk`` — exact-duplicate lines within the chunk (hardcoded rule).
  2. ``is_cache_io`` — read/write of cache files (browser cache, registry hives,
     NTFS metadata, prefetch, .tmp) via fuzzy regex (``config.CACHE_IO_SEED``).
  3. learned patterns from ``rules.json`` (discovered by the runtime analyzer).

A line whose subject or object basename is a currently-detected entity is
**never** dropped by cache-I/O or learned patterns (only dedup applies) — this
protects IoCs (certutil, mimikatz, calc, ...) that might touch a cache-ish path.
"""
import re

from supplementary.normalize import normalize_entity, _basename
from .config import CACHE_IO_SEED, dedup_enabled, filter_cache_io_enabled
from .graph import parse_triple
from .rules import pattern_matches

_CACHE_IO_COMPILED = [re.compile(rx, re.IGNORECASE) for rx in CACHE_IO_SEED]


def dedup_chunk(chunk):
    """Drop exact-duplicate lines within the chunk, preserving order."""
    seen, out = set(), []
    for line in chunk:
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def is_cache_io(line):
    """True for read/write of a cache-file object path (fuzzy, hardcoded seed)."""
    t = parse_triple(line)
    if t.action not in ("read", "write") or not t.object:
        return False
    obj = normalize_entity(t.object)
    return any(rx.search(obj) for rx in _CACHE_IO_COMPILED)


def filter_chunk(chunk, learned_rules=None, protected_basenames=None,
                 enable_dedup=None, enable_cache=None):
    """Apply dedup + cache-I/O + learned-rule filtering to a chunk.

    Returns ``(kept_lines, stats)`` where stats counts dropped lines by reason.
    Detected entities (``protected_basenames``) are never dropped by cache-I/O
    or learned patterns — only dedup applies to them.
    """
    if enable_dedup is None:
        enable_dedup = dedup_enabled()
    if enable_cache is None:
        enable_cache = filter_cache_io_enabled()

    protected = protected_basenames or set()
    learned_rules = learned_rules or []

    n_in = len(chunk)
    deduped = chunk
    if enable_dedup:
        deduped = dedup_chunk(chunk)

    kept, cache_io, learned = [], 0, 0
    for line in deduped:
        t = parse_triple(line)
        subj_b = _basename(t.subject) if t.subject else ""
        obj_b = _basename(t.object) if t.object else ""
        is_protected = subj_b in protected or obj_b in protected

        if not is_protected and enable_cache and is_cache_io(line):
            cache_io += 1
            continue
        if not is_protected and learned_rules:
            obj_n = normalize_entity(t.object) if t.object else ""
            if any(pattern_matches(r, t.action, obj_n) for r in learned_rules):
                learned += 1
                continue
        kept.append(line)

    total_dropped = n_in - len(kept)
    stats = {
        "input": n_in, "kept": len(kept),
        "deduped": n_in - len(deduped), "cache_io": cache_io,
        "learned": learned, "total_dropped": total_dropped,
    }
    return kept, stats
