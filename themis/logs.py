"""Log loading, slicing, and JSON parsing helpers.

Pure data utilities with no graph/LLM imports at module top (the graph-mode
branch of ``line_mentions_entity`` imports lazily to avoid an import cycle with
``themis.graph``, which imports ``chunk_list`` from here).
"""
import json
import os
import re


def chunk_list(lst, n=20):
    """Split list into chunks of n elements."""
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def slice_logs(text, N):
    logs = text
    total_slices = len(logs) // N + (1 if len(logs) % N != 0 else 0)
    slices = [logs[i:i + N] for i in range(0, len(logs), N)]
    return slices, total_slices


def load_host_logs(log_file_path):
    """Load host logs from file. Returns list of triple lines (skipping 2-line header)."""
    with open(log_file_path, 'r', encoding='utf-8') as f:
        logs = [line.strip() for line in f if line.strip()]
        logs = logs[2:]  # first line includes entity list header
        return logs


def line_mentions_entity(entity, line, mode=None):
    """Graph-mode aware 'does this line mention entity as subject/object?'.

    THEMIS_GRAPH_MODE=1 -> parse_triple + subject/object entity_match (NO substring).
    else -> legacy substring (``entity in line``), preserved so prior numbers
    stay reproducible.
    """
    if os.environ.get("THEMIS_GRAPH_MODE") == "1":
        # Lazy import: themis.graph imports chunk_list from this module.
        from themis.graph import parse_triple
        from supplementary.normalize import entity_match
        m = mode or os.environ.get("THEMIS_MATCH_MODE", "relaxed")
        t = parse_triple(line)
        if not t.subject and not t.object:
            return False
        return ((bool(t.subject) and entity_match(entity, t.subject, m).matched) or
                (bool(t.object) and entity_match(entity, t.object, m).matched))
    return entity in line


def find_first_attack_logs(logs, alert_entity):
    """Find the first occurrence of alert_entity in logs and extract context around it."""
    malicious_index = None
    for idx, line in enumerate(logs):
        if line_mentions_entity(alert_entity, line):
            malicious_index = idx
            break

    if malicious_index is None:
        print("Alert entity not found in logs.")
        return

    backward_chain = []
    for i in range(malicious_index, -1, -1):
        backward_chain.append(logs[i])

    forward_chain = []
    for i in range(malicious_index, len(logs)):
        forward_chain.append(logs[i])

    return backward_chain, forward_chain


def parse_text2json(text: str):
    pattern = r"```json\s*([\s\S]*?)\s*```"
    match = re.search(pattern, text)
    if not match:
        json_str = text
    else:
        json_str = match.group(1).strip()
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON: {e}")
