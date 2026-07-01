"""Unit tests for themis.rules — persisted noise-rule store."""
import json
import re
import threading

from themis.rules import Pattern, add_patterns, load_rules, pattern_matches


def test_load_missing_returns_empty(tmp_path):
    assert load_rules(str(tmp_path / "nope.json")) == []


def test_load_corrupt_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not valid json", encoding="utf-8")
    assert load_rules(str(p)) == []


def test_add_and_load_roundtrip(tmp_path):
    p = str(tmp_path / "r.json")
    n = add_patterns(p, [{"regex": "appdata/local/[^/]+/cache", "action": "read", "reason": "cache"}])
    assert n == 1
    rs = load_rules(p)
    assert len(rs) == 1
    assert rs[0].action == "read" and rs[0].reason == "cache"
    assert rs[0].compiled is not None


def test_add_dedup_by_regex(tmp_path):
    p = str(tmp_path / "r.json")
    add_patterns(p, [{"regex": "prefetch"}])
    assert add_patterns(p, [{"regex": "prefetch"}]) == 0  # duplicate regex
    assert len(load_rules(p)) == 1


def test_pattern_matches_action_filter():
    pat = Pattern(regex="cache", action="read", compiled=re.compile("cache"))
    assert pattern_matches(pat, "read", "appdata/local/x/cache")
    assert not pattern_matches(pat, "write", "appdata/local/x/cache")  # action filter
    assert not pattern_matches(pat, "read", "nothing-here")            # no regex match


def test_concurrent_append_no_corruption(tmp_path):
    p = str(tmp_path / "r.json")
    add_patterns(p, [{"regex": "seed"}])

    def worker(i):
        for k in range(25):
            add_patterns(p, [{"regex": f"pat{i}_{k}"}])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    data = json.loads(open(p, encoding="utf-8").read())
    regexes = [pp["regex"] for pp in data["patterns"]]
    assert len(regexes) == len(set(regexes))              # no duplicates, no corruption
    assert "seed" in regexes
    assert len(regexes) == 1 + 4 * 25                      # all present
    assert data["stats"]["learned"] == 1 + 4 * 25          # seed + concurrent adds
