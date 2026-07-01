"""Unit tests for themis.prefilter — batch dedup + cache-I/O + learned-rule filter."""
import re

from themis.prefilter import dedup_chunk, is_cache_io, filter_chunk
from themis.rules import Pattern


def test_dedup_within_chunk_preserves_order():
    assert dedup_chunk(["a fork b", "a fork b", "c read d"]) == ["a fork b", "c read d"]


def test_dedup_empty():
    assert dedup_chunk([]) == []


def test_is_cache_io_browser_cache():
    assert is_cache_io("explorer read c:/users/u/appdata/local/microsoft/windows/webcachev01.dat")


def test_is_cache_io_prefetch_read():
    assert is_cache_io("svchost read c:/windows/prefetch/foo.pf")


def test_is_cache_io_not_rw_action():
    assert not is_cache_io("certutil fork payload.exe")  # action=fork, not read/write


def test_is_cache_io_non_cache_path():
    assert not is_cache_io("mimikatz read c:/users/u/secrets.bin")


def test_filter_drops_cache_keeps_real():
    chunk = [
        "explorer read c:/users/u/appdata/local/microsoft/windows/webcachev01.dat",  # cache -> drop
        "mimikatz read c:/users/u/secrets.bin",                                       # real -> keep
    ]
    kept, st = filter_chunk(chunk, learned_rules=[], enable_dedup=True, enable_cache=True)
    assert "mimikatz read c:/users/u/secrets.bin" in kept
    assert len(kept) == 1
    assert st["cache_io"] == 1


def test_filter_protects_detected_ioc():
    # certutil is detected -> protected even though it touches a cache path
    chunk = ["certutil write c:/users/u/appdata/local/foo/cache"]
    kept, st = filter_chunk(chunk, learned_rules=[], protected_basenames={"certutil"},
                            enable_dedup=True, enable_cache=True)
    assert len(kept) == 1
    assert st["cache_io"] == 0  # protected -> not counted as cache_io drop


def test_filter_learned_rule_applies():
    pat = Pattern(regex="windows/servicing", action="read", compiled=re.compile("windows/servicing"))
    chunk = ["trustedinstaller read c:/windows/servicing/packages.db"]
    kept, st = filter_chunk(chunk, learned_rules=[pat], enable_dedup=True, enable_cache=True)
    assert len(kept) == 0
    assert st["learned"] == 1


def test_filter_empty_chunk_after_filter():
    chunk = [
        "explorer read c:/users/u/appdata/local/microsoft/windows/webcachev01.dat",
        "svchost read c:/windows/prefetch/x.pf",
    ]
    kept, st = filter_chunk(chunk, enable_dedup=True, enable_cache=True)
    assert kept == []
    assert st["total_dropped"] == 2


def test_disable_cache_keeps_everything():
    chunk = ["explorer read c:/users/u/appdata/local/microsoft/windows/webcachev01.dat"]
    kept, st = filter_chunk(chunk, enable_dedup=True, enable_cache=False)
    assert len(kept) == 1
    assert st["cache_io"] == 0
