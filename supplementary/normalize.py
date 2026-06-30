"""Entity/action normalization and matching — NO substring matching.

strict  = normalized full equality
relaxed = basename exact / IP-no-port exact (never a substring test)

Every relaxed match returns a MatchResult.reason so adjacency/evaluation
traces are auditable (FINAL plan §7.1 E1b, Gate0-G0-11/G0-13).
"""
import re
from dataclasses import dataclass


_WS = re.compile(r"\s+")
_BSLASH = re.compile(r"\\")
_QUOTES = re.compile(r"[\"'`,()\[\]]")
_PID_SUFFIX = re.compile(r"_(\d+)$")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_entity(value) -> str:
    """Lowercase, \\ -> /, strip quotes/brackets/whitespace. No semantic split."""
    if value is None:
        return ""
    v = str(value).strip()
    v = _QUOTES.sub("", v)
    v = _BSLASH.sub("/", v)
    v = v.strip().strip("/").strip()
    v = _WS.sub(" ", v)
    return v.lower()


def normalize_action(value) -> str:
    if value is None:
        return ""
    v = _QUOTES.sub("", str(value).strip()).lower()
    return _WS.sub(" ", v)


def _basename(value) -> str:
    v = normalize_entity(value)
    if "/" in v:
        v = v.rsplit("/", 1)[-1]
    v = v.split(":")[0]            # drop port
    v = _PID_SUFFIX.sub("", v)     # payload.exe_2592 -> payload.exe
    # strip executable/script extension so the alert 'certutil.exe' matches the
    # bare process name 'certutil' (W10 stores subjects without .exe).
    v = re.sub(r"\.(exe|dll|bat|ps1|hta|vbs|sh|py|com|scr|sys)$", "", v)
    return v


def _ip_no_port(value) -> str:
    v = normalize_entity(value)
    return re.split(r"[:_]", v)[0]  # 124.1.2.3_8084 / 124.1.2.3:8084 -> 124.1.2.3


def _is_ip(v: str) -> bool:
    return bool(_IP_RE.match(v))


@dataclass
class MatchResult:
    matched: bool
    policy: str   # strict_normalized | basename_exact | ip_exact | none
    reason: str   # human-readable, for audit trace


def entity_keys(value) -> dict:
    n = normalize_entity(value)
    return {
        "normalized": n,
        "basename": _basename(value),
        "ip": _ip_no_port(value),
    }


def entity_match(a, b, mode: str = "strict") -> MatchResult:
    """Match two entity strings. mode = 'strict' | 'relaxed'. Never substring."""
    na, nb = normalize_entity(a), normalize_entity(b)
    if na and na == nb:
        return MatchResult(True, "strict_normalized", f"normalized({na})")
    if mode != "relaxed":
        return MatchResult(False, "none", "")

    # IPs: compare on port-stripped form
    if _is_ip(na) or _is_ip(nb):
        ia, ib = _ip_no_port(a), _ip_no_port(b)
        if ia and ia == ib:
            return MatchResult(True, "ip_exact", f"ip({ia})")

    ba, bb = _basename(a), _basename(b)
    if ba and ba == bb:
        return MatchResult(True, "basename_exact", f"basename({ba})")

    return MatchResult(False, "none", "")
