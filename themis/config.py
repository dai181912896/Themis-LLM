"""Centralized configuration: endpoints, Kill Chain phases, env-driven flags.

All API credentials are read from the environment (``.env`` or system env) —
nothing is hardcoded. ``DEFAULT_ENV`` mirrors the values used by the
investigation launcher so the same knobs are available to every entry point.
"""
import os

# --- Cyber Kill Chain phases (used by KB annotation + story generation) -----
KILL_CHAIN_PHASES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command and Control (C2)", "Actions on Objectives"
]

# --- Volcengine Ark (LLM + embedding) ---------------------------------------
ARK_BASE_URL = os.environ.get(
    "ARK_BASE_URL", "https://ark.cn-beijing.volces.com/api/coding/v3")
ARK_MODEL = os.environ.get("ARK_MODEL", "ark-code-latest")
ARK_EMBEDDING_MODEL = os.environ.get("ARK_EMBEDDING_MODEL", "doubao-embedding-vision")
ARK_RETRIES = int(os.environ.get("ARK_RETRIES", "6"))

# --- Zilliz / Milvus (Kill Chain KB) ----------------------------------------
ZILLIZ_URI = os.environ.get(
    "ZILLIZ_URI",
    "https://in05-a7d87b11006b15f.serverless.ali-cn-hangzhou.cloud.zilliz.com.cn")
ZILLIZ_TOKEN = os.environ.get("ZILLIZ_TOKEN", "")

# --- Investigation behavior flags (env-overridable) -------------------------
def graph_mode() -> bool:
    return os.environ.get("THEMIS_GRAPH_MODE") == "1"

def match_mode() -> str:
    return os.environ.get("THEMIS_MATCH_MODE", "relaxed")

def sleep_seconds() -> int:
    return int(os.environ.get("THEMIS_SLEEP", "2"))

def max_expansions() -> int:
    """0 = unlimited BFS expansion."""
    return int(os.environ.get("THEMIS_MAX_EXPANSIONS", "0"))

# --- Batch pre-filter + runtime noise analyzer (Stage 2 optimization) -------
NOISE_RULES_PATH = os.environ.get("THEMIS_NOISE_RULES", "noise_rules.json")

# Hardcoded cache-file read/write noise patterns (fuzzy, matched on the
# normalized object path). Only applied to action in (read, write). Never
# matches a currently-detected entity — the pre-filter protects those.
CACHE_IO_SEED = [
    r"appdata/local/microsoft/windows/(webcache|inetcache|history|inetcookies)",
    r"appdata/local/[^/]+/(cache|cache2|code cache|gpucache|shadercache)",
    r"temporary internet files",
    r"(webcachev01\.dat|index\.dat)",
    r"appdata/locallow",
    r"(iconcache\.db|fontcache|thumbcache_\d+\.db)",
    r"ntuser\.dat(\.log\d*)?$",
    r"usrclass\.dat(\.log\d*)?$",
    r"\$(mft|logfile|usnjrnl)",
    r"/prefetch/",
    r"\.tmp$",
]


def dedup_enabled() -> bool:
    return os.environ.get("THEMIS_DEDUP", "1") == "1"


def filter_cache_io_enabled() -> bool:
    return os.environ.get("THEMIS_FILTER_CACHE_IO", "1") == "1"


def noise_analyzer_enabled() -> bool:
    """Runtime parallel LLM analyzer is OFF by default (extra token cost)."""
    return os.environ.get("THEMIS_NOISE_ANALYZER", "0") == "1"

# Default environment for the subprocess launcher. (Mirrors the values in
# supplementary/run_themis_investigation.py — single source of truth here.)
DEFAULT_ENV = {
    "ARK_API_KEY": os.environ.get("ARK_API_KEY", ""),
    "ARK_BASE_URL": ARK_BASE_URL,
    "ARK_MODEL": ARK_MODEL,
    "ARK_EMBEDDING_MODEL": ARK_EMBEDDING_MODEL,
    "ZILLIZ_TOKEN": ZILLIZ_TOKEN,
    "THEMIS_GRAPH_MODE": "1",
    "THEMIS_MATCH_MODE": "relaxed",
    "THEMIS_HUB_EXPANSION": "1",
    "THEMIS_FILTER_SYSDLL": "1",
    # Force UTF-8 for the subprocess: Windows console defaults to GBK, which
    # crashes `print(prompt)` when the prompt contains non-GBK chars.
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
}
