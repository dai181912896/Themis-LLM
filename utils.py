import json
import os
import re

from attack_Investigation_byLLM import chunk_list


def slice_logs(text, N):
    logs = text
    total_slices = len(logs) // N + (1 if len(logs) % N != 0 else 0)
    slices = [logs[i:i + N] for i in range(0, len(logs), N)]
    return slices, total_slices


def line_mentions_entity(entity, line, mode=None):
    """Graph-mode aware 'does this line mention entity as subject/object?'.

    THEMIS_GRAPH_MODE=1 -> parse_triple + subject/object entity_match (NO substring).
    else -> legacy substring (`entity in line`), preserved so prior numbers stay
    reproducible. (FINAL plan §2 阶段1 改造点2, Gate0-G0-12.)
    """
    if os.environ.get("THEMIS_GRAPH_MODE") == "1":
        from supplementary.graph_utils import parse_triple
        from supplementary.normalize import entity_match
        m = mode or os.environ.get("THEMIS_MATCH_MODE", "relaxed")
        t = parse_triple(line)
        if not t.subject and not t.object:
            return False
        return ((bool(t.subject) and entity_match(entity, t.subject, m).matched) or
                (bool(t.object) and entity_match(entity, t.object, m).matched))
    return entity in line


_HUBS = {"cmd", "powershell", "wscript", "cscript", "mshta", "wmic",
         "rundll32", "explorer", "powershell_ise"}
_HUB_GENERIC = {"wordpad", "conhost", "calc", "dwellm", "searchindexer",
                "searchfilterhost", "searchprotocolhost", "runtimebroker",
                "sihost", "taskhost", "taskhostw", "csrss", "lsass", "wininit",
                "winlogon", "smss", "services", "spoolsv", "audiodg", "dwm",
                "fontdrvhost", "dllhost", "system", "idle"}


def _is_noise_entity(entity):
    """Stub — noise filtering is done POST-HOC during evaluation, not during BFS.
    This exists so the FILTER_NOISE block and BFS import don't crash."""
    return False


def _hub_children_lines(entity, logs, mode="relaxed", cap=30):
    """Hub-aware expansion: if `entity` is a CHILD of a dispatcher hub
    (cmd/powershell/...), return the hub's OTHER fork-children lines so the
    investigator sees sibling tools (e.g. certutil <- cmd -> mimikatz2).
    Uses graph structure only (no labels); generic-benign children filtered.
    """
    from supplementary.graph_utils import parse_triple
    from supplementary.normalize import entity_match, _basename
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
    # Child-action evidence: also append each sibling's top-K action edges
    # (execute/read/write/connect, system-noise filtered) so the LLM sees WHAT
    # each sibling does (e.g. 'powershell read invoke-mimikatz.ps1', 'calc
    # write X') and can emit it -> iterative expansion reaches the payload.
    # Targeted (only hub siblings' actions), not broad. (A+B optimization.)
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


def _is_noise_edge(line):
    """Filter universal startup noise: system DLL/image loads, prefetch.
    (action=load of system32/syswow64 .dll/.pyd/.sys — every process does this.)"""
    from supplementary.graph_utils import parse_triple
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
    r"_mei\d+[/\\]"                                       # PyInstaller self-extract
    r"|appdata/local/temp/[^/\s]*\.(pyd|dll)\b"           # temp pyd/dll
    r"|__psscriptpolicytest_[^/\s]*\.(ps1|psm1)\b"        # PowerShell policy-test noise (NOT real payloads like invoke-mimikatz.ps1 which live in desktop/shell/)
    r"|appdata/local/temp/[^/\s]*\.(cs|cmdline|out)\b",   # .NET/PowerShell compiled temp artifacts
    re.IGNORECASE)


def _cap_selfextract(lines, max_keep=8):
    """E: cap PyInstaller self-extraction artifacts (_mei<N>/* temp .pyd/.dll) so
    they don't crowd out sibling-tool discovery. Keeps ALL non-self-extract lines
    + up to max_keep self-extract lines. lazagne1 itself is still detected, so its
    (legitimate-TP) PyInstaller events still count — this only limits how many
    such lines the LLM sees per expansion."""
    keep, se = [], []
    for k in lines:
        if _SELFEXTRACT_RE.search(k):
            se.append(k)
        else:
            keep.append(k)
    return keep + se[:max_keep]


def get_neighbor_entity_sequences(entity, logs):
    """Neighbor extraction.

    Graph mode (THEMIS_GRAPH_MODE=1) matches PARSED subject/object — NEVER
    substring (FINAL plan §2 阶段1 改造点1, Gate0-G0-11). Also fixes the legacy
    bug that called chunk_list() inside the loop. Legacy substring path kept so
    previously reported numbers remain reproducible.
    """
    if os.environ.get("THEMIS_GRAPH_MODE") == "1":
        try:
            from supplementary.graph_utils import get_neighbor_lines
            mode = os.environ.get("THEMIS_MATCH_MODE", "relaxed")
            trace_path = os.environ.get("THEMIS_TRACE_PATH") or None
            kept = [k.rstrip("\n") for k in get_neighbor_lines(entity, logs, mode=mode, trace_path=trace_path)]
            # Hub-aware expansion: if entity is a child of a dispatcher hub,
            # also pull the hub's other children (sibling attack tools).
            if os.environ.get("THEMIS_HUB_EXPANSION") == "1":
                kept += _hub_children_lines(entity, logs, mode)
            # Filter universal system-DLL-load noise so attack signal is visible.
            if os.environ.get("THEMIS_FILTER_SYSDLL") == "1":
                kept = [k for k in kept if not _is_noise_edge(k)]
            # E: cap PyInstaller self-extraction artifacts so sibling tools get budget.
            if os.environ.get("THEMIS_CAP_SELFEXTRACT") == "1":
                kept = _cap_selfextract(kept)
            # Filter noise entities (.NET temp dirs, random temp files, system profiles)
            # to keep LLM context tight. Does NOT filter ground-truth IoCs (certutil,
            # mimikatz, calc, procdump etc. don't match noise patterns).
            if os.environ.get("THEMIS_FILTER_NOISE") == "1":
                from supplementary.graph_utils import parse_triple as _pt2
                kept = [k for k in kept
                        if not (_is_noise_entity(_pt2(k).subject) and
                                _is_noise_entity(_pt2(k).object))]
            return chunk_list(kept)
        except Exception as e:
            print("[graph_mode] fallback to legacy:", e)
    results_sequences = []
    for line in logs:
        if entity.lower() in line.lower().strip():
            results_sequences.append(line)
    return chunk_list(results_sequences)


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
        raise ValueError(f"解析 JSON 失败: {e}")


def get_Embedding(text):
    """Embedding for RAG query/index vectors.

    Ark-first (doubao-embedding-vision, 2048-dim) when ARK_API_KEY is set — the
    supported path (Tencent LKEAP quota is exhausted). Legacy Tencent
    lke-text-embedding-v1 kept for reproducibility when ARK_API_KEY is unset.
    KB collection must use the SAME embedding model as queries
    (rebuild_kb_ark.py -> *_doubao collections).
    """
    if os.environ.get("ARK_API_KEY"):
        import time
        from openai import OpenAI
        client = OpenAI(
            api_key=os.environ["ARK_API_KEY"],
            base_url=os.environ.get("ARK_BASE_URL", "https://ark.cn-beijing.volces.com/api/coding/v3"),
        )
        model = os.environ.get("ARK_EMBEDDING_MODEL", "doubao-embedding-vision")
        last = None
        for attempt in range(int(os.environ.get("ARK_RETRIES", "6"))):
            try:
                r = client.embeddings.create(model=model, input=[text])
                return r.data[0].embedding
            except Exception as e:
                last = e
                time.sleep(min(2 ** attempt, 30))
        raise last
    # legacy Tencent path
    import json
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
    from tencentcloud.lkeap.v20240522 import lkeap_client, models
    try:
        sid = os.environ.get("TENCENT_SECRET_ID", "os.getenv("TENCENT_SECRET_ID", "")")
        skey = os.environ.get("TENCENT_SECRET_KEY", "os.getenv("TENCENT_SECRET_KEY", "")")
        cred = credential.Credential(sid, skey)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "lkeap.ap-beijing.tencentcloudapi.com"
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = lkeap_client.LkeapClient(cred, "ap-guangzhou", clientProfile)
        req = models.GetEmbeddingRequest()
        params = {"Model": "lke-text-embedding-v1", "Inputs": [text]}
        req.from_json_string(json.dumps(params))
        resp = client.GetEmbedding(req)
        return json.loads(resp.to_json_string())["Data"][0]["Embedding"]
    except TencentCloudSDKException as err:
        print(err)
