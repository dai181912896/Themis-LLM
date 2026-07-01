"""Rebuild a Zilliz KB collection with Ark doubao-embedding-vision (2048-dim).

Exports each source collection's metadata, re-embeds its `evidence_set` with
doubao, and inserts into a new <src>_doubao collection. KB content (annotated
sequences/phases) is unchanged — only the embedding model is set, keeping the
index and query in the same vector space.

Usage:
  python rebuild_kb_ark.py --src attack_pattern_s1_s2s3s4 \
      [--src attack_pattern_s3_s1s2s4] [--src attack_pattern_s4_s1s2s3]
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXP = os.path.abspath(os.path.join(_HERE, ".."))
if _EXP not in sys.path:
    sys.path.insert(0, _EXP)

from pymilvus import MilvusClient, CollectionSchema, FieldSchema, DataType
from openai import OpenAI

ZILLIZ_URI = "https://in05-a7d87b11006b15f.serverless.ali-cn-hangzhou.cloud.zilliz.com.cn"
ZILLIZ_TOK = os.environ.get("ZILLIZ_TOKEN", "")

SCALAR_FIELDS = ["evidence_set", "core_entities", "phase_type",
                 "chunk_index", "attack_sc", "entity_actions", "phase_description"]
EMBED_DIM = 2048


def _ark_client():
    return OpenAI(api_key=os.environ["ARK_API_KEY"],
                  base_url=os.environ.get("ARK_BASE_URL", "https://ark.cn-beijing.volces.com/api/coding/v3"))


def _embed_batch(texts, model="doubao-embedding-vision"):
    # Ark embedding API caps input at 10/request; use 8 for safety.
    BS = 8
    out, i, cli = [], 0, _ark_client()
    while i < len(texts):
        chunk = texts[i:i + BS]
        r = cli.embeddings.create(model=model, input=chunk)
        out.extend([d.embedding for d in sorted(r.data, key=lambda x: x.index)])
        i += BS
    return out


def _export(c, col):
    for flt in ("my_id >= 0", "my_id != ''", "id >= 0"):
        try:
            rows = c.query(col, filter=flt, output_fields=SCALAR_FIELDS, limit=4096)
            if rows:
                return rows
        except Exception:
            continue
    return []


def rebuild(src, dst, model):
    c = MilvusClient(uri=ZILLIZ_URI, token=ZILLIZ_TOK)
    rows = _export(c, src)
    if not rows:
        print(f"[{src}] no rows exported"); return 0
    texts = [(r.get("evidence_set") or "").strip() or "empty" for r in rows]
    print(f"[{src}] {len(rows)} records -> embedding with {model}")
    vecs = _embed_batch(texts, model)

    try:
        c.drop_collection(dst)
    except Exception:
        pass

    fields = [FieldSchema("my_id", DataType.INT64, is_primary=True, auto_id=True),
              FieldSchema("my_vector", DataType.FLOAT_VECTOR, dim=EMBED_DIM)]
    for f in SCALAR_FIELDS:
        fields.append(FieldSchema(f, DataType.VARCHAR, max_length=65535))
    schema = CollectionSchema(fields, enable_dynamic_field=False)
    c.create_collection(dst, schema=schema)
    ip = MilvusClient.prepare_index_params()
    ip.add_index(field_name="my_vector", index_type="AUTOINDEX", metric_type="COSINE")
    c.create_index(dst, ip)
    c.load_collection(dst)

    data = []
    for r, v in zip(rows, vecs):
        rec = {"my_vector": v}
        for f in SCALAR_FIELDS:
            rec[f] = str(r.get(f, "") or "")[:65000]
        data.append(rec)
    c.insert(dst, data=data)
    c.flush(dst)
    print(f"[{src} -> {dst}] inserted {len(data)} records (dim {EMBED_DIM}, COSINE)")
    return len(data)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", action="append", required=True)
    ap.add_argument("--model", default="doubao-embedding-vision")
    a = ap.parse_args()
    for src in a.src:
        dst = f"{src}_doubao" if not src.endswith("_doubao") else src
        rebuild(src, dst, a.model)
