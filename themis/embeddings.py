"""Embedding generation for RAG query/index vectors (Volcengine Ark).

Uses doubao-embedding-vision (2048-dim). The KB collection must use the SAME
embedding model as queries (rebuild_kb_ark.py -> *_doubao collections).
"""
import os
import time

from openai import OpenAI

from .config import ARK_BASE_URL, ARK_EMBEDDING_MODEL, ARK_RETRIES


def get_Embedding(text):
    """Return the embedding vector for ``text`` via Ark, with retry/backoff."""
    client = OpenAI(
        api_key=os.environ["ARK_API_KEY"],
        base_url=ARK_BASE_URL,
    )
    model = os.environ.get("ARK_EMBEDDING_MODEL", ARK_EMBEDDING_MODEL)
    last = None
    for attempt in range(ARK_RETRIES):
        try:
            r = client.embeddings.create(model=model, input=[text])
            return r.data[0].embedding
        except Exception as e:
            last = e
            time.sleep(min(2 ** attempt, 30))
    raise last
