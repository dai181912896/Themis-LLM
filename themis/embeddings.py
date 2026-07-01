import os
import time

from openai import OpenAI

from .config import ARK_BASE_URL, ARK_EMBEDDING_MODEL, ARK_RETRIES


def get_Embedding(text):
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
