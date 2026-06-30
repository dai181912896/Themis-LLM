"""Embedding generation for RAG query/index vectors.

Ark-first (doubao-embedding-vision, 2048-dim) when ``ARK_API_KEY`` is set —
the supported path (Tencent LKEAP quota is exhausted). The legacy Tencent
lke-text-embedding-v1 path is kept for reproducibility when ``ARK_API_KEY`` is
unset. KB collection must use the SAME embedding model as queries
(rebuild_kb_ark.py -> *_doubao collections).
"""
import os
import time


def get_Embedding(text):
    if os.environ.get("ARK_API_KEY"):
        from openai import OpenAI
        from .config import ARK_BASE_URL, ARK_EMBEDDING_MODEL, ARK_RETRIES
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

    # legacy Tencent path
    import json
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
    from tencentcloud.lkeap.v20240522 import lkeap_client, models
    try:
        sid = os.environ.get("TENCENT_SECRET_ID", "")
        skey = os.environ.get("TENCENT_SECRET_KEY", "")
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
