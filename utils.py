import json
import re

from attack_Investigation_byLLM import chunk_list


def slice_logs(text, N):
    # Split text into log list by lines
    logs=text
    # Calculate number of slices
    total_slices = len(logs) // N + (1 if len(logs) % N != 0 else 0)

    # Divide logs into slices
    slices = [logs[i:i + N] for i in range(0, len(logs), N)]

    return slices, total_slices


def get_neighbor_entity_sequences(entity,logs):

    results_sequneces=[]
    for line in logs:
        if entity.lower() in line.lower().strip():
            results_sequneces.append(line)
            chunk_list(results_sequneces)
    return chunk_list(results_sequneces)

def parse_text2json(text:str):
    pattern = r"```json\s*([\s\S]*?)\s*```"
    match = re.search(pattern, text)
    if not match:
        json_str = text
    else:
        json_str = match.group(1).strip()
    try:
        # Parse JSON string
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON: {e}")


def get_Embedding(text):
    import json
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
    from tencentcloud.lkeap.v20240522 import lkeap_client, models
    try:
        # Instantiate a credential object. You need to pass in Tencent Cloud account SecretId and SecretKey. Pay attention to keeping the key pair secret.
        # Code leakage may cause SecretId and SecretKey leakage and threaten the security of all resources under the account. The following code example is for reference only. It is recommended to use keys in a safer way. Please see: https://cloud.tencent.com/document/product/1278/85305
        # Keys can be obtained at the official console https://console.cloud.tencent.com/cam/capi
        # IMPORTANT: Replace with your actual credentials before use
        cred = credential.Credential("YOUR_TENCENT_SECRET_ID", "YOUR_TENCENT_SECRET_KEY")
        # Instantiate an http option, optional, can be skipped if no special requirements
        httpProfile = HttpProfile()
        httpProfile.endpoint = "lkeap.ap-beijing.tencentcloudapi.com"

        # Instantiate a client option, optional, can be skipped if no special requirements
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # Instantiate the client object of the requested product, clientProfile is optional
        client = lkeap_client.LkeapClient(cred, "ap-guangzhou", clientProfile)

        # Instantiate a request object, each interface will correspond to a request object
        req = models.GetEmbeddingRequest()
        params = {
            "Model": "lke-text-embedding-v1",
            "Inputs": [text]
        }
        req.from_json_string(json.dumps(params))

        # The returned resp is an instance of GetEmbeddingResponse, corresponding to the request object
        resp = client.GetEmbedding(req)
        # Output JSON format string packet
        json_resp=json.loads(resp.to_json_string())
        # print(json_resp)
        return json_resp["Data"][0]["Embedding"]


    except TencentCloudSDKException as err:
        print(err)