# -*- coding: utf-8 -*-
import json

from tencentcloud.common.common_client import CommonClient
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile

class NonStreamResponse(object):
    def __init__(self):
        self.response = ""

    def _deserialize(self, obj):
        self.response = json.dumps(obj)

try:
    # Instantiate a credential object. You need to pass in Tencent Cloud account SecretId and SecretKey. Pay attention to keeping the key pair secret.
    # Code leakage may cause SecretId and SecretKey leakage and threaten the security of all resources under the account. The following code example is for reference only. It is recommended to use keys in a safer way. Please see: https://cloud.tencent.com/document/product/1278/85305
    # Keys can be obtained at the official console https://console.cloud.tencent.com/cam/capi

    # IMPORTANT: Replace with your actual credentials before use
    cred = credential.Credential("YOUR_TENCENT_SECRET_ID", "YOUR_TENCENT_SECRET_KEY")

    httpProfile = HttpProfile()
    httpProfile.endpoint = "lkeap.tencentcloudapi.com"
    httpProfile.reqTimeout = 40000  # Streaming interface may take longer
    clientProfile = ClientProfile()
    clientProfile.httpProfile = httpProfile

    params = "{\"Model\":\"deepseek-r1\",\"Messages\":[{\"Role\":\"user\",\"Content\":\"Hello\"}],\"Stream\":true}";
    common_client = CommonClient("lkeap", "2024-05-22", cred, "ap-guangzhou", profile=clientProfile)
    resp = common_client._call_and_deserialize("ChatCompletions", json.loads(params), NonStreamResponse)
    if isinstance(resp, NonStreamResponse):  # Non-streaming response
        print(resp.response)
    else:  # Streaming response
        for event in resp:
            print(event)
except TencentCloudSDKException as err:
    print(err)