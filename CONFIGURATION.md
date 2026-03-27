# Themis Configuration Guide

This document provides instructions for configuring the Themis system with your API credentials.

## Configuration Files

Before running the system, you need to configure the following files with your actual API credentials:

### 1. config.py

Copy `config.example.py` to `config.py` and fill in your credentials:

```python
account = 'YOUR_BCE_ACCOUNT'  # Your BCE account
api_key = 'YOUR_BCE_API_KEY'  # Your BCE API key
endpoint = 'http://YOUR_ENDPOINT:PORT'  # Your BCE endpoint
```

Also set the Qianfan access keys:

```python
os.environ["QIANFAN_ACCESS_KEY"] = "YOUR_QIANFAN_ACCESS_KEY"
os.environ["QIANFAN_SECRET_KEY"] = "YOUR_QIANFAN_SECRET_KEY"
```

### 2. LLM_config.py

Copy `LLM_config.example.py` to `LLM_config.py` and configure your LLM API client:

```python
client = OpenAI(
    base_url="YOUR_LLM_API_ENDPOINT",
    api_key="YOUR_LLM_API_KEY"
)
```

Supported LLM providers:
- Tencent Cloud LKEAP
- Volces ARK
- OpenAI Hub

### 3. VDB_data_utils.py

Update the Milvus connection information:

```python
CLUSTER_ENDPOINT = "YOUR_MILVUS_CLUSTER_ENDPOINT"
TOKEN = "YOUR_MILVUS_TOKEN"
```

### 4. utils.py

Update the Tencent Cloud credentials for embedding generation:

```python
cred = credential.Credential("YOUR_TENCENT_SECRET_ID", "YOUR_TENCENT_SECRET_KEY")
```

## Getting API Credentials

### Tencent Cloud
- Visit: https://console.cloud.tencent.com/cam/capi
- Create API keys (SecretId and SecretKey)

### Qianfan (Baidu AI Cloud)
- Visit: https://cloud.baidu.com/product/wenxinworkshop
- Get your Access Key and Secret Key

### Milvus / Zilliz Cloud
- Visit: https://cloud.zilliz.com/
- Create a cluster and get your connection credentials

## Security Notes

- **NEVER commit actual API keys to version control**
- Keep your credentials secret and secure
- Use environment variables when possible
- Rotate your keys regularly

## Running the System

After configuration:

```bash
python attack_Investigation_byLLM.py --log_file <path> --alert <entity> --collection <name> --output <path>
```

