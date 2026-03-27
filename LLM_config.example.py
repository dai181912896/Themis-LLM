from openai import OpenAI

# Example configuration file for LLM API client
# IMPORTANT: Copy this file to LLM_config.py and replace with your actual API credentials before use

# Example client configuration (commented out):
# client = OpenAI(
#     # Replace with your API Key: api_key="sk-xxx",
#     api_key="YOUR_TENCENT_API_KEY",
#     base_url="https://api.lkeap.cloud.tencent.com/v1",
# )

# Alternative client configuration (commented out):
# client = OpenAI(
#     api_key="YOUR_VOLCES_API_KEY",
#     base_url="https://ark.cn-beijing.volces.com/api/v3/",
# )

client = OpenAI(
    base_url="https://api.openai-hub.com/v1",
    api_key="YOUR_OPENAI_HUB_API_KEY"
)
