"""LLM call wrapper.

Redirected to Volcengine Ark (env-driven) — the supported path. The legacy
LLM_config.client pointed at a leaked/dead openai-hub key. Signature of
get_answer (reasoning, answer, stats) is unchanged so attack_Investigation_byLLM
needs no edit. Model is env-overridable (ARK_MODEL=ark-code-latest).
"""
import os
from openai import OpenAI

_client = OpenAI(
    api_key=os.environ.get("ARK_API_KEY", ""),
    base_url=os.environ.get("ARK_BASE_URL", "https://ark.cn-beijing.volces.com/api/coding/v3"),
)


def get_answer(question, model_name):
    import time
    stats = {
        'tokens': {'prompt': 0, 'completion': 0, 'reasoning': 0, 'total': 0}
    }
    model = os.environ.get("ARK_MODEL") or model_name  # ARK_MODEL overrides the legacy deepseek name
    response = None
    last = None
    for attempt in range(int(os.environ.get("ARK_RETRIES", "6"))):
        try:
            response = _client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": question}],
                temperature=0.1,
            )
            break
        except Exception as e:
            last = e
            time.sleep(min(2 ** attempt, 30))
    if response is None:
        raise last
    message = response.choices[0].message
    reasoning_content = getattr(message, 'reasoning_content', '') or ''
    answer_content = getattr(message, 'content', '') or ''

    if hasattr(response, 'usage'):
        usage = response.usage
        stats['tokens'] = {
            'prompt': getattr(usage, 'prompt_tokens', 0),
            'completion': getattr(usage, 'completion_tokens', 0),
            'total': getattr(usage, 'total_tokens', 0),
            'reasoning': getattr(
                getattr(usage, 'completion_tokens_details', None),
                'reasoning_tokens', 0
            ) if hasattr(usage, 'completion_tokens_details') else 0
        }

    return reasoning_content, answer_content, stats
