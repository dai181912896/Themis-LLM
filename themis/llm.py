import os
import time

from openai import OpenAI

from .config import ARK_BASE_URL, ARK_MODEL, ARK_RETRIES

_client = OpenAI(
    api_key=os.environ.get("ARK_API_KEY", ""),
    base_url=ARK_BASE_URL,
)


def get_answer(question, model_name=None):
    stats = {
        'tokens': {'prompt': 0, 'completion': 0, 'reasoning': 0, 'total': 0}
    }
    model = os.environ.get("ARK_MODEL") or model_name or ARK_MODEL
    response = None
    last = None
    for attempt in range(ARK_RETRIES):
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
