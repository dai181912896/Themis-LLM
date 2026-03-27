
from LLM_config import client

def get_answer(question,model_name):
    stats = {
        'tokens': {
            'prompt': 0,
            'completion': 0,
            'reasoning': 0,
            'total': 0
        }
    }

    # Create chat completion request
    response = client.chat.completions.create(
        model=model_name,  # Example uses deepseek-v3, can be changed as needed
        messages=[
            {"role": "user", "content":question},
        ],
        temperature=0.1
    )
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



    return reasoning_content, answer_content,stats
