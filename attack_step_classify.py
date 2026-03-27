import time
import traceback
import os
import json

import wrap_tencent_LLM_API
from utils import *


def load_attack_log():
    documents = []
    chunk_size = 50
    log_file_path = r"data/logs/output/filtered_seq_graph_training_preprocessed_logs_S1-CVE-2015-5122_windows.dot.txt"
    with open(log_file_path, 'r', encoding='utf-8') as attack_log_file:
        first_line = attack_log_file.readline().strip()
        malicious_entities = first_line.strip('[]').split(',')
        sequences = [line.strip() for line in attack_log_file]
        slices, total_index = slice_logs(sequences, chunk_size)
        documents.append({
            "malicious_entities": malicious_entities,
            "sequences": slices,
            "total_index": total_index,
            "chunk_size": chunk_size
        })
    return documents
def build_normal_prompt(document, index, summary):
    malicious_entities = document["malicious_entities"]
    current_sequence = document["sequences"][index]
    total_index = document["total_index"]
    prompt = f"""
    Please analyze the following host log triplets based on network attack behavior characteristics and known core attack entities. Generate structured attack behavior information to help build a knowledge base. The output structure must include the original log set and entity association analysis. Specific requirements:

【Core Parameters】
Detected attack entity list = {malicious_entities}

1. Analysis Dimensions:
- Analyze attack-related behavior sequences in logs, clarify various suspicious operations (such as remote connections, malicious file downloads and execution, sensitive directory access, etc.)
- Detect deployment and activation processes of malicious files
- Track behavior chains of suspicious processes and call relationships between entities
- Identify key entities in logs, including malicious programs, malicious files, suspicious IPs, domain names, processes triggering behaviors, etc.
- Ensure output includes specific entity names and their associations

2. Processing Rules:
(1) Strictly maintain original chronological order
(2) Operations with same attack intent or behavior pattern can be merged into one phase
(3) Different attack carriers should be analyzed independently
(4) Must preserve complete log evidence, evidence_set cannot be omitted
(5) Multiple behaviors from same entity should be merged for analysis
(6) Output must be standard JSON format, no comments or extra content
(7) Output results must summarize combined with previous log segment content, fill in last_summary field
(8) All core entities appearing in logs must be added to core_entities field
(9) phase_description field should describe current log behavior in detail
(10) entity_actions records malicious-related entities and their behaviors

3. Output Format:
{{
  "attack_timeline": [
    {{
      "phase_type": "",
      "core_entities": ["matched core entities"],
      "phase_description": "detailed description of attack behavior",
      "evidence_set": [],
      "entity_actions": {{
        "entity_name1": ["action1", "action2"],
        "entity_name2": ["action"]
      }}
    }}
  ],
  "entity_relationship": "description of call or dependency paths between core entities",
  "previous_phase_inference": "attack phase summarized from previous segment's behavior",
  "next_phase_prediction": "predict attacker's possible behavior intent for next phase",
  "chunk_index": "{index + 1}/{total_index}",
  "last_summary": "{summary}"
}}
Output Requirements:
attack_timeline content can only contain one array
Logs to analyze:
Current log is segment {index + 1} of {total_index} total segments.
{current_sequence}

    """
    return prompt.strip()

def build_prompt(document, index, summary):
    malicious_entities = document["malicious_entities"]
    current_sequence = document["sequences"][index]
    total_index = document["total_index"]

    prompt = f"""
Please intelligently classify the following host log triplets into attack stages based on network attack behavior characteristics and known core attack entities. Also divide attack stages according to the cyber kill chain to enhance analysis effectiveness. The output structure must include original log sets and entity association analysis. Specific requirements:

【Core Parameters】
Detected attack entity list = {malicious_entities}

1. Analysis Dimensions:
- Identify key stages of attack lifecycle (such as initial access, browser accessing remote IP addresses, downloading phishing files, executing phishing files, etc.), and combine with cyber kill chain stages for classification: reconnaissance, weaponization, delivery, exploitation, installation, command and control, actions on objectives
- Detect malicious file deployment patterns
- Track suspicious process activity chains
- Mark abnormal path access behaviors
- Analyze call relationships between entities
- Ensure specific entity names and related entity names are provided

2. Processing Rules:
(1) Strictly maintain original time sequence
(2) Operations with same attack intent are merged into stages
(3) Different attack carriers need independent staging
(4) Must include specific log evidence
(5) Multiple operations triggered by same entity are merged for analysis
(6) evidence_set must completely preserve input log entries
(7) Output must be standard JSON format
(8) Combine with previous analysis segment for reasoning and update last_summary
(9) Core entities appearing in logs should be listed in core_entities
(10) phase_description should combine kill chain and describe in detail
(11) Only malicious-related entities allowed in entity_actions
(12) Distinguish between normal processes involved in attack but not malicious

3. Output Format:
{{
  "attack_timeline": [
    {{
      "phase_type": "",
      "core_entities": ["matched core entities"],
      "phase_description": "behavior description",
      "evidence_set": [],
      "entity_actions": {{
        "entity_name1": ["operation type"],
        "entity_name2": ["behavior"]
      }}
    }}
  ],
  "entity_relationship": "description of associations between entities",
  "previous_phase_inference": "inference from previous stage",
  "next_phase_prediction": "prediction for next stage",
  "chunk_index": "{index + 1}/{total_index}",
  "last_summary": "{summary}"
}}

Logs to analyze:
Current log is segment {index + 1} of {total_index} total segments.
{current_sequence}
"""
    return prompt.strip()


def main():
    documents = load_attack_log()
    jsons, queries = [], []

    total_completion_tokens = 0
    total_prompt_tokens = 0
    total_reasoning_tokens = 0
    total_all_tokens = 0

    summary = "This is the first sequence, no previous summary available yet"
    start_time = time.time()
    for document in documents:
        for index in range(document['total_index']):
            prompt = build_prompt(document, index, summary)
            print(prompt)

            json_response = None
            while True:
                try:
                    reasoning_content, answer_content, stats = wrap_tencent_LLM_API.get_answer(
                        prompt, 'deepseek-ai/DeepSeek-R1'
                    )
                    tokens = stats.get('tokens', {})
                    total_completion_tokens += tokens.get('completion', 0)
                    total_prompt_tokens += tokens.get('prompt', 0)
                    total_reasoning_tokens += tokens.get('reasoning', 0)
                    total_all_tokens += tokens.get('total', 0)

                    print(answer_content)
                    print("\n=== Cumulative Token Statistics ===")
                    print(f"Prompt Tokens:    {total_prompt_tokens}")
                    print(f"Completion Tokens:{total_completion_tokens}")
                    print(f"Reasoning Tokens: {total_reasoning_tokens}")
                    print(f"Total Tokens:     {total_all_tokens}")

                    json_response = parse_text2json(answer_content)
                    break
                except Exception as e:
                    print(traceback.format_exc())
                    print("Retrying...")
                    time.sleep(7)

            summary = json_response.get("last_summary", summary)

            output_path = r'data/knowldge_no_chain/filtered_seq_graph_training_preprocessed_logs_S1-CVE-2015-5122_windows.dot.txt'
            with open(output_path, "a", encoding="utf-8") as file:
                file.write(json.dumps(json_response, ensure_ascii=False) + "\n")
            cost_time = time.time() - start_time
            print('cost time'+str(cost_time))
            print("Data has been appended to file")
            jsons.append(json_response)
            queries.append(prompt)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"Error occurred: {e}")
