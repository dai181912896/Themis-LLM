"""Attack investigation main loop (Stage 3): iterative BFS expansion over the
provenance graph with RAG-backed LLM causal reasoning.

``neighbor_scan`` is the primary path: starting from the IDS alert entity it
extracts adjacency-prioritized neighbor sequences, retrieves Kill Chain
knowledge from the KB, reasons with the LLM (backward causal prompt), and
feeds any newly detected entities back into the BFS frontier. ``time_windows_scan``
is the chronological-window alternative.

Output format (results / entities / cost, one per line) is preserved exactly
so ``supplementary.run_themis_investigation.parse_output`` keeps working.
"""
import json
import os
import time
import traceback
from collections import deque

from .embeddings import get_Embedding
from .vector_db import client
from .graph import get_neighbor_entity_sequences, _is_noise_entity
from .logs import load_host_logs, find_first_attack_logs, chunk_list, parse_text2json
from .prompts import (
    generate_normal_prompt, generate_backward_prompt, generate_forward_prompt,
)
from .llm import get_answer


def time_windows_scan(log_file, alert, collection_name):
    host_logs = load_host_logs(log_file)
    alert_entites = [alert]
    backward_chain, forward_chain = find_first_attack_logs(host_logs, alert)
    total_attack_results_json = []
    backward_chain = chunk_list(backward_chain)
    attack_summary = "First scan, no results yet."
    RagRetriverCount = 0
    LLM_Api_recall_count = 0
    format_error_count = 0
    start_time = time.time()
    total_completion_tokens = 0
    total_prompt_tokens = 0
    total_reasoning_tokens = 0
    total_all_tokens = 0

    for chunk in backward_chain:
        query_sequences = ','.join(chunk)
        query_sequences_vector = get_Embedding(query_sequences)
        res = client.search(
            collection_name=collection_name,
            anns_field="my_vector",
            data=[query_sequences_vector],
            limit=3,
            search_params={"metric_type": "COSINE"},
            output_fields=["evidence_set", "entity_actions", "phase_type", "core_entities", "phase_description", "neighbors_prior", "neighbors_next"]
        )
        result_json = []
        for hits in res:
            for hit in hits:
                if hit['distance'] > 0.80:
                    result_json.append(json.dumps(hit['entity'], ensure_ascii=False))
        if result_json:
            RagRetriverCount += 1
        prompt = generate_backward_prompt(query_sequences, attack_summary, alert, result_json, alert_entites)
        json_format = True
        attack_result_json = None
        while json_format:
            try:
                LLM_Api_recall_count += 1
                reasoning_content, answer_content, stats = get_answer(prompt)
                attack_result_json = parse_text2json(answer_content)
                tokens = stats.get('tokens', {})
                total_completion_tokens += tokens.get('completion', 0)
                total_prompt_tokens += tokens.get('prompt', 0)
                total_reasoning_tokens += tokens.get('reasoning', 0)
                total_all_tokens += tokens.get('total', 0)
                json_format = False
            except Exception as e:
                format_error_count += 1
                time.sleep(7)

        new_entities = attack_result_json.get("detected_suspicious_entities", [])
        for entity in new_entities:
            if entity not in alert_entites:
                alert_entites.append(entity)
        attack_summary = attack_result_json.get("summary", [])
        time.sleep(int(os.environ.get("THEMIS_SLEEP", "2")))

    cost_time = time.time() - start_time
    cost_results = {
        "cost_time": cost_time,
        "total_completion_tokens": total_completion_tokens,
        "total_prompt_tokens": total_prompt_tokens,
        "total_reasoning_tokens": total_reasoning_tokens,
        "total_all_tokens": total_all_tokens
    }
    return total_attack_results_json, alert_entites, cost_results


def neighbor_scan(log_file, alert, collection_name):
    host_logs = load_host_logs(log_file)
    alert_entites = [alert]
    neighbor_sequences = get_neighbor_entity_sequences(alert, host_logs)
    attack_summary = "First scan, no results yet."
    chunk_list_queue = deque(neighbor_sequences)
    total_attack_results_json = []
    RagRetriverCount = 0
    LLM_Api_recall_count = 0
    format_error_count = 0
    start_time = time.time()
    total_completion_tokens = 0
    total_prompt_tokens = 0
    total_reasoning_tokens = 0
    total_all_tokens = 0

    while chunk_list_queue:
        chunk = chunk_list_queue.popleft()
        query_sequences = ','.join(chunk)
        query_sequences_vector = get_Embedding(query_sequences)
        res = client.search(
            collection_name=collection_name,
            anns_field="my_vector",
            data=[query_sequences_vector],
            limit=1,
            search_params={"metric_type": "COSINE"},
            output_fields=["evidence_set", "entity_actions", "phase_type", "core_entities", "phase_description", "neighbors_prior", "neighbors_next"]
        )
        result_json = []
        for hits in res:
            for hit in hits:
                if hit['distance'] > 0.65:
                    result_json.append(json.dumps(hit['entity'], ensure_ascii=False))
        if result_json:
            RagRetriverCount += 1

        prompt = generate_backward_prompt(query_sequences, attack_summary, alert, result_json, alert_entites)
        json_format = True
        attack_result_json = None
        while json_format:
            try:
                LLM_Api_recall_count += 1
                reasoning_content, answer_content, stats = get_answer(prompt)
                tokens = stats.get('tokens', {})
                total_completion_tokens += tokens.get('completion', 0)
                total_prompt_tokens += tokens.get('prompt', 0)
                total_reasoning_tokens += tokens.get('reasoning', 0)
                total_all_tokens += tokens.get('total', 0)
                attack_result_json = parse_text2json(answer_content)
                json_format = False
            except Exception as e:
                format_error_count += 1
                time.sleep(7)

        new_entities = attack_result_json.get("detected_suspicious_entities", [])
        _max_exp = int(os.environ.get("THEMIS_MAX_EXPANSIONS", "0"))
        for entity in new_entities:
            if entity not in alert_entites:
                if _max_exp > 0 and len(alert_entites) >= _max_exp:
                    print(f"[max_expansions] reached {_max_exp}, stopping BFS")
                    break
                if _is_noise_entity(entity):
                    print(f"[noise_filter] skipping noise entity: {entity}")
                    continue
                alert_entites.append(entity)
                chunk_list_queue.extendleft(reversed(get_neighbor_entity_sequences(entity, host_logs)))

        attack_summary = attack_result_json.get("summary", [])
        total_attack_results_json.append(attack_result_json)
        time.sleep(int(os.environ.get("THEMIS_SLEEP", "2")))

    cost_time = time.time() - start_time
    cost_results = {
        "cost_time": cost_time,
        "total_completion_tokens": total_completion_tokens,
        "total_prompt_tokens": total_prompt_tokens,
        "total_reasoning_tokens": total_reasoning_tokens,
        "total_all_tokens": total_all_tokens
    }
    return total_attack_results_json, alert_entites, cost_results


def run(log_file, alert, collection_name, output):
    """Run neighbor-based investigation and write results/entities/cost to output."""
    results, alert_entities, cost_results = neighbor_scan(
        log_file, alert, collection_name
    )

    with open(output, "w", encoding="utf-8") as f:
        for item in results:
            f.write(str(item) + "\n")
        for item in alert_entities:
            f.write(str(item) + ",\n")
        f.write(str(cost_results) + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run neighbor-based attack investigation.")
    parser.add_argument('--log_file', type=str, required=True, help="Path to the log file")
    parser.add_argument('--alert', type=str, required=True, help="Initial alert entity")
    parser.add_argument('--collection', type=str, required=True, help="Milvus collection name")
    parser.add_argument('--output', type=str, required=True, help="Output result file path")
    args = parser.parse_args()
    run(args.log_file, args.alert, args.collection, args.output)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"Error: {e}")
