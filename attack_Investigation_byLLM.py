import json
import traceback
from VDB_data_utils import *
import time

import wrap_tencent_LLM_API
from utils import *
import os

# Prompt placeholders:
#   {current_window_sequence}: log sequence in current investigation window
#   {previous_window_summary}: summary from previous reasoning iteration
#   {payload}: alert entity reported by IDS
#   {rag_context}: retrieved Kill Chain knowledge from KB
#   {detected}: entities detected so far across all iterations


def generate_normal_prompt(current_window_sequence, previous_window_summary, payload, rag_context, detected):
    """Generate prompt for the normal (time-window) investigation mode."""
    prompt = f"""You are a security incident forensics expert specializing in attack investigation using heterogeneous system logs. Logs are preprocessed as subject-action-object triples. Below is a sample:
    Current task: host IP is 192.168.17.128. IDS reported malicious entities that may include domains, IPs, or programs. Detected alert entity: ({payload}. Previously detected suspicious entities: {detected}. This indicates potential attack activity. The system traverses logs starting from the alert node in chronological order. Each window must analyze the current log sequence and incorporate summaries from prior windows to form a continuous attack timeline.

    Generate a detailed analysis summary for the current sliding window:
    1. Current log sequence: {current_window_sequence}

    [Output Requirements]
    Identify malicious entities and behaviors. Output detected_suspicious_entities with entities you consider suspicious.
    Output strictly in JSON format with the following fields:
    - "detected_suspicious_entities": list of suspicious/malicious entities you identified.
    - "attack_process": array, each element represents an attack step involving the suspicious entities.
      - "action": step name
      - "sequences": log sequences containing suspicious entities
      - "description": detailed description of this step
      - "summary": description of attack behavior, must specify which entity did what action.

    Example output format:
    {{
      "detected_suspicious_entities": ["xxx.exe", "other_entity"],
      "attack_process": [
        {{
          "action": "step name",
          "sequences": "sequences containing attack behavior, empty if none",
          "description": "describe key log operations and anomalous behavior..."
        }}],
      "detected_suspicious_entities": ["xxx", "other_entity"],
      "summary": "summarize the attack behavior of key entities in the sequences"
    }}
    If the sequence is considered normal, attack_process should be empty.
    Generate the detailed analysis summary and output in JSON format.
    """
    return prompt


def generate_backward_prompt(current_window_sequence, previous_window_summary, payload, rag_context, detected):
    """Generate the backward (causal) investigation prompt - the MAIN prompt used by neighbor_scan.
    This prompt drives the iterative causal reasoning loop (Paper Section 4.3).
    """
    prompt = f"""You are a security incident forensics expert specializing in attack investigation using heterogeneous system logs. Logs are preprocessed as subject-action-object triples.

    Current task: host IP is 192.168.17.130. IDS reported malicious entities that may include domains, IPs, or programs. Detected alert entity: ({payload}. Previously detected suspicious entities: {detected}. This indicates potential attack activity. The system traverses logs starting from the alert node in chronological order. Each window must analyze the current log sequence and incorporate summaries from prior windows to form a continuous attack timeline.

    Generate a detailed analysis summary for the current sliding window using:
    1. Current log sequence from the provenance graph: {current_window_sequence}
    2. Malicious entities and attack behaviors from previous iteration: {previous_window_summary}
    3. Attack patterns retrieved from the Kill Chain knowledge base: {rag_context}. Refer to the core_entities and evidence_set fields and descriptions in the KB. These fields indicate suspicious entities for the corresponding sequences. Follow this analysis pattern to strictly identify suspicious entities. Do NOT misidentify normal system entities as suspicious. Avoid treating all communications as attack entities. In KB matching, the /*attacker IP & C2 server*/ in core_entities refers specifically to the IP resolved from the malicious domain (not the source host IP).
    4. Currently detected suspicious entities: {detected}

    Analysis Requirements:
    - For each log entry in the sequence, identify key operations and anomalous behaviors, and determine their role in the overall attack.
    - Synthesize information from prior reasoning to analyze causal connections between the current window and previous windows, ensuring the analysis follows temporal causality.
    - Leverage similar attack sequences retrieved from the Kill Chain knowledge base to further confirm anomalous operations and attack steps in the current window.
    - Clearly list all detected suspicious entities (e.g., payload.exe). Any process, file, IP, or domain actively used by the attacker in the attack chain should be considered suspicious, including legitimate tools repurposed by attackers (e.g., calc, 7z, procdump, certutil). Attackers frequently use legitimate tool names to disguise malicious behavior.
    - For each window summary, describe in detail the operations, key log evidence, attack intent, and causal relationships.
    - If no relevant data is found in the knowledge base, use your own reasoning to determine if an attack sequence exists.

    [Key Rule Clarifications]
    - Log format "*IP* resolve *WebName*" means domain *WebName* is resolved to *IP* address. That IP is the server address for the domain.
    - Log format "xxx.exe connect connection_x.x.x.x_y.y.y.y" means process xxx.exe sends data to IP y.y.y.y, where x.x.x.x is the local host address.
    - Do NOT simply judge whether an IP is malicious based on the presence of a "resolve" log entry. Combine with the entire attack chain reasoning to identify whether the actual communication target is adversarial.

    Follow these steps for reasoning analysis:

    [Step 1]: Node Identification
    - If a malicious domain is encountered during reasoning, its corresponding IP is the C2 server address. Once determined, add that IP to the malicious entities.
    - Describe each node's normal function and background in the system. For example:
      - explorer.exe: the default Windows file explorer, typically used for user interaction, a normal system process.
    - Important: For log format "X resolve Y.com", this strictly means domain Y is resolved to IP address X. X is the server IP for domain Y. If Y is determined to be a malicious domain, then X should be classified as a C2 server address and added to malicious entities.

    [Step 2]: Normal Behavior Pattern Analysis
    - Analyze the temporal and correlational patterns within the window to determine if they are consistent with normal system operations.
    - List common normal behavior patterns (e.g., user launching applications, routine inter-process calls) and compare with the current sequence:
      - If all events in the window conform to normal operational logic, tentatively classify as normal.
      - Mark the normal operation basis for each node, such as legitimate file access within expected timeframes and valid process call chains.

    [Step 3]: Anomaly Behavior Analysis
    - Refer to attack patterns retrieved from the KB. The core_entities and evidence_set fields indicate suspicious attack entities. Determine whether payloads are communicating with malicious IPs (C2 server IPs).
      - Find sequences associated with attack entities and analyze them to identify entities communicating with malicious programs.
      - If logs show web requests to malicious IPs or domains targeting documents, scripts, or executables, use context to determine if they are potential attack payloads (e.g., accessing .rtf, .doc, .exe, .js resources may indicate exploit or remote code download).
      - Based on already detected entities {detected}, focus on analyzing closely associated malicious domains, IPs, process files, etc.
      - Normal service processes should not proactively connect to malicious IPs. If such connections exist, add that service process to malicious entities.
    - [Hub Sibling Process Analysis - Important] When the current window contains multiple child processes spawned by the same dispatcher (e.g., "cmd fork X, cmd fork Y, cmd fork Z"), this means X, Y, Z are sibling tools from the same attack phase. Examine each sibling's subsequent behavior: credential dumping (read/write lsass/credential files), file downloading (certutil/wget), outbound connections (to known C2 IPs), privilege escalation, or lateral movement. If any sibling exhibits these attack behaviors, it MUST be added to detected_suspicious_entities. Do not ignore a process simply because its name looks like a normal tool (e.g., calc, 7z, procdump, certutil). Attackers frequently borrow legitimate tool names. Judge by the process's actual behavior, not its name.

    [Step 4]: Attack Entity Determination
    - In the attack chain context, any process, script, or tool actively invoked by the attacker should be considered part of the attack entities. This includes: download tools (certutil), archiving tools (7z), credential dumping tools (procdump/mimikatz), process injection hosts (calc), script interpreters (powershell/cscript), privilege escalation tools (fodhelper/JuicyPotato), etc.
    - Criteria: If a process/file/IP/domain appears within the attack timeline window and its behavior relates to attack objectives (credential theft, lateral movement, persistence, C2 communication, data exfiltration, privilege escalation), add it to detected_suspicious_entities. Do not exclude based on "normal-looking" tool names - focus on behavior, not names.

    [Output Requirements]
    Output strictly in JSON format with the following fields:
    - "detected_suspicious_entities": array. Ensure every malicious entity identified during reasoning is included. Strictly add suspicious entities, malicious domains, programs, downloaded exploit files, and other malicious files to this field. Ensure ALL malicious entities from the reasoning process are added. If no suspicious entities are detected, do not add new ones.
    - "attack_process": array. Each element corresponds to a reasoning step. Must include behaviors of the suspicious entities in detected_suspicious_entities. Empty if no suspicious entities were identified.
      - "action": step name
      - "sequences": log sequences containing suspicious entities
      - "description": detailed description of this step
      - "summary": description of inferred attack behavior. Must specify which entity performed what action. Must be highly relevant for the next iteration of reasoning.

    Example output format:
    {{
      "detected_suspicious_entities": ["payload.exe", "other_entity"],
      "attack_process": [
        {{
          "action": "step name",
          "sequences": "sequences containing attack behavior, empty if none",
          "description": "describe key log operations and anomalous behavior..."
        }},
        {{
          "action": "step name",
          "sequences": "sequences containing attack behavior, empty if none",
          "description": "describe key log operations and anomalous behavior..."
        }}],
      "detected_suspicious_entities": ["payload.exe", "other_entity"],
      "summary": "summarize the attack behavior of key entities based on all descriptions above"
    }}
    If the sequence is considered normal, attack_process should be empty. Each entity in detected_suspicious_entities must have a corresponding attack_process entry. If no new detected_suspicious_entities are found, all sequences are considered normal - do not output any unsupported attack_process.
    Generate the detailed analysis summary based on the above requirements and placeholders, and output in JSON format.
    """
    return prompt


def generate_forward_prompt(current_window_sequence, future_window_summary, payload, rag_context):
    """Generate the forward (reverse-causal) investigation prompt."""
    prompt = f"""You are a security incident response expert specializing in attack investigation using heterogeneous system logs. Logs are preprocessed as subject-action-object triples. Below is a sample:
    - c:/windows/system32/vssvc.exe_2564 executed c:/windows/system32/vssvc.exe
    - c:/windows/system32/searchfilterhost.exe_3340 read c:/windows/registration/r000000000006.clb
    - c:/windows/system32/searchfilterhost.exe_3340 read c:/windows/system32/rpcrtremote.dll
    - ... (more logs)

    Current task: IDS reported malicious entity {payload}, indicating potential attack activity. The system uses forward sliding analysis, inferring previous attack steps in reverse causal order. Each window must analyze the current log sequence and incorporate summaries from subsequent windows to infer prior attack steps.
    Most sequences in the log are normal; a small portion may be malicious.

    Generate a detailed analysis summary for the current sliding window using:
    1. Current log sequence: {current_window_sequence}
    2. Summary or causal relationships from prior windows: {future_window_summary}
    3. Contextual knowledge retrieved from the attack knowledge base: {rag_context}. Refer to the core_entities field in the KB, which indicates malicious entities for the corresponding sequence. Follow this analysis pattern to strictly identify suspicious entities. Do NOT misidentify normal system behaviors as entities. Also incorporate the phase_description field for reasoning.

    Analysis Requirements:
    - For each log entry in the current window sequence, identify key operations and anomalous behaviors, and determine their role in the overall attack.
    - Synthesize information from subsequent window summaries to analyze causal connections between the current window and future windows, ensuring reverse-causal reasoning to infer prior attack steps.
    - Leverage similar attack sequences retrieved from the KB to confirm anomalous operations and attack steps in the current window.
    - Clearly list detected suspicious entities (e.g., payload.exe). However, apply strict criteria: if a malicious program's loading involves system service processes, those system processes should NOT be identified as suspicious entities. For example, if a browser downloaded a malicious program, the browser itself should not be considered malicious - we only need to detect the malicious program, malicious IPs, and malicious files.
    - For each window summary, describe operations, key log evidence, attack intent, and causal relationships in detail.
    - If no relevant data is found in the KB, use your own reasoning to determine if an attack sequence exists.
    - Strictly execute the reasoning process. Do not infer normal sequences as malicious. If no anomalous sequences exist, return empty.

    [Output Requirements]
    Output strictly in JSON format with the following two fields:
    - "detected_suspicious_entities": array. Contains all detected suspicious entities. If you identified malicious entities during reasoning, they MUST be included in this array - do not include them in the reasoning but omit from this field.
    - "attack_process": array. Each element corresponds to a reasoning step:
      - "step": step number or name
      - "description": detailed description of this step

    Example output format:
    {{
      "detected_suspicious_entities": ["payload.exe", "other_entity"],
      "attack_process": [
        {{
          "step": "Payload Delivery",
          "description": "describe key log operations and anomalous behavior..."
        }},
        {{
          "step": "Lateral Movement",
          "description": "describe operations and causal connections with subsequent window summaries..."
        }}
      ]
    }}

    Generate the detailed analysis summary based on the above requirements, and output in JSON format.
    """
    return prompt


def load_host_logs(log_file_path):
    """Load host logs from file. Returns list of triple lines (skipping 2-line header)."""
    with open(log_file_path, 'r', encoding='utf-8') as f:
        logs = [line.strip() for line in f if line.strip()]
        logs = logs[2:]  # first line includes entity list header
        return logs


def find_first_attack_logs(logs, alert_entity):
    """Find the first occurrence of alert_entity in logs and extract context around it."""
    malicious_index = None
    for idx, line in enumerate(logs):
        if line_mentions_entity(alert_entity, line):
            malicious_index = idx
            break

    if malicious_index is None:
        print("Alert entity not found in logs.")
        return

    backward_chain = []
    for i in range(malicious_index, -1, -1):
        backward_chain.append(logs[i])

    forward_chain = []
    for i in range(malicious_index, len(logs)):
        forward_chain.append(logs[i])

    return backward_chain, forward_chain


def chunk_list(lst, n=20):
    """Split list into chunks of n elements."""
    return [lst[i:i+n] for i in range(0, len(lst), n)]


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
            output_fields=["evidence_set", "entity_actions", "phase_type", "core_entities", "phase_description"]
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
                reasoning_content, answer_content, stats = wrap_tencent_LLM_API.get_answer(prompt, 'deepseek-ai/DeepSeek-R1')
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
    from collections import deque
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
            output_fields=["evidence_set", "entity_actions", "phase_type", "core_entities", "phase_description"]
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
                reasoning_content, answer_content, stats = wrap_tencent_LLM_API.get_answer(prompt, 'deepseek-ai/DeepSeek-R1')
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
                from utils import _is_noise_entity
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


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run neighbor-based attack investigation.")
    parser.add_argument('--log_file', type=str, required=True, help="Path to the log file")
    parser.add_argument('--alert', type=str, required=True, help="Initial alert entity")
    parser.add_argument('--collection', type=str, required=True, help="Milvus collection name")
    parser.add_argument('--output', type=str, required=True, help="Output result file path")
    args = parser.parse_args()

    results, alert_entities, cost_results = neighbor_scan(
        args.log_file, args.alert, args.collection
    )

    with open(args.output, "w", encoding="utf-8") as f:
        for item in results:
            f.write(str(item) + "\n")
        for item in alert_entities:
            f.write(str(item) + ",\n")
        f.write(str(cost_results) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"Error: {e}")
