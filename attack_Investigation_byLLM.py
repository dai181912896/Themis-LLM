import json
import traceback
from VDB_data_utils import *
import time


import wrap_tencent_LLM_API
from  utils import *
import  os

'''
    1. Current system graph log sequence information: {current_window_sequence}
    2. Malicious entities detected in previous scan and described attack behaviors: {previous_window_summary}
    3. Attack patterns queried from attack knowledge base: {rag_context}. Please refer to the core_entities field and corresponding evidence_set field and descriptions in the knowledge base, which provide suspicious malicious entities for corresponding sequences. Follow this detection analysis pattern to strictly identify suspicious entities, do not misclassify normal system entities as suspicious entities, avoid treating normal communications as attack entities. When matching with knowledge base, the /*Malicious Attacker IP&C2 Server*/ in core_entities field specifically refers to IP address X resolved from malicious domain name (not source host IP).
    4. Currently detected suspicious entities: {detected}
'''

def generate_normal_prompt(current_window_sequence, previous_window_summary, payload, rag_context,detected):
    prompt = f"""You are now a security event forensics analysis expert, specializing in attack investigation and forensics on multi-source heterogeneous log data. The log data has been preprocessed into triple format. Below are some sample log data for you to read and understand:
    In the current task, the host IP address of the logs you are given is 192.168.17.128. The IDS alert has reported malicious entities, which may include domain names, IP addresses, programs, etc. The malicious entities detected in this scan are: ({payload}, and the suspicious entities detected in previous reasoning are {detected}, indicating possible attack behavior. The system uses a step-by-step traversal starting from the alert node reported by the system, analyzing in chronological order. Each window needs to analyze not only the log sequence information within the current window, but also combine the summary or causal relationship generated from the previous window, thereby forming a continuous attack process trajectory.
    Please generate a detailed analysis summary for the current sliding window by combining the following information:
    1. Current system graph log sequence information: {current_window_sequence}
    [Output Requirements]
    Analyze the malicious entities and behaviors, output detected_suspicious_entities, and put the entities you consider suspicious in detected_suspicious_entities.
    Please finally output the result in strict JSON format, which needs to include the following fields:
    - "detected_suspicious_entities": Add the malicious entities you analyzed as suspicious here.
    - "attack_process": Array type, attack steps require including behaviors of suspected entities detected_suspicious_entities inferred.
      - "action": Represents the step name
      -"sequences": Sequences of suspicious entities in corresponding logs
      - "description": Detailed description of this step
      -"summary": Description of attack behavior, must specify what action the specific entity name took, requires strong correlation to facilitate next round of reasoning.
    For example, the output format is as follows:
    {{
      "detected_suspicious_entities": ["xxx.exe", "other_entity"],
      "attack_process": [
        {{
          "action": "Behavior Name",
          "sequences":"Sequences included in attack behavior, empty if none"
          "description": "Describe the key log operations and anomalous behaviors of this step..."
        }},
        {{
          "action": "Behavior Name",
          "sequences":"Sequences included in attack behavior, empty if none"
          "description": "Describe the key log operations and anomalous behaviors of this step..."
        }}],
        "detected_suspicious_entities": ["xxx", "other_entity"],
        "summary":"Combining all descriptions above, summarize the attack behavior of strong entities in the inferred sequence in detail"
    }}
    If the sequence is considered normal, attack_process output is empty.
    Please generate a detailed analysis summary for the current sliding window according to the above requirements and placeholder content in reasoning mode, and output the result in JSON format.
    """
    return prompt






def generate_backward_prompt(current_window_sequence, previous_window_summary, payload, rag_context,detected):
    """
    Generate prompt for backward sliding (forward along chronological causal order).

    Parameters:
    - current_window_sequence: Log sequence information within current sliding window
    - previous_window_summary: Summary or causal relationship generated from previous sliding window
    - user_query_sequence: Log sequence queried by user
    - rag_context: Context knowledge queried from RAG system

    Returns:
    - A string containing complete Prompt content, requiring final output in JSON format.
    """
    prompt = f"""You are now a security event forensics analysis expert, specializing in attack investigation and forensics on multi-source heterogeneous log data. The log data has been preprocessed into triple format. Below are some sample log data for you to read and understand:



In the current task, the host IP address of the logs you are given is 192.168.17.130. The IDS alert has reported malicious entities, which may include domain names, IP addresses, programs, etc. The malicious entities detected in this scan are: ({payload}, and the suspicious entities detected in previous reasoning are {detected}, indicating possible attack behavior. The system uses a step-by-step traversal starting from the alert node reported by the system, analyzing in chronological order. Each window needs to analyze not only the log sequence information within the current window, but also combine the summary or causal relationship generated from the previous window, thereby forming a continuous attack process trajectory.

Please generate a detailed analysis summary for the current sliding window by combining the following information:
1. Current system graph log sequence information: {current_window_sequence}
2. Malicious entities detected in previous scan and described attack behaviors: {previous_window_summary}
3. Attack patterns queried from attack knowledge base: {rag_context}. Please refer to the core_entities field and corresponding evidence_set field and descriptions in the knowledge base, which provide suspicious malicious entities for corresponding sequences. Follow this detection analysis pattern to strictly identify suspicious entities, do not misclassify normal system entities as suspicious entities, avoid treating normal communications as attack entities. When matching with knowledge base, the /*Malicious Attacker IP&C2 Server*/ in core_entities field specifically refers to IP address X resolved from malicious domain name (not source host IP).
4. Currently detected suspicious entities: {detected}

Analysis Requirements:
- For each log in the sequence, identify key operations and anomalous behaviors, and determine their position and role in the entire attack process.
- Combine information from previous reasoning to analyze the causal relationship between current window logs and previous windows, ensuring the analysis process moves forward along chronological causal order.
- Use similar attack sequences and their analysis retrieved from the attack knowledge base to further confirm anomalous operations and attack steps within the current window.
- During analysis, please clearly list detected suspicious entities (e.g., payload.exe, etc.). This requires strict requirements - if certain malicious program loading processes require operating system processes to provide services, such system search processes should not be marked as suspicious entities. For example, if a browser downloads a malicious program, the browser will not be considered a malicious program.
- For each window's generated summary, need to describe in detail each step's operations, key log evidence, attack intent, and causal relationships.
- If no relevant data is found in the knowledge base, please use your reasoning to determine whether there is an attack sequence.
- Also assume that malicious programs use normal programs to run or load through vulnerabilities. Such normal programs will not be marked as suspicious programs. Please keep this in mind.


[Key Rule Clarification]
- Log format "*IP* resolve *WebName*" means domain name *WebName* is resolved to *IP* address, which is the server address corresponding to the domain name.
- Log format xxx.exe connect connection_x.x.x.x_y.y.y.y means process xxx.exe sends data to IP address y.y.y.y, where x.x.x.x is the local address.
- Do not simply judge whether an IP is malicious based on whether "resolve" logs appear. Should combine entire attack chain reasoning to identify whether actual communication target is malicious.


Please perform reasoning analysis strictly following the following process:
[Step 1]: Node Identification
If malicious domain addresses are encountered during reasoning, their corresponding IP addresses are C2 server addresses. If judged as such, the corresponding IP addresses should be added to malicious entities.
- For each node, describe its normal function and background information in the system. For example:
  - explorer.exe: As Windows system's default file resource manager, usually used for user interaction, belongs to normal system process.
- For each node, describe its normal function and background information in the system. Browser plugins, dll loaders, normal system runtime library loading, etc. should all be considered normal behaviors.
- Important rule clarification: For log format "X resolve Y.com", strictly means domain name Y is resolved to IP address X, which is the server IP corresponding to domain name Y. If Y is judged as malicious domain, then X should be classified as C2 server address and added to malicious entities.
[Step 2]: Normal Behavior Pattern Analysis
- Analyze the timing and correlation of events within the window to determine if there are patterns consistent with normal system operations.
- List common normal behavior patterns (such as user starting applications, normal inter-process calls, etc.) and compare with current sequences:
  - If all events in the entire window conform to normal operation logic (e.g., consecutive legitimate user operations or system tasks), then preliminarily judge as normal.
  - Mark the normal operation basis of each node, such as normal file access within a given time period, legitimate process call chains, etc.
[Step 3]: Anomalous Behavior Analysis
- Refer to the attack patterns queried in the attack knowledge base, where core_entities field and corresponding evidence_set field and descriptions, mark suspicious attack entities, and determine whether payload communicates with malicious IP addresses (C2 server IP).
   - Find sequences associated with attack entities for analysis, analyze and judge entities communicating with malicious programs
   - If there are Web requests to malicious IPs or domain names in logs, and the requested targets are documents, scripts, or executable files, should combine context to judge them as potential attack payloads. For example, accessing resources in formats such as `.rtf`, `.doc`, `.exe`, `.js` may indicate vulnerability attacks or remote code downloads.
   - Based on already detected entities {detected}, focus on analyzing already detected suspicious entities, closely related malicious domain names, IPs, process files, etc.
   - Normal service processes should not actively connect to malicious IP addresses under normal circumstances. If connections are generated, the service process should be added to malicious entities.
[Step 4]: Normal System Process Filtering
- If they are system-related processes, browsers, script tool programs, etc., if they play a loading role, they are considered to be exploited by malicious attackers and will not be considered attack entities. If they are exploited by vulnerabilities and have possibility of loading shellcode, they are considered malicious.
- Malicious programs using normal operating systems to execute payloads and other behaviors are malicious behaviors and should be marked in the given attack steps, but normal operating system entities used should not be marked as malicious.
- Important! If certain service programs, such as print programs, may be exploited by vulnerabilities to write malicious programs, then the service program should be added to malicious entities, because this means normal service programs have been loaded with malicious code.


[Output Requirements]
- Entities in detected_suspicious_entities, please strictly give suspicious entities obtained from reasoning.
Please finally output the result in strict JSON format, which needs to include the following fields:
- "detected_suspicious_entities": Array type, based on reasoning process and content, ensure every malicious entity is reflected in reasoning. Please strictly add suspicious entities, malicious domain names, malicious programs, downloaded vulnerability files, malicious files, etc. obtained from reasoning to the detected_suspicious_entities field, ensuring all malicious entities obtained from reasoning process are added to this array. If no suspicious entities are detected, there is no need to add new suspicious entities.
- "attack_process": Array type, each element corresponds to one reasoning attack step, attack steps require including behaviors of suspected entities detected_suspicious_entities inferred. If no suspicious entities are reasoned, it is empty,
  - "action": Represents the step name
  -"sequences": Sequences of suspicious entities in corresponding logs
  - "description": Detailed description of this step
  -"summary": Description of attack behavior obtained from reasoning, must specify what action the specific entity name took, requires strong correlation to facilitate next round of reasoning.


For example, the output format is as follows:
{{
  "detected_suspicious_entities": ["payload.exe", "other_entity"],
  "attack_process": [
    {{
      "action": "Behavior Name",
      "sequences":"Sequences included in attack behavior, empty if none"
      "description": "Describe the key log operations and anomalous behaviors of this step..."
    }},
    {{
      "action": "Behavior Name",
      "sequences":"Sequences included in attack behavior, empty if none"
      "description": "Describe the key log operations and anomalous behaviors of this step..."
    }}],
    "detected_suspicious_entities": ["payload.exe", "other_entity"],
    "summary":"Combining all descriptions above, summarize the attack behavior of strong entities in the inferred sequence in detail"
}}
If the sequence is considered normal, attack_process output is empty. Each behavior in detected_suspicious_entities requires attack_process output as reasoned malicious entities. If no new detected_suspicious_entities are detected, consider all sequences as normal and do not input any attack_process without evidence.
Please generate a detailed analysis summary for the current sliding window according to the above requirements and placeholder content in reasoning mode, and output the result in JSON format.
"""
    return prompt


def generate_forward_prompt(current_window_sequence, future_window_summary, payload, rag_context):
    """
    Generate prompt for forward sliding (backward tracing in reverse chronological causal order).

    Parameters:
    - current_window_sequence: Log sequence information within current sliding window
    - future_window_summary: Summary or causal relationship generated from subsequent sliding windows (future window summary)
    - user_query_sequence: Log sequence queried by user
    - rag_context: Context knowledge queried from RAG system

    Returns:
    - A string containing complete Prompt content, requiring final output in JSON format.
    """
    prompt = f"""You are now a security incident response expert, specializing in attack investigation and forensics on multi-source heterogeneous log data. The log data has been preprocessed into triple format. Below are some sample logs:
- c:/windows/system32/vssvc.exe_2564 executed c:/windows/system32/vssvc.exe
- c:/windows/system32/searchfilterhost.exe_3340 read c:/windows/registration/r000000000006.clb
- c:/windows/system32/searchfilterhost.exe_3340 read c:/windows/system32/rpcrtremote.dll
- … (more logs)

In the current task, the IDS alert has reported malicious entities {payload}, indicating possible attack behavior. The system uses forward sliding for log analysis, that is, tracing back in reverse chronological causal order to infer previous attack steps. Each window needs to analyze not only the log sequence information within the current window, but also combine the summary or causal relationship generated from subsequent windows to infer possible previous attack steps.
Most of the log sequences I give you are normal sequences, a small part are normal sequences.

Please generate a detailed analysis summary for the current sliding window by combining the following information:
1. Log sequence information within current sliding window: {current_window_sequence}
2. Log summary or causal relationship from previous sliding windows: {future_window_summary}
3. Context knowledge queried from attack library system: {rag_context}. Please refer to the core_entities field given in the knowledge base, which provides malicious entities for corresponding sequences. Follow this detection analysis pattern to strictly identify suspicious entities, do not misclassify normal system behaviors as entities. Also combine the phase_description field in the data for reasoning analysis.


Analysis Requirements:
- For each log in [Current Window Sequence], identify key operations and anomalous behaviors, and determine their position and role in the entire attack process.
- Combine information from [Subsequent Window Summary] to analyze the causal relationship between current window logs and subsequent windows, ensuring the analysis process performs tracing in reverse chronological causal order to infer previous attack steps.
- Use similar attack sequences and their analysis retrieved from the attack knowledge base to further confirm whether there are anomalous operations and attack steps within the current window.
- During analysis, please clearly list detected suspicious entities (e.g., payload.exe, etc.). This requires strict requirements - if certain malicious program loading processes require operating system processes to provide services, such system search processes should not be marked as suspicious entities. For example, if a browser downloads a malicious program, the browser will not be considered a malicious program. We only need to detect malicious programs, malicious IP addresses, and malicious files.
- For each window's generated summary, need to describe in detail each step's operations, key log evidence, attack intent, and causal relationships.
- If no relevant data is found in the knowledge base, please use your reasoning to determine whether there is an attack sequence.
- Strictly execute the reasoning process, do not infer normal sequences as malicious. If no anomalous sequences exist, return.


[Output Requirements]
Please finally output the result in strict JSON format, which needs to include the following two fields:
- "detected_suspicious_entities": Array type, contains all detected suspicious entities. If malicious entities are reasoned in reasoning, they must be filled in this array. Cannot have reasoning process containing entities but not filled here.
- "attack_process": Array type, each element corresponds to one reasoning attack step, requiring each element to contain:
  - "step": Represents the step number or name
  - "description": Detailed description of this step

For example, the output format is as follows:
{{
  "detected_suspicious_entities": ["payload.exe", "other_entity"],
  "attack_process": [
    {{
      "step": "Payload Delivery",
      "description": "Describe the key log operations and anomalous behaviors of this step..."
    }},
    {{
      "step": "Lateral Movement",
      "description": "Describe the operations of this step and their causal relationship with subsequent window summaries..."
    }}
  ]
}}

Please generate a detailed analysis summary for the current sliding window according to the above requirements and placeholder content, and output the result in JSON format.
"""
    return prompt





def load_host_logs(log_file_path):
    """
    :param path:  log_file_path: Path to log file, each line format is similar to "c:/windows/system32/vssvc.exe_2564 executed c:/windows/system32/vssvc.exe"
    :return:
    """

    with open(log_file_path, 'r', encoding='utf-8') as f:
        logs = [line.strip() for line in f if line.strip()]
        logs = logs[2:] #first line includes entity
        return logs


def find_first_attack_logs(logs,alert_entity):
    """
    Find the first log containing alert_entity from the log file and extract context logs centered on it.

      window: Context window size (take window lines before and after the alert_entity occurrence line)
    """

    malicious_index  = None
    for idx, line in enumerate(logs):
        if alert_entity in line:
            malicious_index  = idx
            break

    if malicious_index  is None:
        print("Specified alert entity not found in logs.")
        return

        # First wave: Scan forward, from malicious log line to the beginning of file
    backward_chain = []
    for i in range(malicious_index, -1, -1):
        backward_chain.append(logs[i])

    # Second wave: Scan backward, from malicious log line to the end of file
    forward_chain = []
    for i in range(malicious_index, len(logs)):
        forward_chain.append(logs[i])

    # Output scan results
    print("---- First wave: Forward scanning log sequence (from malicious line up to file start) ----")
    for line in backward_chain:
        print(line)
    print("---- Second wave: Backward scanning log sequence (from malicious line down to file end) ----")
    for line in forward_chain:
        print(line)

    return backward_chain, forward_chain



def load_system_log():
    log_dir='./data/logs'
    documents=[]
    chunk_size=20
    for log_filename in os.listdir(log_dir):
        log_file_path = os.path.join(log_dir, log_filename)
        with open(log_file_path, 'r', encoding='utf-8') as attack_log_file:
            first_line = attack_log_file.readline().strip()
            data = first_line.strip('[]').split(',')
            malicious_entities = data
            sequences=[]
            for line in attack_log_file:
                sequences.append(line.strip())  #
            slices,total_index=slice_logs(sequences,chunk_size)
            documents.append({"malicious_entities":malicious_entities,"sequences":slices, "total_index":total_index,"chunk_size":chunk_size})
    return documents


def chunk_list(lst, n=20):
    """
    Split list lst into sublists of n elements each.
    """
    return [lst[i:i+n] for i in range(0, len(lst), n)]


def time_windows_scan(log_file,alert, collection_name):
    host_logs= load_host_logs(log_file)
    alert_entites = [alert]           # Please replace with actual malicious entity string
    backward_chain,forward_chain=find_first_attack_logs(host_logs, alert)
    # documents=load_system_log()
    total_attack_results_json = []
    backward_chain=chunk_list(backward_chain)
    attack_summary = "First scan, no results yet"
    RagRetriverCount =0
    LLM_Api_recall_count=0
    format_error_count=0
    start_time = time.time()
    total_completion_tokens = 0
    total_prompt_tokens = 0
    total_reasoning_tokens = 0
    total_all_tokens = 0

    for chunk in backward_chain:
        query_sequences=','.join(chunk)
        query_sequences_vector=get_Embedding(query_sequences)
        res = client.search(
                    collection_name=collection_name,
                    anns_field="my_vector",
                    data=[query_sequences_vector],
                    limit=3,
                    search_params={"metric_type": "COSINE"},
                    output_fields=["evidence_set","entity_actions","phase_type","core_entities","phase_description"]
                )
        result_json=[]
        for hits in res:
            for hit in hits:
                if hit['distance']>0.80:
                    result_json.append(json.dumps(hit['entity'], ensure_ascii=False))
        if result_json:
            RagRetriverCount+=1
        prompt=generate_backward_prompt(query_sequences, attack_summary, alert, result_json,alert_entites)
        print("\n"+prompt)
        json_format = True
        attack_result_json = None
        while json_format:
            try:
                LLM_Api_recall_count+=1
                reasoning_content, answer_content, stats = wrap_tencent_LLM_API.get_answer(prompt,
                                                                                           'deepseek-ai/DeepSeek-R1')  #tiktok:deepseek-r1-250120   tencent:deepseek-r1
                attack_result_json = parse_text2json(answer_content)
                tokens = stats.get('tokens', {})
                total_completion_tokens += tokens.get('completion', 0)
                total_prompt_tokens += tokens.get('prompt', 0)
                total_reasoning_tokens += tokens.get('reasoning', 0)
                total_all_tokens += tokens.get('total', 0)
                attack_result_json = parse_text2json(answer_content)
                print("\n=== Cumulative Token Statistics ===")
                print(f"Prompt Tokens:    {total_prompt_tokens}")
                print(f"Completion Tokens: {total_completion_tokens}")
                print(f"  - Reasoning:     {total_reasoning_tokens}")
                print(f"Total Tokens:     {total_all_tokens}")
                json_format = False
            except Exception as e:
                format_error_count+=1
                print(e)
                time.sleep(7)

        print(attack_result_json)

        new_entities = attack_result_json.get("detected_suspicious_entities", [])
        for entity in new_entities:
            if entity not in alert_entites:
               alert_entites.append(entity)

        attack_summary = attack_result_json.get("summary", [])

        time.sleep(20)
    cost_time=time.time() - start_time
    cost_results={
      "cost_time": cost_time,
      "total_completion_tokens": total_completion_tokens,
      "total_prompt_tokens": total_prompt_tokens,
      "total_reasoning_tokens": total_reasoning_tokens,
      "total_all_tokens": total_all_tokens
    }
    print("RagRetriverCount:"+str(RagRetriverCount)+" LLM_Api_recall_count:"+str(LLM_Api_recall_count)+" format_error_count:"+str(format_error_count)+"\n")
    return total_attack_results_json,alert_entites,cost_results


def neighbor_scan(log_file,alert, collection_name):
    host_logs = load_host_logs(log_file)
    alert_entites = [alert]
    neighbor_sequneces=get_neighbor_entity_sequences(alert, host_logs)
    attack_summary = "First scan, no results yet"
    from collections import deque
    chunk_list_queue=deque(neighbor_sequneces)
    total_attack_results_json = []
    RagRetriverCount =0
    LLM_Api_recall_count=0
    format_error_count=0
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
            RagRetriverCount+=1

        # prompt = generate_backward_prompt(query_sequences, attack_summary, alert, result_json, alert_entites)                      #Reasoning prompt
        prompt=generate_backward_prompt(query_sequences, attack_summary, alert, result_json, alert_entites)
        print("\n" + prompt)
        json_format = True
        attack_result_json = None
        while json_format:
            try:
                LLM_Api_recall_count+=1
                reasoning_content, answer_content ,stats= wrap_tencent_LLM_API.get_answer(prompt,
                                                                                    'deepseek-ai/DeepSeek-R1')  # tiktok:deepseek-r1-250120   tencent:deepseek-r1
                tokens = stats.get('tokens', {})
                total_completion_tokens += tokens.get('completion', 0)
                total_prompt_tokens += tokens.get('prompt', 0)
                total_reasoning_tokens += tokens.get('reasoning', 0)
                total_all_tokens += tokens.get('total', 0)
                attack_result_json = parse_text2json(answer_content)
                print("\n=== Cumulative Token Statistics ===")
                print(f"Prompt Tokens:    {total_prompt_tokens}")
                print(f"Completion Tokens: {total_completion_tokens}")
                print(f"  - Reasoning:     {total_reasoning_tokens}")
                print(f"Total Tokens:     {total_all_tokens}")
                json_format = False
            except Exception as e:
                format_error_count+=1
                print(e)
                time.sleep(7)

        print(attack_result_json)
        new_entities = attack_result_json.get("detected_suspicious_entities", [])
        for entity in new_entities:
            if entity not in alert_entites:
                alert_entites.append(entity)
                chunk_list_queue.extendleft(reversed(get_neighbor_entity_sequences(entity, host_logs)))

        attack_summary = attack_result_json.get("summary", [])
        total_attack_results_json.append(attack_result_json)
        time.sleep(20)

    cost_time=time.time() - start_time
    cost_results={
      "cost_time": cost_time,
      "total_completion_tokens": total_completion_tokens,
      "total_prompt_tokens": total_prompt_tokens,
      "total_reasoning_tokens": total_reasoning_tokens,
      "total_all_tokens": total_all_tokens
    }



    print("RagRetriverCount:"+str(RagRetriverCount)+" LLM_Api_recall_count:"+str(LLM_Api_recall_count)+" format_error_count:"+str(format_error_count)+"\n")
    return total_attack_results_json,alert_entites,cost_results


def main():
    import argparse
    # time_windows_scan()
    parser = argparse.ArgumentParser(description="Run neighbor-based attack investigation.")
    parser.add_argument('--log_file', type=str, required=True, help="Path to the log file")
    parser.add_argument('--alert', type=str, required=True, help="Initial alert entity")
    parser.add_argument('--collection', type=str, required=True, help="Milvus collection name")
    parser.add_argument('--output', type=str, required=True, help="Output result file path")
    args = parser.parse_args()

    # results, alert_entities, cost_results = neighbor_scan(
    #     args.log_file, args.alert, args.collection
    # )

    results, alert_entities, cost_results = neighbor_scan(
        args.log_file, args.alert, args.collection
    )


    with open(args.output, "w", encoding="utf-8") as f:
        for item in results:
            f.write(str(item) + "\n")
        for item in alert_entities:
            f.write(str(item) + ",\n")
        f.write(str(cost_results) + "\n")




# for document in backward_chain:
    #     for sequnence in document['sequences']:
    #         sequnences=','.join(sequnence)
    #         query_log_vector=get_Embedding(sequnences)
    #         res=client.search(
    #             collection_name='attack_test_1',
    #             anns_field="my_vector",
    #             data=[query_log_vector],
    #             limit=1,
    #             search_params={"metric_type": "COSINE"},
    #             output_fields=["evidence_set","entity_actions","phase_type"]
    #         )
    #         print(res)
    #         for hits in res:
    #             for hit in hits:
    #                 print(hit)
    #         time.sleep(20)

















if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"Error occurred: {e}")