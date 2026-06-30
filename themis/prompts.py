"""LLM prompts for the iterative causal reasoning loop (Stage 3).

Three prompt builders, all f-string templates:

  generate_normal_prompt   — time-window mode
  generate_backward_prompt — MAIN causal prompt used by neighbor_scan
  generate_forward_prompt  — reverse-causal mode

Placeholders (interpolated, not ``.format``):
  {current_window_sequence}, {previous_window_summary}, {payload},
  {rag_context}, {detected}, {future_window_summary}
"""


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
