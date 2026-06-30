import json
import traceback
from VDB_data_utils import *
import time


import wrap_tencent_LLM_API
from  utils import *
import  os

'''
    1. 当前遍历整个系统图的的日志序列信息： {current_window_sequence}
    2. 上一轮扫描中得到的恶意实体以及描述的攻击行为。： {previous_window_summary}
    3. 在我的攻击知识库中查询到的攻击模式为： {rag_context}，请参照知识库中给出的core_entities字段与其相应的evidence_set字段以及描述，该字段给出对应序列的可疑恶意实体，按照这样的检测的分析模式，严格给出可疑的实体，不要将正常的系统实体误判为可疑实体，避免将正常的通信都认为攻击实体，知识库匹配时，core_entities字段中的/*恶意攻击者IP&C2服务器*/特指恶意域名解析得到的IP地址X（而非源主机IP。
    4. 当前已经检测出可疑的实体为:{detected}
'''

def generate_normal_prompt(current_window_sequence, previous_window_summary, payload, rag_context,detected):
    prompt = f"""你现在是一名安全事件溯源分析专家，专门负责对多源异构日志数据进行攻击取证调查。日志数据已被预处理为三元组格式，以下是部分日志数据样例，请你阅读和理解其中的含义：
    当前任务中，给你日志的主机的IP地址为192.168.17.128，IDS 告警上报了恶意实体，可能包含域名、IP地址、程序等，本次检测中发现的恶意实体为：（{payload}，前轮推理检测出的可疑实体为{detected}，提示可能存在攻击行为。系统采用从系统上报的告警节点开始逐步遍历检查日志，即按照时间顺序分析。每个窗口不仅需要分析当前窗口内的日志序列信息，还要结合前序窗口生成的总结或因果关系，从而形成连续的攻击过程轨迹。
    请结合以下信息生成当前滑动窗口的详细分析总结：
    1. 当前遍历整个系统图的的日志序列信息： {current_window_sequence}
    【输出要求】
    分析出恶意的实体和行为，输出detected_suspicious_entities，你认为可疑的实体放在detected_suspicious_entities里面。
    请最终以严格的 JSON 格式输出结果，格式需包含以下字段：照
    - "detected_suspicious_entities":你分析为可疑的恶意实体加入到这里。
    - "attack_process": 数组类型，攻击步骤要求包含推测出可疑实体detected_suspicious_entities的行为。
      - "action": 表示步骤名称
      -"sequences":对应日志中的可疑实体的序列
      - "description": 对该步骤的详细描述
      -"summary":攻击行为的描述，描述必须指明具体的实体名称做出了什么行动，要求非常强相关，以便进行下一轮的推理。
    例如，输出格式如下：
    {{
      "detected_suspicious_entities": ["xxx.exe", "other_entity"],
      "attack_process": [
        {{
          "action": "行为名称",
          "sequences":"攻击行为包含的序列，如果没有则为空"
          "description": "描述该步骤的关键日志操作及其异常行为..."
        }},
        {{
          "action": "行为名称",
          "sequences":"攻击行为包含的序列，如果没有贼为空"
          "description": "描述该步骤的关键日志操作及其异常行为..."
        }}],
        "detected_suspicious_entities": ["xxx", "other_entity"],
        "summary":"结合上述所有description的描述，详细总结推理出的序列中强实体的攻击行为，如果推断出"
    }}
    如果序列被认为正常，则attack_process输出为空.
    请根据上述要求和占位符内容按照推理模式，生成当前滑动窗口的详细分析总结，并以 JSON 格式输出结果。
    """
    return prompt






def generate_backward_prompt(current_window_sequence, previous_window_summary, payload, rag_context,detected):
    """
    生成后向滑动（顺着时间因果顺序向后）的 prompt。

    参数:
    - current_window_sequence: 当前滑动窗口内的日志序列信息
    - previous_window_summary: 前序滑动窗口生成的总结或因果关系
    - user_query_sequence: 用户查询的日志序列
    - rag_context: 从 RAG 系统查询到的上下文知识

    返回:
    - 一个字符串，包含完整的 Prompt 内容，要求最终输出为 JSON 格式。
    """
    prompt = f"""你现在是一名安全事件溯源分析专家，专门负责对多源异构日志数据进行攻击取证调查。日志数据已被预处理为三元组格式，以下是部分日志数据样例，请你阅读和理解其中的含义：



当前任务中，给你日志的主机的IP地址为192.168.17.130，IDS 告警上报了恶意实体，可能包含域名、IP地址、程序等，本次检测中发现的恶意实体为：（{payload}，前轮推理检测出的可疑实体为{detected}，提示可能存在攻击行为。系统采用从系统上报的告警节点开始逐步遍历检查日志，即按照时间顺序分析。每个窗口不仅需要分析当前窗口内的日志序列信息，还要结合前序窗口生成的总结或因果关系，从而形成连续的攻击过程轨迹。

请结合以下信息生成当前滑动窗口的详细分析总结：
1. 当前遍历整个系统图的的日志序列信息： {current_window_sequence}
2. 上一轮扫描中得到的恶意实体以及描述的攻击行为。： {previous_window_summary}
3. 在我的攻击知识库中查询到的攻击模式为： {rag_context}，请参照知识库中给出的core_entities字段与其相应的evidence_set字段以及描述，该字段给出对应序列的可疑恶意实体，按照这样的检测的分析模式，严格给出可疑的实体，不要将正常的系统实体误判为可疑实体，避免将正常的通信都认为攻击实体，知识库匹配时，core_entities字段中的/*恶意攻击者IP&C2服务器*/特指恶意域名解析得到的IP地址X（而非源主机IP。
4. 当前已经检测出可疑的实体为:{detected}

分析要求：
- 针对发生的序列中的每条日志，识别关键操作和异常行为，判断其在整个攻击过程中的位置和作用。
- 综合之前推理得出的的信息，分析当前窗口日志与之前窗口之间的因果联系，确保分析过程顺着时间因果顺序向后推进。
- 利用攻击知识库中中检索到的相似攻击序列及其分析，进一步确认当前窗口内的异常操作和攻击步骤。
- 在分析过程中，请明确列出检测到的可疑实体（例如：payload.exe 等）。任何在攻击链中被攻击者主动使用的进程、文件、IP、域名都应视为可疑实体，包括那些被攻击者借用的合法工具（如calc、7z、procdump、certutil等）。攻击者经常利用合法工具执行恶意操作，这些工具在攻击上下文中已成为攻击链的一部分，应当被标记。
- 针对每个窗口生成的总结中，需详细描述每一步的操作、关键日志证据、攻击意图及前后因果关系。
- 如果知识库中未查询到相关数据，请结合你的推理进行判断是否有攻击序列。


【关键规则澄清】
- 日志格式"*IP* resolve *WebName*"表示域名*WebName*被解析为*IP*地址，该IP即为域名对应的服务器地址。
- 日志格式 xxx.exe connect connection_x.x.x.x_y.y.y.y 表示进程xxx.exe 向y.y.y.y ip地址发送数据，x.x.x.x为本机地址。
- 请勿简单依据是否出现 "resolve" 日志来判断 IP 是否恶意，应结合整个攻击链推理，识别实际通信目标是否具有攻击性。


请严格按照以下过程进行推理分析：
【步骤1】：节点识别
如果在推理过程中遇到恶意域名地址，其对应的IP地址就为C2服务器的地址，如果判断后，那么对应的IP地址应该加入的恶意实体中。
- 对每个节点描述其在系统中的正常功能和背景信息。例如：
  - explorer.exe：作为 Windows 系统的默认文件资源管理器，通常用于用户交互，属于正常系统进程。
- 对每个节点描述其在系统中的正常功能和背景信息，如浏览器插件，dll加载器，正常的系统运行库的加载，等行为都应该属于正常行为。
- 重要规则澄清：对于日志"X resolve Y.com"格式，严格表示域名Y被解析为IP地址X，该X即为域名Y对应的服务器IP。若Y被判定为恶意域名，则X应归类为C2服务器地址加入恶意实体。
【步骤2】：正常行为模式分析
- 分析该窗口内事件的时序与关联性，判断是否存在与系统正常操作一致的模式。
- 列举常见的正常行为模式（如用户启动应用、常规进程间调用等），并对比当前序列：
  - 如果整个窗口的事件均符合正常操作逻辑（例如连续的合法用户操作或系统任务），则初步判定为正常。
  - 标记出各节点的正常运行依据，如既定时间段内的正常文件访问、合法的进程调用链等。
【步骤3】：异常行为分析
- 参照攻击知识库中查询到的攻击模式为，其中core_entities字段与其相应的evidence_set字段以及描述，标记出可疑攻击实体，判断是否载荷与恶意IP地址（C2服务器IP）发生通信。
   -找出其中与攻击实体相关联的序列进行分析，分析判断出与恶意程序进行通讯的实体
   - 若日志中存在对恶意 IP 或域名发起的 Web 请求，且请求目标为文档、脚本或执行文件，应结合上下文判断其为潜在的攻击载荷。例如访问 `.rtf`, `.doc`, `.exe`, `.js` 等格式的资源，可能为漏洞攻击或远程代码下载。
   -根据已检测出的实体{detected}，重点分析已经检测出的的可疑实体，密切关联的恶意域名、IP、进程文件等实体
   -正常的服务进程，正常情况下不应主动外部连接到恶意IP地址，如何产生连接，应该将该服务进程加入到恶意实体。
- 【Hub兄弟进程分析 — 重要】当当前窗口日志中存在同一个调度进程（如cmd、powershell）派生多个子进程时（例如"cmd fork X, cmd fork Y, cmd fork Z"），说明X、Y、Z是同一攻击阶段的兄弟工具。请逐一检查每个兄弟进程的后续行为：是否执行凭据转储（读写lsass/凭据文件）、是否下载文件（certutil/wget）、是否进行网络外连（连接已知C2 IP）、是否进行提权或横向移动。若某个兄弟进程展现出上述任一攻击行为，必须将其加入detected_suspicious_entities。不要因为进程名看起来像正常工具（如calc、7z、procdump、certutil等常见工具名）而忽略——攻击者经常借用合法工具名来伪装恶意行为。判定依据是该进程的实际行为，而非其名称。
【步骤4】：攻击实体判定
- 在攻击链上下文中，被攻击者主动调用的进程、脚本、工具均应视为攻击实体的一部分。包括但不限于：被用于下载载荷的工具（certutil）、被用于打包外传的工具（7z）、被用于凭据转储的工具（procdump/mimikatz）、被用于进程注入的宿主（calc）、被用于执行脚本的解释器（powershell/cscript）、被用于提权的工具（fodhelper/JuicyPotato）等。
- 判定标准：如果一个进程/文件/IP/域名出现在攻击时序窗口内，且其行为与攻击目标（凭据窃取、横向移动、持久化、C2通信、数据外传、提权等）相关，就应加入 detected_suspicious_entities。不要因为工具名看起来”正常”而排除——关注其行为而非名称。


【输出要求】
-detected_suspicious_entities中的实体，请严格按照推理得出的可疑实体给出。
请最终以严格的 JSON 格式输出结果，格式需包含以下字段：
- "detected_suspicious_entities": 数组类型，根据推理的过程和内容，确保每一个恶意实体在推理中有体现。请严格将可疑的实体，推理得出的恶意域名、恶意程序、如下载漏洞文件、恶意文件等该类实体加入到detected_suspicious_entities字段内，确保推理过程得出所有恶意实体都务必加入到该数组。如果没有检测到可疑实体，就不必加入新的可疑实体。
- "attack_process": 数组类型，每个元素对应一次推理的攻击步骤，攻击步骤要求包含推测出可疑实体detected_suspicious_entities的行为，如果没有推理出可疑实体，则为空，
  - "action": 表示步骤名称
  -"sequences":对应日志中的可疑实体的序列
  - "description": 对该步骤的详细描述
  -"summary":推理得到的攻击行为的描述，描述必须指明具体的实体名称做出了什么行动，要求非常强相关，以便进行下一轮的推理。


例如，输出格式如下：
{{
  "detected_suspicious_entities": ["payload.exe", "other_entity"],
  "attack_process": [
    {{
      "action": "行为名称",
      "sequences":"攻击行为包含的序列，如果没有则为空"
      "description": "描述该步骤的关键日志操作及其异常行为..."
    }},
    {{
      "action": "行为名称",
      "sequences":"攻击行为包含的序列，如果没有贼为空"
      "description": "描述该步骤的关键日志操作及其异常行为..."
    }}],
    "detected_suspicious_entities": ["payload.exe", "other_entity"],
    "summary":"结合上述所有description的描述，详细总结推理出的序列中强实体的攻击行为，如果推断出"
}}
如果序列被认为正常，则attack_process输出为空，detected_suspicious_entities中的每一个行为都要求必须包含attack_process输出为推理得出的恶意实体，如果未检测出新的detected_suspicious_entities，即认为所有序列都是正常的，不输入任何没有证据的attack_process。
请根据上述要求和占位符内容按照推理模式，生成当前滑动窗口的详细分析总结，并以 JSON 格式输出结果。
"""
    return prompt


def generate_forward_prompt(current_window_sequence, future_window_summary, payload, rag_context):
    """
    生成前向滑动（逆时间因果顺序向后回溯）的 prompt。

    参数:
    - current_window_sequence: 当前滑动窗口内的日志序列信息
    - future_window_summary: 后续滑动窗口生成的总结或因果关系（未来窗口的总结）
    - user_query_sequence: 用户查询的日志序列
    - rag_context: 从 RAG 系统查询到的上下文知识

    返回:
    - 一个字符串，包含完整的 Prompt 内容，要求最终输出为 JSON 格式。
    """
    prompt = f"""你现在是一名安全事件响应专家，专门负责对多源异构日志数据进行攻击取证调查。日志数据已被预处理为三元组格式，以下是部分样例：
- c:/windows/system32/vssvc.exe_2564 executed c:/windows/system32/vssvc.exe
- c:/windows/system32/searchfilterhost.exe_3340 read c:/windows/registration/r000000000006.clb
- c:/windows/system32/searchfilterhost.exe_3340 read c:/windows/system32/rpcrtremote.dll
- …（更多日志）

当前任务中，IDS 告警上报了恶意实体{payload}，提示可能存在攻击行为。系统采用前向滑动方式进行日志分析，即以逆时间因果顺序向后回溯推断之前的攻击步骤。每个窗口不仅需要分析当前窗口内的日志序列信息，还要结合后续窗口生成的总结或因果关系，以推断之前可能发生的攻击步骤。
我给你的日志序列中大部分为正常的序列，小部分为正常的序列，

请结合以下信息生成当前滑动窗口的详细分析总结：
1. 当前滑动窗口内的日志序列信息： {current_window_sequence}
2. 前面滑动窗口的日志总结或因果关系： {future_window_summary}
3. 从攻击库系统中查询得到的上下文知识： {rag_context}，请参照知识库中给出的core_entities字段，该字段给出对应序列的恶意实体，i，按照这样的检测的分析模式，严格给出可疑的实体，不要将正常的系统行为误判为实体。同时结合数据中的phase_description的字段进行推理分析。


分析要求：
- 针对【当前窗口序列】中的每条日志，识别关键操作和异常行为，判断其在整个攻击过程中的位置和作用。
- 综合【后续窗口总结】的信息，分析当前窗口日志与之后窗口之间的因果联系，确保分析过程以逆时间因果顺序进行回溯，推断之前的攻击步骤。
- 利用攻击知识库中检索到的相似攻击序列及其分析，进一步确认当前窗口内的是否有异常操作和攻击步骤。
- 在分析过程中，请明确列出检测到的可疑实体（例如：payload.exe 等），但是该项需要严格的要求，如果某些恶意程序加载的过程需要关操作系统的进程进行服务，这样不该将这类系统搜索进程作为可疑实体，例如对于浏览器下载了恶意程序，那么浏览器将不作为恶意程序，我们只需要检测到恶意程序、恶意IP地址、以及恶意的文件,。
- 针对每个窗口生成的总结中，需详细描述每一步的操作、关键日志证据、攻击意图及前后因果关系。
- 如果知识库中未查询到相关数据，请结合你的推理进行判断是否有攻击序列。
- 严格执行推理过程，不要将正常序列推断为恶意的，如果不存在异常序列，即返回。


【输出要求】
请最终以严格的 JSON 格式输出结果，格式需包含以下两个字段：
- "detected_suspicious_entities": 数组类型，包含所有检测到的可疑实体,如果推理中推理出了恶意的实体，请严格务必要填入该数组，不能推理过程含有，而这里没有填入。
- "attack_process": 数组类型，每个元素对应一次推理的攻击步骤，要求每个元素包含：
  - "step": 表示步骤的编号或名称
  - "description": 对该步骤的详细描述

例如，输出格式如下：
{{
  "detected_suspicious_entities": ["payload.exe", "other_entity"],
  "attack_process": [
    {{
      "step": "载荷投递",
      "description": "描述该步骤的关键日志操作及其异常行为..."
    }},
    {{
      "step": "横向移动",
      "description": "描述该步骤的操作与后续窗口总结的因果联系..."
    }}
  ]
}}

请根据上述要求和占位符内容，生成当前滑动窗口的详细分析总结，并以 JSON 格式输出结果。
"""
    return prompt





def load_host_logs(log_file_path):
    """
    :param path:  log_file_path: 日志文件路径，每行格式类似 "c:/windows/system32/vssvc.exe_2564 executed c:/windows/system32/vssvc.exe"
    :return:
    """

    with open(log_file_path, 'r', encoding='utf-8') as f:
        logs = [line.strip() for line in f if line.strip()]
        logs = logs[2:] #first line include entity
        return logs


def find_first_attack_logs(logs,alert_entity):
    """
    从日志文件中找到第一条出现 alert_entity 的日志，并以此为中心提取上下文日志。

      window: 上下文窗口大小（取 alert_entity 出现行之前和之后各 window 行）
    """

    malicious_index  = None
    for idx, line in enumerate(logs):
        # Graph-mode aware: line_mentions_entity uses parse_triple + subject/
        # object entity_match when THEMIS_GRAPH_MODE=1, else legacy substring.
        # (FINAL plan §2 阶段1 改造点2, Gate0-G0-12.) Available via `from utils import *`.
        if line_mentions_entity(alert_entity, line):
            malicious_index  = idx
            break

    if malicious_index  is None:
        print("未在日志中找到指定的告警实体。")
        return

        # 第一波：向前扫描，从恶意日志行一直扫描到文件开头
    backward_chain = []
    for i in range(malicious_index, -1, -1):
        backward_chain.append(logs[i])

    # 第二波：向后扫描，从恶意日志行一直扫描到文件末尾
    forward_chain = []
    for i in range(malicious_index, len(logs)):
        forward_chain.append(logs[i])

    # 输出扫描结果
    print("---- 第一波：向前扫描的日志序列（从恶意行向上至文件起始） ----")
    for line in backward_chain:
        print(line)
    print("---- 第二波：向后扫描的日志序列（从恶意行向下至文件末尾） ----")
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
    将列表 lst 分成每组 n 个元素的子列表。
    """
    return [lst[i:i+n] for i in range(0, len(lst), n)]


def time_windows_scan(log_file,alert, collection_name):
    host_logs= load_host_logs(log_file)
    alert_entites = [alert]           # 请替换为实际的恶意实体字符串
    backward_chain,forward_chain=find_first_attack_logs(host_logs, alert)
    # documents=load_system_log()
    total_attack_results_json = []
    backward_chain=chunk_list(backward_chain)
    attack_summary = "第一次扫描，暂时无结果"
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
                print("\n=== 累计Token统计 ===")
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

        time.sleep(int(os.environ.get("THEMIS_SLEEP", "2")))
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
    attack_summary = "第一次扫描，暂时无结果"
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

        # prompt = generate_backward_prompt(query_sequences, attack_summary, alert, result_json, alert_entites)                      #推理prompt
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
                print("\n=== 累计Token统计 ===")
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
        _max_exp = int(os.environ.get("THEMIS_MAX_EXPANSIONS", "0"))
        for entity in new_entities:
            if entity not in alert_entites:
                if _max_exp > 0 and len(alert_entites) >= _max_exp:
                    print(f"[max_expansions] reached {_max_exp}, stopping BFS")
                    break
                # Skip noise entities (.NET temp, random temp files, system profiles)
                # to avoid wasting BFS budget. Gold IoCs never match noise patterns.
                from utils import _is_noise_entity
                if _is_noise_entity(entity):
                    print(f"[noise_filter] skipping noise entity: {entity}")
                    continue
                alert_entites.append(entity)
                chunk_list_queue.extendleft(reversed(get_neighbor_entity_sequences(entity, host_logs)))

        attack_summary = attack_result_json.get("summary", [])
        total_attack_results_json.append(attack_result_json)
        time.sleep(int(os.environ.get("THEMIS_SLEEP", "2")))

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
    #         time.sleep(int(os.environ.get("THEMIS_SLEEP", "2")))

















if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"发生错误：{e}")