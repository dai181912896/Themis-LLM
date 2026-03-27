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
    请根据网络攻击行为特征和已知核心攻击实体，对下列主机日志三元组进行行为描述，生成结构化的攻击行为信息，帮助构建知识库。输出结构需包含原始日志集合与实体关联分析。具体要求如下：

【核心参数】
检测到的攻击实体列表 = {malicious_entities}

1. 分析维度：
- 分析日志中的攻击相关行为序列，明确各类可疑行为操作（如远程连接、恶意文件下载与执行、敏感目录访问等）。
- 检测恶意文件的部署和激活过程。
- 追踪可疑进程的行为链与实体之间的调用关系。
- 明确日志中的关键实体，包括恶意程序、恶意文件、可疑IP、域名、触发行为的进程等。
- 请确保输出中必须给出具体的实体名称及其关联。

2. 处理规则：
（1） 严格保持原始时间顺序。
（2） 相同攻击意图或行为模式可以合并为一个阶段。
（3） 不同攻击载体应独立分析。
（4） 必须保留完整日志证据，evidence_set 不能省略。
（5） 相同实体产生的多个行为应合并分析。
（6） 输出必须为标准 JSON 格式，不得加入注释或额外内容。
（7） 输出结果需结合上一个日志片段内容进行总结，填入 last_summary 字段。
（8） 日志中出现的所有核心实体需加入 core_entities 字段。
（9） phase_description 字段应详细描述当前日志行为。
（10） entity_actions 记录恶意相关的实体及其行为。

3. 输出格式：
{{
  "attack_timeline": [
    {{
      "phase_type": "为空",
      "core_entities": ["匹配的核心实体"],
      "phase_description": "攻击行为的详细描述",
      "evidence_set": [为空],
      "entity_actions": {{
        "实体名称1": ["行为1", "行为2"],
        "实体名称2": ["行为"]
      }}
    }}
  ],
  "entity_relationship": "核心实体之间的调用或依赖路径描述",
  "previous_phase_inference": "根据上一个片段的行为总结出的攻击阶段",
  "next_phase_prediction": "预测下一阶段攻击者可能的行为意图",
  "chunk_index": "{index + 1}/{total_index}",
  "last_summary": "{summary}"
}}
输出要求:
attack_timeline内容只能出现一个数组
待分析日志：
当前日志为第 {index + 1} 个片段，总共 {total_index} 个片段。
{current_sequence}

    """
    return prompt.strip()

def build_prompt(document, index, summary):
    malicious_entities = document["malicious_entities"]
    current_sequence = document["sequences"][index]
    total_index = document["total_index"]

    prompt = f"""
请根据网络攻击行为特征和已知核心攻击实体对下列主机日志三元组进行攻击阶段智能划分，同时按网络安全杀伤链来划分攻击阶段以强化分析效果，输出结构需包含原始日志集合和实体关联分析。具体要求：
【核心参数】
检测到的攻击实体列表 = {malicious_entities}

1. 分析维度：
- 识别攻击生命周期关键阶段（如初始访问、浏览器访问远程IP地址、下载钓鱼文件、执行钓鱼文件等），并结合网络安全杀伤链的阶段进行划分，如侦察、武器化、交付、利用、安装、命令与控制、行动与目标达成。
- 检测恶意文件部署模式
- 追踪可疑进程活动链
- 标记异常路径访问行为
- 分析实体间的调用关系
- 请注意必须给出具体的实体名称，以及相关的实体名称。

2. 处理规则：
（1） 严格保持原始时间序列
（2） 相同攻击意图的操作合并为阶段
（3） 不同攻击载体需独立划分
（4） 必须包含具体日志证据
（5） 相同实体触发的多个操作合并分析
（6） evidence_set必须完整保留输入日志条目
（7） 输出必须为标准json格式
（8） 与上一个分析片段结合推理并更新last_summary
（9） 日志中出现的核心实体应列入core_entities
（10） phase_description应结合杀伤链并详细描述
（11） entity_actions中只允许恶意相关实体出现
（12） 注意区分参与攻击但非恶意的正常进程

3. 输出格式：
{{
  "attack_timeline": [
    {{
      "phase_type": "",
      "core_entities": ["匹配的核心实体"],
      "phase_description": "行为描述",
      "evidence_set": [],
      "entity_actions": {{
        "实体名1": ["操作类型"],
        "实体名2": ["行为"]
      }}
    }}
  ],
  "entity_relationship": "实体之间的关联描述",
  "previous_phase_inference": "上一个阶段的推测",
  "next_phase_prediction": "下一阶段的预测",
  "chunk_index": "{index + 1}/{total_index}",
  "last_summary": "{summary}"
}}

待分析日志：
当前日志为第 {index + 1} 个片段，总共 {total_index} 个片段。
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

    summary = "当前为第一个序列，暂未包含上一次的最新摘要"
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
                    print("\n=== 累计Token统计 ===")
                    print(f"Prompt Tokens:    {total_prompt_tokens}")
                    print(f"Completion Tokens:{total_completion_tokens}")
                    print(f"Reasoning Tokens: {total_reasoning_tokens}")
                    print(f"Total Tokens:     {total_all_tokens}")

                    json_response = parse_text2json(answer_content)
                    break
                except Exception as e:
                    print(traceback.format_exc())
                    print("重试中...")
                    time.sleep(7)

            summary = json_response.get("last_summary", summary)

            output_path = r'data/knowldge_no_chain/filtered_seq_graph_training_preprocessed_logs_S1-CVE-2015-5122_windows.dot.txt'
            with open(output_path, "a", encoding="utf-8") as file:
                file.write(json.dumps(json_response, ensure_ascii=False) + "\n")
            cost_time = time.time() - start_time
            print('cost time'+str(cost_time))
            print("数据已追加到文件")
            jsons.append(json_response)
            queries.append(prompt)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"发生错误：{e}")
