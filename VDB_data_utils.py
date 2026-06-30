import json
from pymilvus import MilvusClient
from utils import *
import traceback
import  os

# Milvus 连接信息
CLUSTER_ENDPOINT = "https://in05-a7d87b11006b15f.serverless.ali-cn-hangzhou.cloud.zilliz.com.cn"
TOKEN = "os.getenv("ZILLIZ_TOKEN", "")"


# 连接 Milvus
client = MilvusClient(uri=CLUSTER_ENDPOINT, token=TOKEN)


def load_ndjson_data(file_path):
    """逐行读取 NDJSON 文件"""
    data_list = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():  # 跳过空行
                data_list.append(json.loads(line))  # 解析 JSON 并添加到列表
    return data_list


def extract_attack_sc(file_path):
    """从文件名中提取 attack_sc 字段"""
    filename = os.path.basename(file_path)
    return filename.split("_")[3] if "_" in filename else "Unknown"


def process_and_insert(datas, attack_sc):
    """解析 JSON 数据并插入 Milvus"""
    entities = []
    for data in datas:
        attack_timeline = data.get("attack_timeline", [])
        chunk_index = data.get("chunk_index", "")

        for event in attack_timeline:
            entity = {
                "phase_type": event.get("phase_type", ""),
                "core_entities": ",".join(event.get("core_entities", [])),
                "evidence_set": ",".join(event.get("evidence_set", [])),
                "entity_actions": json.dumps(event.get("entity_actions", {}), ensure_ascii=False),
                "chunk_index": chunk_index,
                "phase_description": event.get("phase_description", ""),
                "attack_sc": attack_sc,
            }
            entity["my_vector"] = get_Embedding(entity["evidence_set"])  # 生成嵌入向量
            entities.append(entity)

    if entities:
        client.insert(collection_name=COLLECTION_NAME, data=entities)  # 批量插入
        print(f"Inserted {len(entities)} records for attack_sc: {attack_sc}")


def main(directory):
    """批量处理目录下的所有 JSON 文件"""
    file_paths = glob(os.path.join(directory, "**/*.json"), recursive=True)

    for file_path in file_paths:
        try:
            attack_sc = extract_attack_sc(file_path)
            data = load_ndjson_data(file_path)
            process_and_insert(data, attack_sc)
        except Exception as e:
            print(traceback.format_exc())
            print(f"Error processing file {file_path}: {e}")

from glob import glob

# 运行导入流程
COLLECTION_NAME = "attack_pattern_s4_s1s2s3"
def main():
    file_path="./data/jsons/filtered_seq_graph_training_preprocessed_logs_S2-CVE-2015-3105_windows.dot.json"
    data = load_ndjson_data(file_path)  # 请替换为实际的 JSON 文件路径
    process_and_insert(data,'s4')

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"发生错误：{e}")