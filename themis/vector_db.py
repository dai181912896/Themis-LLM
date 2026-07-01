import json
import os

from pymilvus import MilvusClient

from .config import ZILLIZ_URI, ZILLIZ_TOKEN
from .embeddings import get_Embedding

client = MilvusClient(uri=ZILLIZ_URI, token=ZILLIZ_TOKEN)


def load_ndjson_data(file_path):
    data_list = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                data_list.append(json.loads(line))
    return data_list


def extract_attack_sc(file_path):
    filename = os.path.basename(file_path)
    return filename.split("_")[3] if "_" in filename else "Unknown"


def process_and_insert(datas, attack_sc, collection_name):
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
            entity["my_vector"] = get_Embedding(entity["evidence_set"])
            entities.append(entity)

    if entities:
        client.insert(collection_name=collection_name, data=entities)
        print(f"Inserted {len(entities)} records for attack_sc: {attack_sc}")
