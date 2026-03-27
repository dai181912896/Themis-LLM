import json
import os
import traceback
from glob import glob
from pymilvus import MilvusClient
from utils import get_Embedding

# Milvus connection information
# IMPORTANT: Replace with your actual credentials before use
CLUSTER_ENDPOINT = "YOUR_MILVUS_CLUSTER_ENDPOINT"
TOKEN = "YOUR_MILVUS_TOKEN"
client = MilvusClient(uri=CLUSTER_ENDPOINT, token=TOKEN)

DATA_DIR = "./data/mxhy/"

def load_ndjson_data(file_path):
    """Read NDJSON file line by line"""
    data_list = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                data_list.append(json.loads(line))
    return data_list

def extract_attack_sc(file_path):
    """Extract attack_sc field from filename (example: m1h1 => h1)"""
    filename = os.path.basename(file_path)
    return filename.replace(".json", "").split("h")[-1] if "h" in filename else "unknown"

def process_and_insert(datas, attack_sc, collection_name):
    """Process and insert data into specified Milvus collection"""
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
        print(f"[✓] Inserted {len(entities)} records into {collection_name} for attack_sc: {attack_sc}")

def batch_insert_for_m_series():
    """Iterate through m1~m6, construct corresponding insert collections, insert non-self data"""
    all_files = glob(os.path.join(DATA_DIR, "*.json"))
    m_file_map = {"m1": [], "m2": [], "m3": [], "m4": [], "m5": [], "m6": []}

    for file in all_files:
        basename = os.path.basename(file).lower()
        for m in m_file_map:
            if basename.startswith(m):
                m_file_map[m].append(file)

    for target_m in m_file_map:
        other_ms = [m for m in m_file_map if m != target_m]
        collection_name = f"attack_pattern_{target_m}_" + "".join(other_ms)

        print(f"\n[>] Inserting into {collection_name} (excluding {target_m})")

        for m in other_ms:
            for file_path in m_file_map[m]:
                try:
                    attack_sc = extract_attack_sc(file_path)
                    data = load_ndjson_data(file_path)
                    process_and_insert(data, attack_sc, collection_name)
                except Exception as e:
                    print(traceback.format_exc())
                    print(f"[!] Error processing {file_path}: {e}")

if __name__ == "__main__":
    try:
        batch_insert_for_m_series()
    except Exception as e:
        print(traceback.format_exc())
        print(f"Error occurred: {e}")
