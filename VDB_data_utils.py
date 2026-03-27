import json
from pymilvus import MilvusClient
from utils import *
import traceback
import  os

# Milvus connection information
# IMPORTANT: Replace with your actual credentials before use
CLUSTER_ENDPOINT = "YOUR_MILVUS_CLUSTER_ENDPOINT"
TOKEN = "YOUR_MILVUS_TOKEN"


# Connect to Milvus
client = MilvusClient(uri=CLUSTER_ENDPOINT, token=TOKEN)


def load_ndjson_data(file_path):
    """Read NDJSON file line by line"""
    data_list = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():  # Skip empty lines
                data_list.append(json.loads(line))  # Parse JSON and add to list
    return data_list


def extract_attack_sc(file_path):
    """Extract attack_sc field from filename"""
    filename = os.path.basename(file_path)
    return filename.split("_")[3] if "_" in filename else "Unknown"


def process_and_insert(datas, attack_sc):
    """Parse JSON data and insert into Milvus"""
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
            entity["my_vector"] = get_Embedding(entity["evidence_set"])  # Generate embedding vector
            entities.append(entity)

    if entities:
        client.insert(collection_name=COLLECTION_NAME, data=entities)  # Batch insert
        print(f"Inserted {len(entities)} records for attack_sc: {attack_sc}")


def main(directory):
    """Batch process all JSON files under directory"""
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

# Run import process
COLLECTION_NAME = "attack_pattern_s4_s1s2s3"
def main():
    file_path="./data/jsons/filtered_seq_graph_training_preprocessed_logs_S2-CVE-2015-3105_windows.dot.json"
    data = load_ndjson_data(file_path)  # Please replace with actual JSON file path
    process_and_insert(data,'s4')

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"Error occurred: {e}")