# entity_count.py
def count_entities(log_file):
    entities = set()
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 3:
                entity1 = parts[0]
                entity2 = parts[2]
                entities.add(entity1)
                entities.add(entity2)
    print(f"Total number of unique entities: {len(entities)}")
    return entities

if __name__ == "__main__":
    log_path = r"D:\JGame\exp\other_code\linux_logs_preprocess\data\parsed\no agent\processed_no_agent\parsed_vpn-filter.txt"  # Replace with your log file path
    unique_entities = count_entities(log_path)
    # If you need to print all entities, uncomment below
    # for e in unique_entities:
    #     print(e)
