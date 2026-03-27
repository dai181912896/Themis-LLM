# Connect using a MilvusClient object
from pymilvus import MilvusClient, DataType

# IMPORTANT: Replace with your actual credentials before use
CLUSTER_ENDPOINT="YOUR_MILVUS_CLUSTER_ENDPOINT" # Set your cluster endpoint
TOKEN="YOUR_MILVUS_TOKEN" # Set your token

# Initialize a MilvusClient instance
# Replace uri and token with your own
client = MilvusClient(
    uri=CLUSTER_ENDPOINT, # Cluster endpoint obtained from the console
    token=TOKEN # API key or a colon-separated cluster username and password
)



def create_schema():
    """Define and return collection Schema"""
    schema = client.create_schema(enable_dynamic_field=True)
    schema.add_field(field_name="my_id", datatype=DataType.INT64, is_primary=True, auto_id=True)
    schema.add_field(field_name="my_vector", datatype=DataType.FLOAT_VECTOR, dim=1024)
    schema.add_field(field_name="evidence_set", datatype=DataType.VARCHAR, max_length=10480)
    schema.add_field(field_name="core_entities", datatype=DataType.VARCHAR, max_length=128)
    schema.add_field(field_name="phase_type", datatype=DataType.VARCHAR, max_length=512)
    schema.add_field(field_name="chunk_index", datatype=DataType.VARCHAR, max_length=64)
    schema.add_field(field_name="attack_sc", datatype=DataType.VARCHAR, max_length=16)
    schema.add_field(field_name="entity_actions", datatype=DataType.JSON, max_length=10480)
    schema.add_field(field_name="phase_description", datatype=DataType.VARCHAR, max_length=1024)
    return schema


def create_index_params():
    """Define and return index parameters"""
    index_params = client.prepare_index_params()
    index_params.add_index(field_name="my_id", index_type="STL_SORT")
    index_params.add_index(field_name="my_vector", index_type="AUTOINDEX", metric_type="COSINE")
    index_params.add_index(field_name="core_entities", index_name="attack_entities")
    index_params.add_index(field_name="chunk_index", index_name="chunk_index")
    index_params.add_index(field_name="attack_sc", index_name="index_sc")
    return index_params


def create_collections(collection_names):
    """Batch create collections"""
    schema = create_schema()
    index_params = create_index_params()

    for name in collection_names:
        client.create_collection(collection_name=name, schema=schema, index_params=index_params)
        res = client.get_load_state(collection_name=name)
        print(f"Collection '{name}' load state: {res}")


def main():
    """Main function, execute batch collection creation"""
    collection_names = ["attack_pattern_m1_m2m3m4m5m6", "attack_pattern_m2_m1m3m4m5m6", "attack_pattern_m3_m1m2m4m5m6","attack_pattern_m4_m1m2m3m5m6","attack_pattern_m5_m1m2m3m4m6","attack_pattern_m6_m1m2m3m4m5"]
    create_collections(collection_names)

if __name__ == "__main__":
    main()