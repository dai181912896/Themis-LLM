
import time
import pymochow  # Import pymochow library for database operations
from pymochow.configuration import Configuration  # For configuring client
import config  # Import configuration file containing authentication and endpoint information

# Import pymochow model-related classes and enumeration types
from pymochow.model.schema import Schema, Field, VectorIndex, SecondaryIndex, HNSWParams
from pymochow.model.enum import FieldType, IndexType, MetricType, TableState
from pymochow.model.table import Partition

# Initialize client using information from configuration file
config_obj = Configuration(credentials=config.credentials, endpoint=config.endpoint)
client = pymochow.MochowClient(config_obj)

# Select or create database
db = client.database("db_attack_investigate")

# Define data table fields
fields = [
    Field("id", FieldType.UINT64, primary_key=True, partition_key=True, auto_increment=False, not_null=True),
    Field("text", FieldType.STRING),
    Field("metadata", FieldType.STRING),
    Field("source", FieldType.STRING, not_null=True),
    Field("entity", FieldType.STRING,not_null=True),# Malicious entity retrieval enhancement
    Field("type", FieldType.STRING, not_null=True), # Step
    Field("Creator", FieldType.STRING, not_null=True),  # Step
    Field("vector", FieldType.FLOAT_VECTOR, not_null=True, dimension=384)
]

# Define data table indexes
indexes = [
    VectorIndex(index_name="vector_idx", field="vector", index_type=IndexType.HNSW, metric_type=MetricType.L2, params=HNSWParams(m=32, efconstruction=200)),
    SecondaryIndex(index_name="entity_type", field="entity") # index data must be Not null
]

# Try to create data table, catch and print possible exceptions
try:
    # Replication count should not exceed number of instance data nodes
    # Free tier reference value: replication=1
    # Standard tier reference value: replication=3
    table = db.create_table(table_name="chunks", replication=1, partition=Partition(partition_num=1), schema=Schema(fields=fields, indexes=indexes))
except Exception as e:  # Catch all types of exceptions
    print(f"Error: {e}")  # Print exception information

# Poll data table status until table state is NORMAL, indicating table is ready
while True:
    time.sleep(2)  # Pause for 2 seconds before each check to reduce server pressure
    table = db.describe_table("chunks")
    if table.state == TableState.NORMAL:  # Table state is NORMAL, exit loop
        break

# Print detailed information of data table
print("table: {}".format(table.to_dict()))

client.close()  # Close client connection
