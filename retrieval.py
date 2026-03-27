import os
import config
import pymochow
import qianfan
from pymochow.configuration import Configuration
from pymochow.model.table import AnnSearch, HNSWSearchParams

# Initialize Qianfan AI platform embedding model object
emb = qianfan.Embedding()

# Define question text to query
question = ""

# Get embedding vector of question text
resp = emb.do(texts=[question])
question_embedding = resp['data'][0]['embedding']

# Initialize vector database client using configuration information
config_obj = Configuration(credentials=config.credentials, endpoint=config.endpoint)
client = pymochow.MochowClient(config_obj)

# Select database
db = client.database("document")

try:
    # Get description information of specified table
    table = db.describe_table("chunks")
    # Build approximate nearest neighbor search object
    anns = AnnSearch(
        vector_field="vector",  # Specify vector field name for search
        vector_floats=question_embedding,  # Provide query vector
        params=HNSWSearchParams(ef=200, limit=1)  # Set HNSW algorithm parameters and return result limit
    )
    # Execute search operation
    res = table.search(anns=anns)
    # Print search results
    print(res)
except Exception as e:  # Catch and print all exception information
    print(f"Error: {e}")

# Close client connection
client.close()
