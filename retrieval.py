import os
import config
import pymochow
import qianfan
from pymochow.configuration import Configuration
from pymochow.model.table import AnnSearch, HNSWSearchParams

# 初始化千帆AI平台的嵌入模型对象
emb = qianfan.Embedding()

# 定义待查询的问题文本
question = ""

# 获取问题文本的嵌入向量
resp = emb.do(texts=[question])
question_embedding = resp['data'][0]['embedding']

# 使用配置信息初始化向量数据库客户端
config_obj = Configuration(credentials=config.credentials, endpoint=config.endpoint)
client = pymochow.MochowClient(config_obj)

# 选择数据库
db = client.database("document")

try:
    # 获取指定表的描述信息
    table = db.describe_table("chunks")
    # 构建近似最近邻搜索对象
    anns = AnnSearch(
        vector_field="vector",  # 指定用于搜索的向量字段名
        vector_floats=question_embedding,  # 提供查询向量
        params=HNSWSearchParams(ef=200, limit=1)  # 设置HNSW算法参数和返回结果的限制数量
    )
    # 执行搜索操作
    res = table.search(anns=anns)
    # 打印搜索结果
    print(res)
except Exception as e:  # 捕获并打印所有异常信息
    print(f"Error: {e}")

# 关闭客户端连接
client.close()