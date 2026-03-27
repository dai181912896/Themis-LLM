
import time
import pymochow  # 导入pymochow库，用于操作数据库
from pymochow.configuration import Configuration  # 用于配置客户端
import config  # 导入配置文件，包含身份验证和终端信息

# 导入pymochow模型相关的类和枚举类型
from pymochow.model.schema import Schema, Field, VectorIndex, SecondaryIndex, HNSWParams
from pymochow.model.enum import FieldType, IndexType, MetricType, TableState
from pymochow.model.table import Partition

# 使用配置文件中的信息初始化客户端
config_obj = Configuration(credentials=config.credentials, endpoint=config.endpoint)
client = pymochow.MochowClient(config_obj)

# 选择或创建数据库
db = client.database("db_attack_investigate")

# 定义数据表的字段
fields = [
    Field("id", FieldType.UINT64, primary_key=True, partition_key=True, auto_increment=False, not_null=True),
    Field("text", FieldType.STRING),
    Field("metadata", FieldType.STRING),
    Field("source", FieldType.STRING, not_null=True),
    Field("entity", FieldType.STRING,not_null=True),# 恶意实体检索增强
    Field("type", FieldType.STRING, not_null=True), #步骤
    Field("Creator", FieldType.STRING, not_null=True),  # 步骤
    Field("vector", FieldType.FLOAT_VECTOR, not_null=True, dimension=384)
]

# 定义数据表的索引
indexes = [
    VectorIndex(index_name="vector_idx", field="vector", index_type=IndexType.HNSW, metric_type=MetricType.L2, params=HNSWParams(m=32, efconstruction=200)),
    SecondaryIndex(index_name="entity_type", field="entity") # index的数据必为Not null
]

# 尝试创建数据表，捕获并打印可能出现的异常
try:
    # replication 数量不超过实例数据节点的数量
    # 免费版参考值 replication=1
    # 标准版参考值 replication=3
    table = db.create_table(table_name="chunks", replication=1, partition=Partition(partition_num=1), schema=Schema(fields=fields, indexes=indexes))
except Exception as e:  # 捕获所有类型的异常
    print(f"Error: {e}")  # 打印异常信息

# 轮询数据表状态，直到表状态为NORMAL，表示表已准备好
while True:
    time.sleep(2)  # 每次检查前暂停2秒，减少对服务器的压力
    table = db.describe_table("chunks")
    if table.state == TableState.NORMAL:  # 表状态为NORMAL，跳出循环
        break

# 打印数据表的详细信息
print("table: {}".format(table.to_dict()))

client.close()  # 关闭客户端连接