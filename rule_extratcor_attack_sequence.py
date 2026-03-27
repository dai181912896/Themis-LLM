import os
import json
import traceback


# 定义处理日志文件的函数
def extractor_entity_sequences(new_malicious_entities,logs):
    output_results=[]
    for line in logs:
        if new_malicious_entities.lower() in line.lower().strip():
            output_results.append(line)
    return output_results




def process_log_files(log_dir):
    # 遍历文件夹中的所有文件
    for log_filename in os.listdir(log_dir):
        log_file_path = os.path.join(log_dir, log_filename)

        # 只处理日志文件（假设是.txt格式）
        if log_filename.endswith(".txt"):
            with open(log_file_path, 'r', encoding='utf-8') as log_file:
                # 读取第一行实体名称数组
                first_line = log_file.readline().strip()
                malicious_entities = []
                data = first_line.strip('[]').split(',')
                malicious_entities=data

                # 设置输出文件路径，文件名与原文件一致
                output_file_path = os.path.join(log_dir+'\output', f"filtered_{log_filename}")
                if not os.path.exists(output_file_path):
                    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                # 打开输出文件进行写入
                with open(output_file_path, 'w', encoding='utf-8') as output:
                    output.write(','.join(malicious_entities) + '\n')
                    for line in log_file:
                        # 检查是否包含恶意实体名称
                        if any(entity.lower() in line.lower().strip() for entity in malicious_entities):
                            # 如果包含恶意实体，则保存该行
                            output.write(line)

            print(f"处理完成，结果已保存到: {output_file_path}")




def main():
    # 设置日志文件夹路径
    log_dir = "data/logs/P1-P2/"  # 修改为你的日志文件夹路径

    # 调用处理函数
    process_log_files(log_dir)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"发生错误：{e}")

