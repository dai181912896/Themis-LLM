import numpy as np
from sklearn.metrics import confusion_matrix, classification_report


def evaluate_logs(log_file, ground_truth_words, predicted_words):
    """
    评估日志检测效果并计算混淆矩阵

    参数:
    log_file -- 日志文件路径，每行一个事件
    ground_truth_words -- 真实恶意关键词列表
    predicted_words -- 预测恶意关键词列表

    返回:
    confusion_matrix -- 混淆矩阵
    classification_report -- 分类报告
    """
    # 读取日志文件
    with open(log_file, 'r',encoding='utf-8') as f:
        logs = f.readlines()

    # 初始化标签数组
    y_true = []
    y_pred = []

    # 为每条日志打标签
    for log in logs:
        # 真实标签 (1=恶意, 0=正常)
        gt_malicious = any(word in log for word in ground_truth_words)
        y_true.append(1 if gt_malicious else 0)

        # 预测标签 (1=恶意, 0=正常)
        pred_malicious = any(word in log for word in predicted_words)
        y_pred.append(1 if pred_malicious else 0)

    # 计算混淆矩阵
    cm = confusion_matrix(y_true, y_pred)

    # 计算分类报告
    report = classification_report(y_true, y_pred, target_names=['正常', '恶意'])

    return cm, report


# 示例使用
if __name__ == "__main__":
    # 示例数据 - 替换为您的实际数据
    log_file = "other_code/linux_logs_preprocess/data/parsed/no agent/processed_no_agent/parsed_shellshock-pene.txt"  # 您的日志文件路径
    malicious_groundtruth = ["/tmp/bdoor", "172.31.77.48", "cgi-bin/bdoor","env.cgi",'ping.cgi']  # 真实恶意关键词
    predic_words = ["/tmp/bdoor",'172.31.77.48','sbrainconnect.com' ,'ping.cgi','env.cgi','libnsl','libc.so.6','libdl','/curl']  # 预测恶意关键词

    # 计算评估指标
    cm, report = evaluate_logs(log_file, malicious_groundtruth, predic_words)

    print("混淆矩阵:")
    print(cm)
    print("\n分类报告:")
    print(report)

    # 从混淆矩阵中提取各项指标
    tn, fp, fn, tp = cm.ravel()
    print("\n详细指标:")
    print(f"真阴性(TN): {tn} | 假阳性(FP): {fp}")
    print(f"假阴性(FN): {fn} | 真阳性(TP): {tp}")
    print(f"准确率: {(tp + tn) / (tp + tn + fp + fn):.2f}")
    print(f"召回率: {tp / (tp + fn):.2f}")
    print(f"精确率: {tp / (tp + fp):.2f}")
    print(f"F1分数: {2 * tp / (2 * tp + fp + fn):.2f}")