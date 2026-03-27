import sys
import re


def evaluate_combined_tpr_fpr(file_paths, threat_entities):
    combined_normal = []
    combined_abnormal = []

    # 合并所有文件的样本
    for file_path in file_paths:
        normal, abnormal = group_logs_by_label(file_path)
        combined_normal.extend(normal)
        combined_abnormal.extend(abnormal)

    # 统一计算指标
    tp = 0  # 真阳性
    fp = 0  # 假阳性
    fn = 0  # 假阴性
    tn = 0  # 真阴性

    undetected_abnormal = []  # 未检测出的异常日志
    misclassified_normal = []  # 误判为正常的异常日志

    # 评估异常样本
    for log in combined_abnormal:
        if any(entity in log for entity in threat_entities):
            tp += 1
        else:
            fn += 1
            undetected_abnormal.append(log)

    # 评估正常样本
    for log in combined_normal:
        if any(entity in log for entity in threat_entities):
            fp += 1
            misclassified_normal.append(log)
        else:
            tn += 1

    # 计算指标
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    # 打印结果
    print("\n===== 合并评估结果 =====")
    print(f"{'总正常样本数':<20}: {len(combined_normal)}")
    print(f"{'总异常样本数':<20}: {len(combined_abnormal)}")
    print("\n混淆矩阵基础指标：")
    print(f"{'真阳性(TP)':<15}: {tp}")
    print(f"{'假阳性(FP)':<15}: {fp}")
    print(f"{'假阴性(FN)':<15}: {fn}")
    print(f"{'真阴性(TN)':<15}: {tn}")
    print(f"\n{'True Positive Rate':<20}: {tpr:.6f}")
    print(f"{'False Positive Rate':<20}: {fpr:.6f}")
    print(f"{'未检测出的异常日志数':<20}: {len(undetected_abnormal)}")
    print(f"{'误判的正常日志数':<20}: {len(misclassified_normal)}")

    return {
        'total_normal': len(combined_normal),
        'total_abnormal': len(combined_abnormal),
        'tpr': tpr,
        'fpr': fpr,
        'undetected': undetected_abnormal,
        'misclassified': misclassified_normal
    }



def group_logs_by_label(file_path):
    normal_samples = []  # 存储正常样本（-LB-）
    abnormal_samples = []  # 存储异常样本（-LB+）

    pattern_normal = re.compile(r'-..-$')  # 匹配 -任意两字符-
    pattern_abnormal = re.compile(r'-..\+$')  # 匹配 -任意两字符+

    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if pattern_normal.search(line):
                normal_samples.append(line)
            elif pattern_abnormal.search(line):
                abnormal_samples.append(line)

    return normal_samples, abnormal_samples


def evaluate_tpr_fpr(normal_logs, abnormal_logs, threat_entities):
    tp = 0  # 真阳性
    fp = 0  # 假阳性
    fn = 0  # 假阴性
    tn = 0  # 真阴性

    undetected_abnormal = []  # 未检测出的异常日志
    misclassified_normal = []  # 误判为正常的异常日志

    for log in abnormal_logs:
        if any(entity in log for entity in threat_entities):
            tp += 1  # 命中异常，是真阳性
        else:
            fn += 1  # 应该是异常，但未检测到
            undetected_abnormal.append(log)

    for log in normal_logs:
        if any(entity in log for entity in threat_entities):
            fp += 1  # 误判为异常，实际上正常
            misclassified_normal.append(log)
        else:
            tn += 1  # 正确判断为正常

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0  # 召回率 (True Positive Rate)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # 假阳率 (False Positive Rate)

    print("混淆矩阵基础指标：")
    print(f"{'真阳性(TP)':<15}: {tp}")
    print(f"{'假阳性(FP)':<15}: {fp}")
    print(f"{'假阴性(FN)':<15}: {fn}")
    print(f"{'真阴性(TN)':<15}: {tn}")

    return tpr, fpr, undetected_abnormal, misclassified_normal


def count_unique_entities(file_path):
    unique_entities = set()
    import json
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:  # 逐行读取JSON对象
            data = json.loads(line.strip())
            unique_entities.update(data.get("detected_suspicious_entities", []))

    print(f"不重复的 detected_suspicious_entities 数量: {len(unique_entities)}")
    print("不重复的字段:")
    for entity in unique_entities:
        print(entity)
    return list(unique_entities)




def main():
    # if len(sys.argv) < 2:
    #     print("Usage: python script.py <log_file>")
    #     sys.exit(1)
    #
    # log_file = sys.argv[1]
    # file_paths = [
    #     "data/rawlogs/training_preprocessed_logs_M6-CVE-2017-11882_windows_h1",
    #     "data/rawlogs/training_preprocessed_logs_M6-CVE-2017-11882_windows_h2"  # 请替换为实际第二个文件路径
    # ]
    # threat_entities = [
    #     '192.168.223.3', 'pypayload.exe', '0xalsaheel.com','msf.rtf','payload.exe','msf.exe','35.165.209.195','c:/users/aalsahee/appdata/locallow/microsoft/cryptneturlcache/metadata/94308059b57b3142e455b38a6eb92015','c:/users/aalsahee/appdata/local/microsoft/windows/temporaryinternetfiles/counters.dat','aalsahee/index.html'
    # ]
    # results = evaluate_combined_tpr_fpr(file_paths, threat_entities)

# ---------------
    log_file_path=r"data/rawlogs/training_preprocessed_logs_S1-CVE-2015-5122_windows"
    test=['dllhost','svchost','firefox.exe']
    threat_entities=['192.168.223.3','firefox','winword','svchost']



    print(threat_entities)

    normal, abnormal = group_logs_by_label(log_file_path)

    tpr, fpr, undetected_abnormal, misclassified_normal = evaluate_tpr_fpr(normal, abnormal, threat_entities)



    # print("Undetected Abnormal Logs:", undetected_abnormal)
    # print("Misclassified Normal Logs:", misclassified_normal)
    print(f"True Positive Rate (TPR): {tpr:.6f}")
    print(f"False Positive Rate (FPR): {fpr:.6f}")
# ----------------------------------

if __name__ == "__main__":
    main()
