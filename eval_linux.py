import sys
import re


def evaluate_combined_tpr_fpr(file_paths, threat_entities):
    combined_normal = []
    combined_abnormal = []

    # Merge samples from all files
    for file_path in file_paths:
        normal, abnormal = group_logs_by_label(file_path)
        combined_normal.extend(normal)
        combined_abnormal.extend(abnormal)

    # Calculate metrics uniformly
    tp = 0  # True Positive
    fp = 0  # False Positive
    fn = 0  # False Negative
    tn = 0  # True Negative

    undetected_abnormal = []  # Undetected abnormal logs
    misclassified_normal = []  # Misclassified normal logs

    # Evaluate abnormal samples
    for log in combined_abnormal:
        if any(entity in log for entity in threat_entities):
            tp += 1
        else:
            fn += 1
            undetected_abnormal.append(log)

    # Evaluate normal samples
    for log in combined_normal:
        if any(entity in log for entity in threat_entities):
            fp += 1
            misclassified_normal.append(log)
        else:
            tn += 1

    # Calculate metrics
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    # Print results
    print("\n===== Combined Evaluation Results =====")
    print(f"{'Total Normal Samples':<20}: {len(combined_normal)}")
    print(f"{'Total Abnormal Samples':<20}: {len(combined_abnormal)}")
    print("\nConfusion Matrix Basic Metrics:")
    print(f"{'True Positive (TP)':<15}: {tp}")
    print(f"{'False Positive (FP)':<15}: {fp}")
    print(f"{'False Negative (FN)':<15}: {fn}")
    print(f"{'True Negative (TN)':<15}: {tn}")
    print(f"\n{'True Positive Rate':<20}: {tpr:.6f}")
    print(f"{'False Positive Rate':<20}: {fpr:.6f}")
    print(f"{'Undetected Abnormal Logs':<20}: {len(undetected_abnormal)}")
    print(f"{'Misclassified Normal Logs':<20}: {len(misclassified_normal)}")

    return {
        'total_normal': len(combined_normal),
        'total_abnormal': len(combined_abnormal),
        'tpr': tpr,
        'fpr': fpr,
        'undetected': undetected_abnormal,
        'misclassified': misclassified_normal
    }



def group_logs_by_label(file_path):
    normal_samples = []  # Store normal samples (-LB-)
    abnormal_samples = []  # Store abnormal samples (-LB+)

    pattern_normal = re.compile(r'-..-$')  # Match -any two characters-
    pattern_abnormal = re.compile(r'-..\+$')  # Match -any two characters+

    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if pattern_normal.search(line):
                normal_samples.append(line)
            elif pattern_abnormal.search(line):
                abnormal_samples.append(line)

    return normal_samples, abnormal_samples


def evaluate_tpr_fpr(normal_logs, abnormal_logs, threat_entities):
    tp = 0  # True Positive
    fp = 0  # False Positive
    fn = 0  # False Negative
    tn = 0  # True Negative

    undetected_abnormal = []  # Undetected abnormal logs
    misclassified_normal = []  # Misclassified normal logs

    for log in abnormal_logs:
        if any(entity in log for entity in threat_entities):
            tp += 1  # Hit abnormal, is True Positive
        else:
            fn += 1  # Should be abnormal but not detected
            undetected_abnormal.append(log)

    for log in normal_logs:
        if any(entity in log for entity in threat_entities):
            fp += 1  # Misclassified as abnormal, actually normal
            misclassified_normal.append(log)
        else:
            tn += 1  # Correctly classified as normal

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0  # Recall (True Positive Rate)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate

    print("Confusion Matrix Basic Metrics:")
    print(f"{'True Positive (TP)':<15}: {tp}")
    print(f"{'False Positive (FP)':<15}: {fp}")
    print(f"{'False Negative (FN)':<15}: {fn}")
    print(f"{'True Negative (TN)':<15}: {tn}")

    return tpr, fpr, undetected_abnormal, misclassified_normal


def count_unique_entities(file_path):
    unique_entities = set()
    import json
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:  # Read JSON objects line by line
            data = json.loads(line.strip())
            unique_entities.update(data.get("detected_suspicious_entities", []))

    print(f"Number of unique detected_suspicious_entities: {len(unique_entities)}")
    print("Unique entities:")
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
    #     "data/rawlogs/training_preprocessed_logs_M6-CVE-2017-11882_windows_h2"  # Please replace with actual second file path
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
