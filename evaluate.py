import numpy as np
from sklearn.metrics import confusion_matrix, classification_report


def evaluate_logs(log_file, ground_truth_words, predicted_words):
    """
    Evaluate log detection performance and calculate confusion matrix

    Parameters:
    log_file -- log file path, one event per line
    ground_truth_words -- list of true malicious keywords
    predicted_words -- list of predicted malicious keywords

    Returns:
    confusion_matrix -- confusion matrix
    classification_report -- classification report
    """
    # Read log file
    with open(log_file, 'r',encoding='utf-8') as f:
        logs = f.readlines()

    # Initialize label arrays
    y_true = []
    y_pred = []

    # Label each log
    for log in logs:
        # True label (1=malicious, 0=normal)
        gt_malicious = any(word in log for word in ground_truth_words)
        y_true.append(1 if gt_malicious else 0)

        # Predicted label (1=malicious, 0=normal)
        pred_malicious = any(word in log for word in predicted_words)
        y_pred.append(1 if pred_malicious else 0)

    # Calculate confusion matrix
    cm = confusion_matrix(y_true, y_pred)

    # Calculate classification report
    report = classification_report(y_true, y_pred, target_names=['Normal', 'Malicious'])

    return cm, report


# Example usage
if __name__ == "__main__":
    # Sample data - replace with your actual data
    log_file = "other_code/linux_logs_preprocess/data/parsed/no agent/processed_no_agent/parsed_shellshock-pene.txt"  # Your log file path
    malicious_groundtruth = ["/tmp/bdoor", "172.31.77.48", "cgi-bin/bdoor","env.cgi",'ping.cgi']  # True malicious keywords
    predic_words = ["/tmp/bdoor",'172.31.77.48','sbrainconnect.com' ,'ping.cgi','env.cgi','libnsl','libc.so.6','libdl','/curl']  # Predicted malicious keywords

    # Calculate evaluation metrics
    cm, report = evaluate_logs(log_file, malicious_groundtruth, predic_words)

    print("Confusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(report)

    # Extract metrics from confusion matrix
    tn, fp, fn, tp = cm.ravel()
    print("\nDetailed Metrics:")
    print(f"True Negative (TN): {tn} | False Positive (FP): {fp}")
    print(f"False Negative (FN): {fn} | True Positive (TP): {tp}")
    print(f"Accuracy: {(tp + tn) / (tp + tn + fp + fn):.2f}")
    print(f"Recall: {tp / (tp + fn):.2f}")
    print(f"Precision: {tp / (tp + fp):.2f}")
    print(f"F1 Score: {2 * tp / (2 * tp + fp + fn):.2f}")
