import json


def load_nodes_from_json_files(file_paths):
    """
    Load and merge nodes from multiple JSON array files (keep duplicates)
    File format requirement: ["node1", "node2", ...]

    Parameters:
        file_paths: list of JSON file paths

    Returns:
        Merged node list (keeps all duplicate nodes)
    """
    all_nodes = []
    for file_path in file_paths:
        with open(file_path, 'r') as f:
            nodes = json.load(f)
            if not isinstance(nodes, list):
                raise ValueError(f"File {file_path} is not a valid array format JSON")
            all_nodes.extend(nodes)  # Directly extend, no deduplication
    return all_nodes


def load_nodes_from_json(json_file):
    """Load node list from JSON file"""
    with open(json_file, 'r') as f:
        data = json.load(f)
    return data['orign_node']


def contains_any(target_string, match_list):
    """Check if target string contains any substring from match list"""
    return any(match in target_string for match in match_list)


def calculate_metrics(all_nodes, ground_truth, predictions):
    """
    Calculate classification metrics (supports fuzzy matching)

    Parameters:
        all_nodes: list of all nodes
        ground_truth: list of true malicious identifiers
        predictions: list of predicted malicious identifiers

    Returns:
        Dictionary containing various metrics
    """
    # Initialize counters
    tp = fp = tn = fn = 0

    for node in all_nodes:
        # Determine true label and predicted label
        is_malicious = contains_any(node, ground_truth)
        is_pred_malicious = contains_any(node, predictions)

        # Update confusion matrix
        if is_malicious and is_pred_malicious:
            tp += 1
        elif is_malicious and not is_pred_malicious:
            fn += 1
        elif not is_malicious and is_pred_malicious:
            fp += 1
        else:
            tn += 1

    # Calculate metrics (handle division by zero)
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    accuracy = (tp + tn) / len(all_nodes) if all_nodes else 0

    return {
        'Confusion Matrix': {
            'True Positive': tp,
            'False Positive': fp,
            'True Negative': tn,
            'False Negative': fn
        },
        'Metrics': {
            'TPR (Recall)': tpr,
            'FPR': fpr,
            'Precision': precision,
            'Accuracy': accuracy,
            'F1 Score': 2 * (precision * tpr) / (precision + tpr) if (precision + tpr) > 0 else 0
        },
        'Total Nodes': len(all_nodes)
    }


def print_metrics(metrics):
    """Format and print metric results"""
    print("\n=== Confusion Matrix ===")
    for k, v in metrics['Confusion Matrix'].items():
        print(f"{k:<15}: {v}")

    print("\n=== Performance Metrics ===")
    for k, v in metrics['Metrics'].items():
        if isinstance(v, float):
            print(f"{k:<15}: {v:.4f}")
        else:
            print(f"{k:<15}: {v}")

    print(f"\nTotal Nodes: {metrics['Total Nodes']}")


# ==================== Usage Example ====================
if __name__ == "__main__":
    # Define labels
    ground_truth = ["0xalsaheel.com", "192.168.223.3","payload.exe"]  # True malicious (hit if contained)
    predictions =    # Calculate metrics
    nodes = load_nodes_from_json('data/nodes/s2/nodes/origin_nodes.json')

    # nodes=load_nodes_from_json_files(["data/nodes/training_preprocessed_logs_M6-CVE-2017-11882_windows_h1_nodes_list.json","data/nodes/training_preprocessed_logs_M6-CVE-2017-11882_windows_h2_nodes_list.json"])
    results = calculate_metrics(nodes, ground_truth, predictions)

    # Print results
    print("==== Test Results ====")
    print_metrics(results)

    # Example 2: Actual file test (uncomment to use)
    """
    real_ground_truth = [...]  # Replace with true malicious label list
    real_predictions = [...]   # Replace with predicted malicious label list

    real_nodes = load_nodes_from_json('real_data.json')
    real_results = calculate_metrics(real_nodes, real_ground_truth, real_predictions)

    print("\n==== Actual Data Results ====")
    print_metrics(real_results)
    """
