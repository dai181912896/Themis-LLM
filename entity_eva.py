import json


def load_nodes_from_json_files(file_paths):
    """
    从多个JSON数组文件中加载并合并节点（保留重复项）
    文件格式要求：["node1", "node2", ...]

    参数:
        file_paths: JSON文件路径列表

    返回:
        合并后的节点列表（保留所有重复节点）
    """
    all_nodes = []
    for file_path in file_paths:
        with open(file_path, 'r') as f:
            nodes = json.load(f)
            if not isinstance(nodes, list):
                raise ValueError(f"文件 {file_path} 不是有效的数组格式JSON")
            all_nodes.extend(nodes)  # 直接扩展，不去重
    return all_nodes


def load_nodes_from_json(json_file):
    """从JSON文件加载节点列表"""
    with open(json_file, 'r') as f:
        data = json.load(f)
    return data['orign_node']


def contains_any(target_string, match_list):
    """检查目标字符串是否包含匹配列表中的任意子串"""
    return any(match in target_string for match in match_list)


def calculate_metrics(all_nodes, ground_truth, predictions):
    """
    计算分类指标（支持模糊匹配）

    参数:
        all_nodes: 全部节点列表
        ground_truth: 真实恶意标识列表
        predictions: 预测为恶意的标识列表

    返回:
        包含各项指标的字典
    """
    # 初始化计数器
    tp = fp = tn = fn = 0

    for node in all_nodes:
        # 判断真实标签和预测标签
        is_malicious = contains_any(node, ground_truth)
        is_pred_malicious = contains_any(node, predictions)

        # 更新混淆矩阵
        if is_malicious and is_pred_malicious:
            tp += 1
        elif is_malicious and not is_pred_malicious:
            fn += 1
        elif not is_malicious and is_pred_malicious:
            fp += 1
        else:
            tn += 1

    # 计算指标（处理除零情况）
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
    """格式化打印指标结果"""
    print("\n=== 混淆矩阵 ===")
    for k, v in metrics['Confusion Matrix'].items():
        print(f"{k:<15}: {v}")

    print("\n=== 性能指标 ===")
    for k, v in metrics['Metrics'].items():
        if isinstance(v, float):
            print(f"{k:<15}: {v:.4f}")
        else:
            print(f"{k:<15}: {v}")

    print(f"\n总节点数: {metrics['Total Nodes']}")


# ==================== 使用示例 ====================
if __name__ == "__main__":
    # 定义标签
    ground_truth = ["0xalsaheel.com", "192.168.223.3","payload.exe"]  # 真实恶意（包含即命中）
    predictions =    # 计算指标
    nodes = load_nodes_from_json('data/nodes/s2/nodes/origin_nodes.json')

    # nodes=load_nodes_from_json_files(["data/nodes/training_preprocessed_logs_M6-CVE-2017-11882_windows_h1_nodes_list.json","data/nodes/training_preprocessed_logs_M6-CVE-2017-11882_windows_h2_nodes_list.json"])
    results = calculate_metrics(nodes, ground_truth, predictions)

    # 打印结果
    print("==== 测试结果 ====")
    print_metrics(results)

    # 示例2：实际文件测试（取消注释使用）
    """
    real_ground_truth = [...]  # 替换为真实恶意标签列表
    real_predictions = [...]   # 替换为预测标签列表

    real_nodes = load_nodes_from_json('real_data.json')
    real_results = calculate_metrics(real_nodes, real_ground_truth, real_predictions)

    print("\n==== 实际数据结果 ====")
    print_metrics(real_results)
    """