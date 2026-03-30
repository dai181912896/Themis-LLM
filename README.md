# Themis-LLM: LLM-Based Attack Investigation and Forensics System

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19327970.svg)](https://doi.org/10.5281/zenodo.19327970)

## Overview

Themis-LLM is an intelligent security event forensics analysis system that leverages Large Language Models (LLMs) to conduct attack investigation and forensics on multi-source heterogeneous log data. The system processes preprocessed log data in triple format and employs a sliding window approach to analyze attack trajectories, detect suspicious entities, and reconstruct attack chains.

## Key Features

- **Multi-Source Log Analysis**: Processes heterogeneous log data from various sources
- **LLM-Powered Investigation**: Utilizes advanced LLMs for intelligent attack pattern recognition
- **Knowledge Base Integration**: Queries attack patterns from Milvus-based vector database (RAG)
- **Sliding Window Analysis**: Traverses log sequences chronologically to form continuous attack process trajectories
- **Entity Detection**: Identifies malicious entities (domains, IPs, programs, etc.) reported by IDS alerts
- **Attack Chain Reconstruction**: Builds comprehensive attack process summaries with step-by-step analysis
- **Multiple LLM Support**: Compatible with Tencent Cloud LKEAP, Volces ARK, OpenAI Hub, and more

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Log Data       │ -> │ Preprocessing   │ -> │  Triple Format  │
│  (Multi-source) │    │  Module         │    │  Logs           │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                      │
                                                      v
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Attack Report  │ <- │  LLM Analysis   │ <- │  Sliding Window │
│  & Summary      │    │  Engine         │    │  Traversal      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                               │
                               v
                        ┌─────────────────┐
                        │  Vector DB      │
                        │  (Milvus/Zilliz)│
                        │  Attack KB      │
                        └─────────────────┘
```

#
## Installation

### Prerequisites

- Python 3.8+
- Milvus/Zilliz Cloud account (for vector database)
- LLM API access (Tencent Cloud, Qianfan, or OpenAI-compatible)
- Tencent Cloud account (for embedding generation)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/Themis-LLM.git
cd Themis-LLM
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure API credentials**

Copy the example configuration files and fill in your credentials:

```bash
cp config.example.py config.py
cp LLM_config.example.py LLM_config.py
```

Edit `config.py` with your BCE and Qianfan credentials:
```python
account = 'YOUR_BCE_ACCOUNT'
api_key = 'YOUR_BCE_API_KEY'
endpoint = 'http://YOUR_ENDPOINT:PORT'
```

Edit `LLM_config.py` with your LLM API endpoint:
```python
client = OpenAI(
    base_url="YOUR_LLM_API_ENDPOINT",
    api_key="YOUR_LLM_API_KEY"
)
```

Update `VDB_data_utils.py` with your Milvus connection:
```python
CLUSTER_ENDPOINT = "YOUR_MILVUS_CLUSTER_ENDPOINT"
TOKEN = "YOUR_MILVUS_TOKEN"
```

For detailed configuration instructions, see [CONFIGURATION.md](CONFIGURATION.md).

## Usage

### Basic Attack Investigation

```bash
python attack_Investigation_byLLM.py \
    --log_file <path_to_log_file> \
    --alert <malicious_entity> \
    --collection <vector_db_collection> \
    --output <output_path>
```

### Rule-Based Attack Sequence Extraction

```bash
python rule_extratcor_attack_sequence.py
```

This processes log files in `data/logs/P1-P2/`, extracts lines containing malicious entities, and saves filtered results to `data/logs/P1-P2/output/`.

### Attack Step Classification

```bash
python attack_step_classify.py
```

### Entity Evaluation

```bash
python entity_eva.py
```

## Configuration

### Supported LLM Providers

- **Tencent Cloud LKEAP**
- **Volces ARK**
- **OpenAI Hub**
- Other OpenAI-compatible APIs

### Knowledge Base Setup

The system uses Milvus/Zilliz Cloud as a vector database for storing and retrieving attack patterns. To create a vector database:

```bash
python Zili_MIlv_CreateVDB.py
```



## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Permanent Archive**: This repository is permanently archived at [https://doi.org/10.5281/zenodo.19327970](https://doi.org/10.5281/zenodo.19327970)
