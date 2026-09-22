# NEXUS-Forecast: Offline Inference Pipeline User Guide

## Overview
The NEXUS-Forecast Offline Inference Pipeline packages temporal network attack forecasting, probability calibration, model explainability, and cybersecurity knowledge enrichment into an air-gapped, production-grade CLI and Python library.

## Quick Start (CLI)

### 1. Run inference on a sequence file (.parquet or .csv)
```bash
python -m src.inference.run \
    --input data/demo/example_sequence.parquet \
    --input-type sequence \
    --explain lightweight \
    --enrich full \
    --output outputs/forecast_report.json \
    --format json
```

### 2. Export SOC Analyst Markdown Brief
```bash
python -m src.inference.run \
    --input data/demo/example_sequence.parquet \
    --input-type sequence \
    --explain lightweight \
    --enrich full \
    --output outputs/soc_alert.md \
    --format markdown
```

### 3. Verify Offline Environment and Cryptographic Integrity
```bash
python -m src.inference.validate_offline
```

---

## Python API Usage

```python
import numpy as np
from src.inference.pipeline import OfflineInferencePipeline
from src.inference.config import InferenceConfig
from src.inference.output import OutputFormatter

# 1. Initialize pipeline with automatic cryptographic integrity checks
pipeline = OfflineInferencePipeline()

# 2. Input unscaled sequence tensor of shape (10, 22)
# (10 historical 60-second windows with 30-second steps)
sample_sequence = np.random.randn(10, 22).astype(np.float32)

# 3. Predict with explainability and enrichment
result = pipeline.predict_single_sequence(
    x_raw=sample_sequence,
    explain_mode="lightweight",  # "none", "lightweight", "full"
    enrich_mode="full",          # "none", "attack", "full"
)

# 4. Access structured results
print(f"Overall Attack: {result['summary']['overall_attack_forecasted']}")
print(f"Trajectory: {' -> '.join(result['summary']['predicted_trajectory'])}")

# 5. Format as SOC Markdown
markdown_report = OutputFormatter.to_soc_markdown(result)
```

---

## CLI Options

| Argument | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `--input` | File path | Required | Path to `.parquet` or `.csv` sequence file |
| `--input-type` | `sequence`, `flows` | `sequence` | Format of input data |
| `--explain` | `none`, `lightweight`, `full` | `lightweight` | Explainability attribution level |
| `--enrich` | `none`, `attack`, `full` | `full` | MITRE ATT&CK and CAPEC enrichment level |
| `--output` | File path | `outputs/forecast_output.json` | Path where output is saved |
| `--format` | `json`, `jsonl`, `markdown` | `json` | Output formatting type |
| `--threshold` | Float | `0.45` | Operational attack decision threshold $\theta^*$ |
| `--device` | `cpu`, `cuda` | `cpu` | Device for PyTorch GRU tensor execution |

---

## Cryptographic Security & Anti-Causality
- **Checksum Enforcement**: All model checkpoints, scalers, and knowledge bases are validated against `models/manifest.json`.
- **Air-Gapped Operation**: Guaranteed zero socket connections or runtime external dependencies.
- **Epistemic Integrity**: ATT&CK and CAPEC associations represent structured contextual knowledge, **not** forensic proof of endpoint infection.
