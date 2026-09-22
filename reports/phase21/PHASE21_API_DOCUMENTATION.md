# PHASE 21 — REST API DOCUMENTATION
**NEXUS-Forecast — Network Attack Forecasting & Threat Intelligence (SIH PS26153)**
*Documentation Date: 2026-09-22 | Status: VERIFIED & COMPLETE*

---

## 1. Overview & Architecture

The **NEXUS-Forecast** local backend API is a high-performance, air-gapped FastAPI service designed for the offline analyst workstation. It interfaces directly with the frozen PyTorch Recurrent World Model (`MultiTaskGRUWorldModel`), Platt calibration layer, Phase 17 Integrated Gradients engine, Phase 18 MITRE ATT&CK / CAPEC knowledge base, and historical research reports.

- **Base URL**: `http://127.0.0.1:8000`
- **Prefix**: `/api`
- **Network Mode**: 100% Offline / Zero external egress / Air-gapped
- **Device**: CPU (Intel/AMD x86_64, deterministic execution)
- **Operational Threshold**: $\theta^* = 0.45$

---

## 2. API Endpoints Specification

### 2.1 System & Health

#### `GET /api/health`
Checks API liveliness, offline mode, and manifest status.
- **Response `200 OK`**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "mode": "offline",
  "air_gapped": true,
  "manifest_valid": true,
  "active_device": "cpu"
}
```

#### `GET /api/status`
Returns model pipeline properties, operational thresholds, and cryptographic SHA-256 digests for all loaded assets.
- **Response `200 OK`**:
```json
{
  "status": "operational",
  "version": "1.0.0",
  "operational_threshold": 0.45,
  "sequence_length": 10,
  "num_features": 22,
  "horizons": [1, 3, 6],
  "artifacts": {
    "gru_world_model": {
      "path": ".../models/world_model/gru/best_model.pt",
      "sha256": "9f94d0aacff538096d2770e1b4f1509e5b38ae8f78f0cb31b850cb903fa8bc9f",
      "size_bytes": 919925,
      "status": "LOADED"
    }
  }
}
```

---

### 2.2 Datasets & Benchmarks

#### `GET /api/datasets`
Returns metadata and comparative performance specifications for all 3 supported evaluation datasets:
1. `CIC-IDS2017` (Primary Training & Benchmark)
2. `UNSW-NB15` (Cross-Domain Generalization)
3. `CTU-13` (Botnet & C2 Traffic Evaluation)

#### `GET /api/dataset_analysis`
Provides horizon-by-horizon ($+30\text{s}$, $+90\text{s}$, $+180\text{s}$) metrics (Accuracy, F1, Recall, ROC-AUC, FPR, MAE, Stage Accuracy) consumed by the Dataset Analysis UI.

---

### 2.3 Evaluation Scenarios

#### `GET /api/scenarios`
Returns the 10 pre-packaged benchmark evaluation scenarios (spanning True Positives, True Negatives, False Positives, and False Negatives) derived from Phase 17.
- **Query Parameters**: None
- **Response `200 OK`**: List of scenario summaries (`id`, `name`, `category`, `attack_probability`, `predicted_stage`).

#### `GET /api/scenarios/{scenario_id}`
Returns full scenario detail including temporal state sequences, ground truth, and execution annotations.

---

### 2.4 Offline Inference

#### `POST /api/inference` (and `POST /api/inference/run`)
Executes a forward pass through the frozen GRU World Model.
- **Request Body**:
```json
{
  "input_type": "demo",
  "scenario_id": "scenario_01",
  "raw_sequence": null,
  "horizons": [1, 3, 6],
  "explain_mode": "lightweight",
  "enrich_mode": "full"
}
```
- **Validation**: Accepts `input_type="state"` with an unscaled `[10, 22]` float array. Invalid shapes or non-numeric values return `400 Bad Request`.
- **Response `200 OK`**:
```json
{
  "forecast_id": "NEXUS-FC-E948B71C",
  "timestamp": "2026-09-22T03:10:44Z",
  "device": "cpu",
  "execution_time_ms": 28.4,
  "horizons": {
    "h1": {
      "horizon_step": 1,
      "horizon_seconds": 30,
      "raw_attack_logit": 1.482,
      "calibrated_attack_prob": 0.8214,
      "predicted_attack": true,
      "threshold": 0.45,
      "predicted_stage": "DISCOVERY",
      "stage_confidence": 0.764
    }
  },
  "summary": {
    "overall_attack_forecasted": true,
    "max_attack_prob": 0.8214,
    "predicted_trajectory": ["DISCOVERY", "INITIAL_ACCESS", "EXECUTION"],
    "threat_level": "HIGH"
  }
}
```

---

### 2.5 Forecast History & Overview

#### `GET /api/dashboard/overview`
Aggregates primary forecast cards, timeline points (observed $\to$ prediction origin $\to$ forecasted rollout), telemetry evidence anomalies, and canonical 8-stage progression for the active scenario.

#### `GET /api/forecasts`
Lists historical forecast records combined with pre-computed scenarios. Supports filtering by decision, stage, and horizon.

#### `GET /api/forecasts/{id}`
Returns granular forecast parameters, state rollout predictions, and execution metadata.

#### `GET /api/forecasts/{id}/knowledge`
Fetches matched MITRE ATT&CK techniques and CAPEC patterns specific to the forecasted attack stage.

---

### 2.6 Explainability (Phase 17)

#### `GET /api/explanations/{forecast_id}` (and `GET /api/explanations`)
Retrieves post-hoc explainability artifacts computed via 50-step Integrated Gradients:
1. **Top Features**: Attribution magnitude, deviation from train-partition median, and baseline comparisons.
2. **Temporal Attribution**: Step-by-step importance across windows $t-9$ to $t$.
3. **Feature $\times$ Time Matrix**: Authoritative $10 \times 22$ heatmap attribution grid.
4. **Flow Evidence**: Heuristic mappings tying numerical features to NetFlow/PCAP telemetry observations.
5. **Counterfactual Sensitivity**: Model logit and calibrated probability shifts under controlled feature and temporal ablations.

---

### 2.7 Knowledge Enrichment (Phase 18)

#### `GET /api/knowledge/mitre`
Retrieves enterprise MITRE ATT&CK techniques mapped to the canonical 8 attack stages.
- **Preservation Policy**: Strictly preserves all 19 `REVIEW_REQUIRED` techniques with explicit epistemic uncertainty tags.
- **Filter**: Optional `?stage=` query parameter.

#### `GET /api/knowledge/capec`
Retrieves normalized CAPEC attack patterns with execution mechanisms, typical severities, and defensive mitigations.
- **Search**: Optional `?query=` string parameter.

---

### 2.8 Reports & Audit Documents

#### `GET /api/reports`
Lists all technical engineering and audit markdown reports with disk file sizes and timestamps.

#### `GET /api/reports/{id}` (and `GET /api/reports/view?path=`)
Reads and renders the full UTF-8 text content of a report with directory traversal protection.

#### `GET /api/reports/{id}/download` (and `GET /api/reports/download?path=`)
Serves the raw `.md` file for offline export.
