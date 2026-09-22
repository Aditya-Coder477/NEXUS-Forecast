# PHASE 21A — NEXUS-FORECAST API CONTRACT SPECIFICATION REPORT
**System**: NEXUS-Forecast (SIH PS26153)  
**Protocol**: REST / JSON over HTTP  
**Target Host**: `http://127.0.0.1:8000` (Air-Gapped Local Workstation)

---

## 1. Overview

This document specifies the exact request and response schemas implemented between the frontend workstation UI (`src/dashboard/static/js/api.js` & `app.js`) and the unified FastAPI backend (`backend/app/main.py`).

---

## 2. API Contract Specifications

### 2.1 System Health & Verification
- **Endpoint**: `GET /api/health`
- **Response**:
```json
{
  "status": "healthy",
  "mode": "offline",
  "air_gapped": true,
  "manifest_valid": true,
  "active_device": "cpu",
  "operational_threshold": 0.45
}
```

- **Endpoint**: `GET /api/status`
- **Response**:
```json
{
  "status": "operational",
  "version": "1.0.0",
  "offline_mode": true,
  "device": "cpu",
  "operational_threshold": 0.45,
  "sequence_length": 10,
  "num_features": 22,
  "artifacts": {
    "gru_world_model": { "path": "models/world_model/gru/best_model.pt", "status": "LOADED" },
    "scaler": { "path": "models/world_model/gru/scaler.joblib", "status": "LOADED" },
    "calibration_model": { "path": "models/world_model/gru/calibration_model.joblib", "status": "LOADED" }
  }
}
```

---

### 2.2 Live Inference Execution
- **Endpoint**: `POST /api/inference/run` (or `/api/inference`)
- **Request Body**:
```json
{
  "input_type": "demo",
  "dataset": "CIC-IDS2017",
  "scenario_id": "scenario_01",
  "raw_sequence": null,
  "horizons": [1, 3, 6],
  "explain_mode": "lightweight",
  "enrich_mode": "full"
}
```
- **Response Body**:
```json
{
  "forecast_id": "NEXUS-FC-A1B2C3D4",
  "timestamp": "2026-09-22T04:00:00.000000Z",
  "device": "cpu",
  "execution_time_ms": 24.5,
  "origin_window_index": 0,
  "horizons": {
    "h1": {
      "horizon_step": 1,
      "horizon_seconds": 30,
      "raw_attack_logit": 1.84,
      "calibrated_attack_prob": 0.825,
      "predicted_attack": true,
      "threshold": 0.45,
      "predicted_stage": "DISCOVERY",
      "stage_confidence": 0.78,
      "stage_probabilities": { "DISCOVERY": 0.78, "RECONNAISSANCE": 0.15 },
      "forecasted_state_physical": {},
      "explanation": {
        "top_contributing_features": ["dst_port_entropy", "flow_count"]
      },
      "enrichment": {
        "attack_techniques": [{ "attack_id": "T1046", "technique": "Network Service Discovery" }],
        "capec_patterns": [{ "capec_id": "CAPEC-287", "name": "TCP Port Scanning" }]
      }
    }
  },
  "summary": { "max_prob": 0.825, "overall_decision": "ATTACK" },
  "meta": { "air_gapped_guarantee": true }
}
```

---

### 2.3 Forecast Registry & Query Filtering
- **Endpoint**: `GET /api/forecasts?decision={dec}&stage={stg}&horizon={hor}&limit={lim}`
- **Parameters**:
  - `decision`: `"ALL"`, `"ATTACK"`, `"BENIGN"`
  - `stage`: `"ALL"`, `"RECONNAISSANCE"`, `"DISCOVERY"`, `"INITIAL_ACCESS"`, `"COMMAND_AND_CONTROL"`, `"BENIGN"`
  - `horizon`: `"ALL"`, `"+30s"`, `"+90s"`, `"+180s"`
  - `limit`: Integer (default 50)
- **Response**: Array of `ForecastSummary` objects.

---

### 2.4 Explanations (Phase 17 Dual Schema)
- **Endpoint**: `GET /api/explanations/{forecast_id}`
- **Response**:
```json
{
  "scenario_id": "scenario_01",
  "prediction_origin": "2017-07-07 04:46:30",
  "forecast_horizon_seconds": 30,
  "calibrated_attack_probability": 0.85,
  "predicted_stage": "DISCOVERY",
  "top_features": [
    { "feature": "dst_port_entropy", "attribution": 0.42, "current_value": 4.12, "baseline_median": 0.85, "iqr_deviation": 3.2, "direction": "attack_supporting" }
  ],
  "feature_attribution": [
    { "feature": "dst_port_entropy", "attribution": 0.42, "current_value": 4.12, "baseline_median": 0.85, "iqr_deviation": 3.2, "direction": "attack_supporting" }
  ],
  "temporal_attribution": [
    { "window": "W-0", "offset_seconds": 0, "attribution": 0.35, "relative_weight": 0.28 }
  ],
  "feature_time_matrix": { "rows": [{ "feature": "dst_port_entropy", "windows": [0.01, 0.05, 0.42] }] },
  "heatmap_matrix": [{ "feature": "dst_port_entropy", "windows": [0.01, 0.05, 0.42] }],
  "counterfactual_sensitivity": [
    { "feature": "dst_port_entropy", "original_prob": 0.85, "perturbed_prob": 0.89, "delta": 0.04, "consistent": true }
  ],
  "sensitivity": [
    { "feature": "dst_port_entropy", "original_prob": 0.85, "perturbed_prob": 0.89, "delta": 0.04, "consistent": true }
  ],
  "error_analysis": {
    "TP": [{ "scenario_id": "scenario_01", "calibrated_attack_probability": 0.85, "forecast_decision": "ATTACK" }]
  }
}
```

---

### 2.5 Threat Intelligence & Knowledge (Phase 18)
- **Endpoint**: `GET /api/knowledge?stage={stage}`
- **Parameters**: `stage` (e.g., `"DISCOVERY"`, `"RECONNAISSANCE"`)
- **Response**:
```json
{
  "selected_stage": "DISCOVERY",
  "techniques": [
    {
      "attack_id": "T1046",
      "technique": "Network Service Discovery",
      "mitre_tactic": "Discovery",
      "relevance": "EVIDENCE_SUPPORTED",
      "mapping_confidence": "HIGH",
      "evidence_notes": "Corroborated by high destination port entropy"
    }
  ],
  "capec_patterns": [
    {
      "capec_id": "CAPEC-287",
      "name": "TCP Port Scanning",
      "typical_severity": "Medium",
      "likelihood_of_attack": "High",
      "related_attack_ids": ["T1046"],
      "relevance": "EVIDENCE_SUPPORTED"
    }
  ],
  "review_required_count": 19
}
```
