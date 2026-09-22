# PHASE 21 — PRE-INTEGRATION AUDIT
**NEXUS-Forecast — Network Attack Forecasting & Threat Intelligence (SIH PS26153)**
*Audit Date: 2026-09-22 | Status: APPROVED TO PROCEED*

---

## 1. Executive Summary

This pre-integration audit establishes the formal inventory of existing components, ML artifacts, frontend views, data sources, and mocks prior to executing **Phase 21: End-to-End Integration**. 

Phase 21 connects the frontend analytical dashboard with the verified, frozen Python World Model pipeline (`src/inference`, `src/explainability`, `src/knowledge_enrichment`, `src/world_model`, `src/rollout`), creating a **100% offline, air-gapped, verifiable system**.

No machine learning models will be retrained, and all pipeline parameters ($\theta^* = 0.45$, Platt calibration, 22-dimensional state vector, 10-step sequence length, 50-step Integrated Gradients) remain immutable.

---

## 2. Integrity Baseline & Model Hashes

All core model, calibration, baseline, and knowledge graph artifacts have been verified and their SHA-256 digests recorded in `reports/phase21/model_integrity_before.json`:

| Artifact | File Path | SHA-256 Digest | Size (bytes) | Status |
| :--- | :--- | :--- | :--- | :--- |
| **GRU World Model** | `models/world_model/gru/best_model.pt` | `9f94d0aacff538096d2770e1b4f1509e5b38ae8f78f0cb31b850cb903fa8bc9f` | 919,925 | Frozen |
| **Feature Scaler** | `models/world_model/gru/scaler.joblib` | `9d1e26da627dd0879f2bb640fa762bce14e50ac9f875e9fff8ee6d2a969a2ff2` | 1,111 | Frozen |
| **Calibration Model** | `models/world_model/gru/calibration_model.joblib` | `61b50aa5c47bde70c216714d04b0bf45c831c40e73f23c90214dc5a6f429fda7` | 1,694 | Frozen |
| **Baseline Statistics**| `models/explainability/baseline_statistics.json` | `59e69b5b4584a0bc4da5b78ccac8e16c775047a24afd91f4c042b94b10767e56` | 9,252 | Frozen |
| **MITRE ATT&CK Map** | `data/knowledge/mitre_attack/processed/attack_stage_mapping.json` | `739a79ccde977b982416dacdd8da04de15c917a078f822b675053a553a7791b4` | 96,080 | Frozen |
| **CAPEC Catalog** | `data/knowledge/capec/processed/capec_normalized.json` | `d32ce2bb7b75a3c15eb5b67685497015d2cf198a6af396e9208e6f809c608268` | 988,495 | Frozen |
| **Model Manifest** | `models/manifest.json` | `9fb862cbd71394f1249ef7dbd10af58c3809fea2b61a9fa5ccc74cc6ec1718c4` | 1,891 | Frozen |

---

## 3. Frontend Views & Navigation Audit

The system features strictly **7 navigation views** with zero "Settings" page and no generic AI styling:

| # | View ID | Page Title | Functional Scope & Integration Target |
|---|---|---|---|
| 1 | `view-dashboard` | **System Dashboard** | Real-time system status, offline indicator, GRU architecture summary, model metrics, live sequence preview, 10 scenario quick-picker. |
| 2 | `view-live-inference` | **Live Inference** | Input selection (scenario picker or parquet file upload), explainability depth selector (`none`, `lightweight`, `full`), run inference trigger, execution timeline, raw input sequence inspect. |
| 3 | `view-forecast-results`| **Forecast Results** | Calibrated probability gauge, calibrated vs uncalibrated comparison, decision badge ($\theta^*=0.45$), attack stage classification, multi-step rollout trajectories ($t+1$ to $t+5$), forecast history table. |
| 4 | `view-explanations` | **Explanations** | Top-5 feature attribution bar chart, 10-step temporal attribution curve, $10 \times 22$ Feature $\times$ Time heatmap, flow evidence attribution table, counterfactual sensitivity analysis. |
| 5 | `view-knowledge` | **ATT&CK / CAPEC** | 8 Attack stages explorer, 210 MITRE ATT&CK techniques (displaying and preserving all 19 `REVIEW_REQUIRED`), 615 CAPEC attack patterns with execution mechanisms and mitigations. |
| 6 | `view-dataset` | **Dataset Analysis** | Comparative analysis across CIC-IDS2017, UNSW-NB15, CTU-13. Class balance distribution, temporal window metrics, feature distribution comparisons. |
| 7 | `view-reports` | **Reports & Audit** | Interactive reader for all Phase 12–21 technical markdown reports, downloadable raw reports, model integrity verification panel with SHA-256 checks. |

---

## 4. Backend Python Modules & Capabilities Audit

The repository contains fully realized, tested Python libraries that will be directly wrapped by backend services:

1. **`src/inference/pipeline.py` (`OfflineInferencePipeline`)**:
   - Single-load singleton pattern for model, scaler, calibration, baseline stats, and MITRE enricher.
   - Comprehensive error handling and validation for input shape $[10, 22]$ and numeric ranges.
   - Outputs: calibrated probability, binary attack decision, stage probabilities, multi-step rollout, optional Integrated Gradients attribution, and MITRE/CAPEC threat intelligence.
   - Offline verification: manifest hash check passes, average execution latency < 35ms.

2. **`src/explainability/`**:
   - `attribution.py`: Integrated Gradients (50 steps) using training-set baseline.
   - `temporal_attribution.py`: Per-step temporal attribution vector $[10]$.
   - `matrix_attribution.py`: Full $10 \times 22$ attribution matrix.
   - `flow_evidence.py`: Heuristic flow-level evidence attribution.
   - `sensitivity.py`: Feature perturbation counterfactual sensitivity.
   - Pre-computed authoritative dataset: `reports/phase17/representative_explanations.json` (10 scenarios: TP, TN, FP, FN) and `reports/phase17/feature_time_attribution.csv`.

3. **`src/knowledge_enrichment/`**:
   - `mitre_enrichment.py`: 210 techniques mapped to 8 stages, strict preservation of 19 `REVIEW_REQUIRED` tags.
   - `capec_enrichment.py`: 615 CAPEC patterns normalized.

4. **`reports/`**:
   - 13 comprehensive engineering reports ready for direct presentation and download.

---

## 5. Mock vs Real Data Inventory

| Component / Feature | Current State | Phase 21 Target State |
| :--- | :--- | :--- |
| System Health / Status | Static indicators | Dynamic `GET /api/health` and `GET /api/status` verifying model load & manifest |
| Datasets List & Stats | Hardcoded card HTML | Dynamic `GET /api/datasets` backed by `DatasetService` from phase reports |
| Scenario Selection | Hardcoded dropdown list | Dynamic `GET /api/scenarios` loaded from `representative_explanations.json` |
| Inference Execution | Client-side simulation | Real `POST /api/inference` invoking `OfflineInferencePipeline.predict()` |
| Forecast History | Static table rows | Live dynamic memory-backed forecast repository populated via inference |
| Explanation Visuals | Static SVG / CSS bars | Dynamic rendering driven by `GET /api/explanations/{id}` and Phase 17 matrix |
| ATT&CK / CAPEC Explorer | Partial static cards | Full search & filter driven by `GET /api/knowledge/mitre` and `/capec` |
| Reports Reader | Fixed text | Dynamic `GET /api/reports` and `GET /api/reports/{id}` with secure markdown reader |

---

## 6. REST API Endpoint Specification

To maintain clean separation and high maintainability, the backend will be organized into `backend/app/`:

- `GET /api/health` — Service health and offline status
- `GET /api/status` — Pipeline status, loaded model hashes, active device (CPU)
- `GET /api/datasets` — Metadata and comparative stats for all 3 datasets
- `GET /api/scenarios` — Pre-packaged validation scenarios (TP, TN, FP, FN)
- `POST /api/inference` — Run inference on raw array or scenario ID
- `GET /api/forecasts` — List forecast history
- `GET /api/forecasts/{id}` — Retrieve detailed forecast result by ID
- `GET /api/forecasts/{id}/knowledge` — Retrieve enriched threat intelligence
- `GET /api/explanations/{id}` — Retrieve feature, temporal, matrix attribution & flow evidence
- `GET /api/knowledge/mitre` — MITRE ATT&CK techniques with stage filters and review status
- `GET /api/knowledge/capec` — CAPEC attack patterns catalog
- `GET /api/reports` — List of available engineering reports
- `GET /api/reports/{id}` — Retrieve rendered content of a specific report
- `GET /api/reports/{id}/download` — Secure download of raw markdown file

---

## 7. Audit Conclusion

The system is ready for Phase 21 implementation. All prerequisites, frozen artifacts, and evaluation baselines are accounted for. Implementation will proceed with the creation of `backend/app/` followed by frontend integration and full validation suite execution.
