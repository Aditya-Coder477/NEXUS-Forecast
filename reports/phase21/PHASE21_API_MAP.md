# PHASE 21 / 21A — NEXUS-FORECAST API ENDPOINT MAP & TOPOLOGY
**System**: NEXUS-Forecast (SIH PS26153)  
**Server Architecture**: Unified FastAPI Server (`backend/app/main.py`)  
**Deployment Profile**: Air-Gapped / Offline Local Workstation (`http://127.0.0.1:8000`)  
**Client Interface**: Vanilla ES2022 Central API Wrapper (`src/dashboard/static/js/api.js`)

---

## 1. Top-Level Architectural Map

```
                     +---------------------------------------+
                     |   ANALYST BROWSER (OFFLINE UI)        |
                     |   Vanilla JS + CSS (Zero CDN)         |
                     +-------------------+-------------------+
                                         |
                                         | JSON HTTP / REST
                                         v
                     +---------------------------------------+
                     |    UNIFIED FASTAPI BACKEND            |
                     |    backend/app/main.py (Port 8000)    |
                     +-------------------+-------------------+
                                         |
             +---------------------------+---------------------------+
             |                           |                           |
             v                           v                           v
+------------------------+  +------------------------+  +------------------------+
|  INFERENCE & WORLD     |  |   EXPLAINABILITY &     |  |   THREAT INTELLIGENCE  |
|  MODEL PIPELINE        |  |   EVIDENCE ATTRIBUTION |  |   & AUDIT ARCHIVE      |
|  - GRU (best_model.pt) |  |   - Integrated Gradients| |   - MITRE ATT&CK       |
|  - StandardScaler      |  |   - Temporal Weights   |  |   - MITRE CAPEC        |
|  - Platt Calibration   |  |   - Robust IQR Baselines| |   - Markdown Reports   |
+------------------------+  +------------------------+  +------------------------+
```

---

## 2. Comprehensive Endpoint Directory

| Method | Endpoint Path | Query / Body Parameters | Return Schema | Underlying Service |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | None | HTML | `StaticFiles` (`index.html`) |
| `GET` | `/static/{path:path}` | None | Static Assets (`.js`, `.css`) | `StaticFiles` (`src/dashboard/static`) |
| `GET` | `/api/health` | None | `HealthResponse` | `backend/app/api/health.py` |
| `GET` | `/api/status` | None | `SystemStatusResponse` | `backend/app/api/health.py` |
| `GET` | `/api/datasets` | None | `List[DatasetMetadata]` | `DatasetService.get_datasets` |
| `GET` | `/api/dataset_analysis` | None | `DatasetAnalysisResponse` | `DatasetService` |
| `GET` | `/api/scenarios` | None | `List[ScenarioSummary]` | `ForecastService.get_all_scenarios` |
| `GET` | `/api/scenarios/{id}` | `scenario_id: str` | `ScenarioDetail` | `ForecastService.get_scenario_by_id` |
| `GET` | `/api/dashboard/overview` | `dataset`, `scenario`, `time_range` | `DashboardOverview` | `ForecastService` + `DatasetService` |
| `POST` | `/api/inference/run` | `InferenceRequest` JSON | `InferenceResponse` | `InferenceService.run_inference` |
| `POST` | `/api/inference` | `InferenceRequest` JSON (alias) | `InferenceResponse` | `InferenceService.run_inference` |
| `GET` | `/api/forecasts` | `decision`, `stage`, `horizon`, `dataset`, `scenario`, `limit` | `List[ForecastSummary]` | `ForecastService.list_forecasts` |
| `GET` | `/api/forecasts/{id}` | `forecast_id: str` | `ForecastDetail` | `ForecastService.get_forecast_by_id` |
| `GET` | `/api/forecasts/{id}/knowledge`| `forecast_id: str` | `ForecastKnowledge` | `ForecastService` + `KnowledgeService` |
| `GET` | `/api/explanations` | `scenario_id: Optional[str]` | `ExplanationResponse` | `ExplanationService.get_explanation` |
| `GET` | `/api/explanations/{id}` | `forecast_id: str` | `ExplanationResponse` | `ExplanationService.get_explanation` |
| `GET` | `/api/knowledge` | `stage: Optional[str]` | `UnifiedKnowledgeResponse` | `KnowledgeService.get_unified_knowledge` |
| `GET` | `/api/knowledge/mitre` | `stage: Optional[str]` | `MitreKnowledgeResponse` | `KnowledgeService.get_mitre_techniques` |
| `GET` | `/api/knowledge/capec` | `query`, `limit` | `CapecKnowledgeResponse` | `KnowledgeService.get_capec_patterns` |
| `GET` | `/api/reports` | None | `List[ReportMetadata]` | `ReportService.list_reports` |
| `GET` | `/api/reports/{id}` | `report_id: str` | `ReportDetailResponse` | `ReportService.get_report_content` |
| `GET` | `/api/reports/{id}/download` | `report_id: str` | Raw File Attachment | `ReportService.get_report_file_path` |
| `GET` | `/api/reports/view` | `path: str` (fallback) | `ReportDetailResponse` | `ReportService.get_report_content` |
| `GET` | `/api/reports/download` | `path: str` (fallback) | Raw File Attachment | `ReportService.get_report_file_path` |

---

## 3. Client Consumption Architecture (`api.js`)

All endpoints are mapped to modern `async/await` methods on the global `NexusAPI` object:

```javascript
NexusAPI.getHealth();
NexusAPI.getStatus();
NexusAPI.getDatasets();
NexusAPI.getDatasetAnalysis();
NexusAPI.getScenarios();
NexusAPI.getDashboardOverview({ dataset, scenario, time_range });
NexusAPI.runInference(canonicalPayload);
NexusAPI.getForecasts({ decision, stage, horizon, dataset, scenario, limit });
NexusAPI.getForecastDetail(forecastId);
NexusAPI.getForecastKnowledge(forecastId);
NexusAPI.getExplanation(forecastId);
NexusAPI.getUnifiedKnowledge(stage);
NexusAPI.getMitreKnowledge(stage);
NexusAPI.getCapecKnowledge(query, limit);
NexusAPI.getReports();
NexusAPI.getReportDetail(reportId);
```
