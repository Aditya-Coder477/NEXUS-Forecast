# PHASE 21A — PRE-FIX COMPREHENSIVE AUDIT REPORT
**Project**: NEXUS-FORECAST (Network Attack Forecasting & Threat Intelligence)  
**Timestamp**: 2026-09-22T03:55:00Z  
**Author**: Antigravity Agent  
**Status**: AUDIT COMPLETE — ROOT CAUSES CATALOGED  

---

## 1. Executive Summary

This pre-fix audit documents the architectural discrepancies, runtime syntax errors, API contract mismatches, and component-level failures preventing the NEXUS-Forecast dashboard from operating as an end-to-end functional offline system.

The core machine learning artifacts (frozen GRU model checkpoint, StandardScaler, Platt calibration model, baseline statistics) and inference engines are cryptographically verified and 100% operational. However, the client-side JavaScript layer fails to execute due to fatal syntax errors in template literals, and several user interactions (filters, dropdown selectors, explanation linking, and inference requests) fail to communicate properly with the backend services.

---

## 2. Current Frontend Architecture

- **Path**: `src/dashboard/static/`
- **Markup**: `src/dashboard/static/index.html` (single-page application layout with 7 functional views: Dashboard, Live Inference, Forecast Results, Explanations, ATT&CK/CAPEC, Dataset Analysis, Reports).
- **Styles**: `src/dashboard/static/css/main.css` (editorial styling, zero external fonts or CDN stylesheets).
- **Scripts**: `src/dashboard/static/js/app.js` (monolithic event handling, routing, state management, and direct `fetch()` calls).
- **Routing**: Tab/view toggling managed via `.nav-item` click listeners switching `.page-view.active` classes.
- **State Management**: In-memory `state` object holding active selections (`dataset`, `scenario`, `activeHorizon`, `activePage`, `selectedForecast`, etc.).

---

## 3. Current Backend Architecture

- **Canonical Backend**: `backend/app/main.py`
  - Modular FastAPI application mounting `backend/app/api/` routers (`health`, `datasets`, `scenarios`, `inference`, `forecasts`, `explanations`, `knowledge`, `reports`).
  - Underlying services in `backend/app/services/` wrapping frozen pipeline singletons (`inference_service`, `forecast_service`, `explanation_service`, `knowledge_service`, `dataset_service`, `report_service`).
- **Secondary/Duplicate Backend**: `src/dashboard/app.py`
  - Monolithic 730-line FastAPI application duplicating many of the same routes with differing schema expectations (`LiveInferenceRequest` vs `InferenceRequest`).
- **CLI Launcher**: `src/dashboard/run.py`
  - Configured to launch the duplicate `src.dashboard.app:app` instead of the canonical `backend.app.main:app`.

---

## 4. Current API Endpoints & Frontend Mappings

| Frontend Action / View | Called Endpoint | Expected Schema / Params | Backend Handling Service | Status |
| :--- | :--- | :--- | :--- | :--- |
| Initial Load / Health Check | `GET /api/health` | None | `health.py` | Working (200 OK) |
| Dashboard Overview | `GET /api/dashboard/overview` | `?dataset=...&scenario=...&time_range=...` | `forecast_service.py` | Functional, needs scenario linking |
| Header Dataset Dropdown | `GET /api/datasets` | None | `dataset_service.py` | Working |
| Header Scenario Dropdown | `GET /api/scenarios` | None | `forecast_service.py` | Working |
| Live Inference Execution | `POST /api/inference/run` | `{input_type, scenario_id, horizons, explain_mode, enrich_mode}` | `inference_service.py` | Schema mismatch (`scenario` vs `scenario_id`, `explain` vs `explain_mode`) |
| Forecast Results Table | `GET /api/forecasts` | `?decision=...&stage=...&horizon=...` | `forecast_service.py` | Query params previously ignored |
| Forecast Row Detail | `GET /api/forecasts/{id}` | Path param `forecast_id` | `forecast_service.py` | Implemented |
| Explanations View | `GET /api/explanations/{id}`| Path param `forecast_id` | `explanation_service.py` | Falls back silently to scenario_01 |
| MITRE ATT&CK Knowledge | `GET /api/knowledge/mitre` | `?stage=...` | `knowledge_service.py` | Working |
| CAPEC Attack Patterns | `GET /api/knowledge/capec` | `?query=...&limit=...` | `knowledge_service.py` | Working |
| Unified Knowledge Flow | `GET /api/knowledge` | `?stage=...` | `knowledge_service.py` | Working |
| Dataset Analysis | `GET /api/dataset_analysis` | None | `dataset_service.py` | Working |
| Reports Listing | `GET /api/reports` | None | `report_service.py` | Working |
| Report Viewing | `GET /api/reports/{id}` | Path param `id` | `report_service.py` | Working |

---

## 5. JavaScript Runtime & Syntax Errors

1. **Fatal SyntaxError at Line 869**:
   - Expression: `color:${iqr > 0 ? "var(--semantic-attack)" : "var(--semantic-benign)};"}`
   - Issue: Semicolon `;` placed inside the quote string before closing brace, causing Node.js and browser V8 engines to throw `SyntaxError: Missing } in template expression`.
   - Result: `app.js` completely fails to parse, preventing all event listeners from binding on initial page load.
2. **Invalid Python Formatting at Line 887**:
   - Expression: `${t.offset_seconds:+d}s`
   - Issue: Python format specifier `:+d` is invalid in JavaScript template literals; renders as literal string `undefineds` or throws runtime errors in strict parsers.
3. **Unchecked API Responses**:
   - Direct calls to `const data = await res.json()` without checking `res.ok`. If backend returns 400 or 500, subsequent property accesses (e.g. `data.horizons.h1`) throw `TypeError: Cannot read properties of undefined`.

---

## 6. API Schema Mismatches

1. **Live Inference Request**:
   - Frontend sent:
     ```json
     {
       "input_type": "sequence",
       "dataset": "CIC-IDS2017",
       "scenario": "Scenario 01",
       "horizons": [1, 3, 6],
       "explain": true,
       "enrich_attack": true,
       "enrich_capec": true
     }
     ```
   - Canonical Pydantic Schema (`InferenceRequest`):
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
   - Result: HTTP 400 validation error due to unknown/missing field names.

2. **Forecast Results Filter Parameters**:
   - Frontend passed `decision`, `stage`, `horizon` query parameters.
   - Backend `list_forecasts` only accepted `limit: int = 50`, completely ignoring filters.

3. **Feature Attribution & Matrix Rows**:
   - Frontend expected `data.heatmap_matrix` or rows with `.values`, while backend provided `.windows`.
   - Frontend expected `data.sensitivity` with `prob_original`, while backend returned `counterfactual_sensitivity`.

---

## 7. Duplicate Backend Implementations

- **File A**: `src/dashboard/app.py` (730 lines, monolithic).
- **File B**: `backend/app/main.py` (modular, clean architecture).
- **Runner**: `src/dashboard/run.py` launches `src.dashboard.app:app`.
- **Resolution**: Convert `src/dashboard/run.py` to launch `backend.app.main:app`. Mark `src/dashboard/app.py` as superseded or align its imports.

---

## 8. Missing Data & Artifact Resolution

- **Manifest Path Resolution**: `src/inference/loader.py` checks `os.path.exists(norm_path)` using relative paths from the current working directory. If uvicorn is launched from outside project root, artifact checks fail.
- **Runtime Artifacts Verified Present**:
  - `models/world_model/gru/best_model.pt` (SHA256: `9f94d0aa...`)
  - `models/world_model/gru/scaler.joblib` (SHA256: `9d1e26da...`)
  - `models/world_model/gru/calibration_model.joblib` (SHA256: `61b50aa5...`)
  - `data/demo/example_sequence.parquet` (Present, 30 canonical sequences)
  - `data/knowledge/mitre_attack/processed/attack_stage_mapping.json` (Present)
  - `data/knowledge/mitre_attack/processed/techniques.json` (Present)
  - `data/knowledge/capec/processed/capec_normalized.json` (Present)

---

## 9. Non-Functional Navigation & Buttons

1. **Header Dropdowns**: Changing Dataset and Scenario fired `loadDashboard()`, but scenario choices did not sync with Live Inference or Forecast detail context.
2. **Horizon Toggles on Dashboard**: `+30s`, `+90s`, `+180s` buttons adjusted local math approximations rather than requesting actual multi-horizon rollout data.
3. **Forecast -> Explanation Transition**: Clicking "View Explanation" in the drawer navigated to `#page-explanations` but did not pass `forecast_id`, defaulting silently to generic scenario 1.
4. **Forecast -> ATT&CK Mapping Transition**: Clicking "View ATT&CK Mapping" did not filter knowledge by the forecast's predicted stage.
5. **Forecast Filters**: Changing "All Decisions", "All Stages", or "All Horizons" did not filter backend rows.

---

## 10. Hardcoded / Mock Data Inventory

1. `primary_forecast`: Hardcoded fallback values (`0.82`, `0.45`, `DISCOVERY`) when scenario parsing encountered subtle naming differences.
2. `timeline`: Fallback array with static values (`[0.12, 0.15, 0.28, 0.42, 0.65, 0.78, 0.82, 0.88, 0.93]`).
3. `ForecastService.list_forecasts`: Hardcoded `"2024-04-21 10:45:00 UTC"` timestamp instead of scenario origin timestamp.
4. Demo input labelling: Live inference panel did not explicitly clarify whether it was running against `example_sequence.parquet` (test partition) or a live capture.

---

## 11. Recommended Minimal Fixes

1. **Syntax Fix**: Correct malformed template expressions and Python-style string formats in `app.js`. Validate with `node --check`.
2. **Central API Client**: Create `src/dashboard/static/js/api.js` implementing robust `apiFetch` with stateful error handling (LOADING, SUCCESS, EMPTY, ERROR).
3. **Canonical Backend Unification**: Update `src/dashboard/run.py` to point to `backend.app.main:app`.
4. **Manifest Path Anchor**: Update `src/inference/loader.py` to resolve manifest paths against `BASE_DIR`.
5. **Request/Response Schema Standardization**: Update `app.js` inference invocation to use `{input_type, dataset, scenario_id, raw_sequence, horizons, explain_mode, enrich_mode}`.
6. **Query Filter Implementation**: Add `dataset`, `scenario`, `decision`, `stage`, `horizon`, `limit` filtering to `ForecastService.list_forecasts`.
7. **Forecast-Specific Context Propagation**: Carry `forecast_id` into Explanations and `stage` into ATT&CK/CAPEC views.
8. **Live Forecast Explanation Support**: Enable `ExplanationService` to extract explanations for live forecasts in addition to cached scenarios.
9. **Zero External Dependencies**: Retain 100% offline air-gapped guarantee with zero internet calls.
