# NEXUS-FORECAST
### AI-Powered Network Attack Forecasting & Threat Intelligence Workstation
**Smart India Hackathon (SIH) — Problem Statement PS26153**

---

## 1. Overview

**NEXUS-Forecast** is an air-gapped, offline security research and analyst workstation that forecasts future network attack behavior before damage occurs. Rather than acting as a traditional reactive Intrusion Detection System (IDS), NEXUS-Forecast models how network states evolve over time using a recurrent **Temporal World Model (Multi-Task GRU)**.

Key capabilities include:
- **Multi-Step Rollout Forecasting**: Forecasts future network states, attack probability, and attack stages across multiple horizons ($+30\text{s}$, $+90\text{s}$, $+180\text{s}$).
- **Platt Calibrated Probabilities**: Empirically calibrated probability outputs evaluated against a frozen operational threshold ($\theta^* = 0.45$).
- **Explainability & Attribution (Phase 17)**: 50-step Integrated Gradients using training-only baselines to generate feature attribution, temporal attribution, and a complete $10 \times 22$ Feature $\times$ Time matrix.
- **Threat Intelligence Enrichment (Phase 18)**: Automated post-forecasting alignment with 210 MITRE ATT&CK techniques (strictly preserving 19 `REVIEW_REQUIRED` items with non-causal epistemic safety) and 615 CAPEC attack patterns.
- **100% Offline & Air-Gapped**: Runs entirely locally on CPU with zero internet reliance, zero telemetry phone-home, and zero third-party cloud APIs.

---

## 2. Quick Start: Launching the Workstation

### Prerequisites
- Python 3.11+
- Virtual environment with project dependencies:
```bash
pip install -r requirements.txt  # or: pip install fastapi uvicorn torch pandas numpy scikit-learn joblib
```

### Start the Local Workstation Server
Run the integrated backend server using Python:

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Once launched, open your web browser and navigate to:
```
http://127.0.0.1:8000
```

The server serves both the high-performance REST API (`/api/*`) and the static editorial analyst frontend (`/`).

---

## 3. Workstation Views & Capabilities

The workstation features strictly 7 focused views:

1. **Dashboard**: Live primary forecast status, interactive SVG forecast timeline (observed $\to$ prediction origin $\to$ rollout), telemetry evidence anomaly ranking, 8-stage lifecycle progression, and top contributing features.
2. **Live Inference**: Run on-demand inference over test-partition parquets, pre-packaged scenarios, or raw $[10, 22]$ state sequences with real-time execution telemetry.
3. **Forecast Results**: Filter and review recorded and benchmark forecasts by decision, stage, and horizon with slide-out audit drawers.
4. **Explanations**: Comprehensive post-hoc explainability panel featuring top feature attribution tables, 10-step temporal cards, interactive $10 \times 22$ heatmap, counterfactual sensitivity tables, and error group breakdown (TP, TN, FP, FN).
5. **ATT&CK / CAPEC**: Threat intelligence browser linking forecasted attack stages to MITRE ATT&CK techniques and CAPEC patterns.
6. **Dataset Analysis**: Benchmark comparative metrics across `CIC-IDS2017`, `UNSW-NB15`, and `CTU-13`.
7. **Reports**: Integrated document reader and downloader for all 10 authoritative technical reports and audits.

---

## 4. Running Verification Tests

Run the complete test suite across all project phases (Phases 12–21):

```bash
python -m pytest tests/ -v
```

To run only the Phase 21 End-to-End Integration tests:

```bash
python -m pytest tests/phase21/test_integration.py -v
```

---

## 5. Model Integrity & Cryptographic Registry

All core models and knowledge assets are cryptographically locked:

| Component | Path | SHA-256 Digest | Status |
|---|---|---|---|
| **GRU World Model** | `models/world_model/gru/best_model.pt` | `9f94d0aacff538096d2770e1b4f1509e5b38ae8f78f0cb31b850cb903fa8bc9f` | Frozen |
| **Feature Scaler** | `models/world_model/gru/scaler.joblib` | `9d1e26da627dd0879f2bb640fa762bce14e50ac9f875e9fff8ee6d2a969a2ff2` | Frozen |
| **Platt Calibrator** | `models/world_model/gru/calibration_model.joblib` | `61b50aa5c47bde70c216714d04b0bf45c831c40e73f23c90214dc5a6f429fda7` | Frozen |
| **Baseline Stats** | `models/explainability/baseline_statistics.json` | `59e69b5b4584a0bc4da5b78ccac8e16c775047a24afd91f4c042b94b10767e56` | Frozen |
| **MITRE Mapping** | `data/knowledge/mitre_attack/processed/attack_stage_mapping.json` | `739a79ccde977b982416dacdd8da04de15c917a078f822b675053a553a7791b4` | Frozen |
| **CAPEC Catalog** | `data/knowledge/capec/processed/capec_normalized.json` | `d32ce2bb7b75a3c15eb5b67685497015d2cf198a6af396e9208e6f809c608268` | Frozen |
